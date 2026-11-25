#!/usr/bin/env python3
"""Fixed, offline guest fixture extractor. Never installs or runs package scripts.

Run only as root in the separately attested disposable guest. Archive input is
read-only seed media at /run/metaclaw-seed/debs; output is a fresh fixed
/opt/metaclaw-qualification tree. Partial output is retained on failure.
"""
import ctypes
import hashlib
import os
import stat
import subprocess
import tarfile
import tempfile
from pathlib import Path

ARCHIVES = {
 'conmon_2.1.13+ds1-2_amd64.deb': '61da0329bfc8b3f9af64b31a857a70640f41d21609f8cad4812e4ce1cd469dc5',
 'crun_1.21-1ubuntu3_amd64.deb': '46f3be5c8f76317eabeef77a156148550eeb7d2338d379db8fcb6383b381c98d',
 'golang-github-containers-common_0.66.0+ds2-3_all.deb': '88ca25147d181b88b062e9344255ee9c2f800e3dc7e3d9c952909d93d07caaf8',
 'golang-github-containers-image_5.38.0+ds2-2_all.deb': 'f46e9b45ce54f6f98223fb3ff2803595ccb70e1e1fdaf3015b835dd281017bb9',
 'libsubid5_1%3a4.17.4-2ubuntu3_amd64.deb': 'd05f5f5bda0288dffa12f01f1edbc934c477e915f6cb6d85ee5f995c75947993',
 'libyajl2_2.1.0-5.1_amd64.deb': '049df3f8e8aed7272fd5c65b8709e66d77b1539791f65d5dfb5026048cacceac',
 'netavark_1.16.1-3.1_amd64.deb': 'd346ba50f073d7f4dc8b9188351c9bbe03dc260193fd9cc31ae26d845cdf75f7',
 'podman_5.7.0+ds2-3build1_amd64.deb': 'bc8fbe3c31f0904550a9e6cb32363643fd34ad9b78553fda233b50caef2e11bd',
 'uidmap_1%3a4.17.4-2ubuntu3_amd64.deb': 'b4942df2976de17739887a170d51060c30ae5433fd7123b444c9ec5cef9490ff',
}
# Path -> (mode, length, SHA256). No services, units or scripts are selected.
FILES = {
 'usr/bin/podman': (0o755,43180896,'6627da0abfd3b0189498089319f5759c7b132bb6a51130bf8ff43d7f102d9673'),
 'usr/bin/conmon': (0o755,152368,'856d10b5842ae5dd7f4cf73a60d0f1a764bdcd0cfadc447adb0b0ef41a935412'),
 'usr/bin/crun': (0o755,483392,'0e6d2727a3bcb013652543f6c8124a24cdea863ee0a99038c55b3591c0d8c126'),
 'usr/bin/newgidmap': (0o4755,41944,'745ce9348600b27fa3007f7df7c115d6e586cef163e89caa44cac4e2f9c8d52c'),
 'usr/bin/newuidmap': (0o4755,41944,'fd13a73987411f71b8b135cf55ffa00db048754f8d1faf507b6b4aa6204d0ddc'),
 'usr/lib/podman/netavark': (0o755,13343280,'53fc9fe0ff1d80159713d76ec609984ce38ed390cc1729847aa55f4e6a8e9e2f'),
 'usr/lib/x86_64-linux-gnu/libsubid.so.5.0.0': (0o644,41408,'4973ce6852e811cb632533450e2f2748340d0752f4bc93d63eda8cde1cb60b4a'),
 'usr/lib/x86_64-linux-gnu/libyajl.so.2.1.0': (0o644,43392,'c54f554ef49cc941d85d56714930d06f39e44bb8968cecb2ee52503c834df04d'),
}
LINKS = {'usr/lib/x86_64-linux-gnu/libsubid.so.5': 'libsubid.so.5.0.0', 'usr/lib/x86_64-linux-gnu/libyajl.so.2': 'libyajl.so.2.1.0'}
SOURCE = Path('/run/metaclaw-seed/debs')
DEST = Path('/opt/metaclaw-qualification')
MAX_MEMBERS = 100000
MAX_MEMBER_SIZE = 128 * 1024 * 1024
MAX_TOTAL_SIZE = 2 * 1024 * 1024 * 1024


def scan(stream, selected, links, sink, *, max_members=MAX_MEMBERS, max_member_size=MAX_MEMBER_SIZE, max_total_size=MAX_TOTAL_SIZE):
    """Read complete archive; call sink only for selected regular file bytes."""
    seen = set()
    found = set()
    total = 0
    count = 0
    with tarfile.open(fileobj=stream, mode='r|') as archive:
        for member in archive:
            count += 1
            name = member.name.removeprefix('./').rstrip('/')
            if count > max_members or len(name.encode()) > 4096 or member.size < 0 or member.size > max_member_size:
                raise ValueError('tar member limit exceeded')
            total += member.size
            if total > max_total_size:
                raise ValueError('tar total size limit exceeded')
            if not name:
                continue
            if name.startswith('/') or any(part in ('', '.', '..') for part in name.split('/')) or name in seen:
                raise ValueError('unsafe or duplicate tar member')
            seen.add(name)
            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise ValueError('unsupported tar member type')
            if name in selected:
                mode, size, expected = selected[name]
                if not member.isfile() or member.mode != mode or member.size != size:
                    raise ValueError('selected member type, mode or length mismatch')
                reader = archive.extractfile(member)
                if reader is None:
                    raise ValueError('selected payload absent')
                data = reader.read(size + 1)
                if len(data) != size or hashlib.sha256(data).hexdigest() != expected:
                    raise ValueError('selected payload digest mismatch')
                sink(name, data, mode)
                found.add(name)
            elif name in links:
                if not member.issym() or member.linkname != links[name]:
                    raise ValueError('selected symlink target mismatch')
                found.add(name)
    return found


def trusted_dir(path):
    info = path.lstat()
    return stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not (info.st_mode & 0o022)


def safe_archive(info, read_only_mount):
    return read_only_mount and stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not (info.st_mode & 0o022)


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def publish_no_replace(source, destination):
    """Atomically publish a completed tree; never replace an existing path."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def main():
    if os.geteuid() != 0 or not all(trusted_dir(p) for p in (Path('/run'), SOURCE.parent, SOURCE, Path('/opt'))):
        raise SystemExit('requires root and trusted fixed guest paths')
    if not (os.statvfs(SOURCE).f_flag & os.ST_RDONLY) or set(os.listdir(SOURCE)) != set(ARCHIVES) or DEST.exists() or DEST.is_symlink():
        raise SystemExit('unexpected archive set or existing destination')
    handles = []
    try:
        for name, expected in ARCHIVES.items():
            fd = os.open(SOURCE / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            info = os.fstat(fd)
            if not safe_archive(info, bool(os.statvfs(SOURCE).f_flag & os.ST_RDONLY)):
                raise ValueError('archive must be root-owned and read-only')
            with os.fdopen(os.dup(fd), 'rb') as f:
                actual = hashlib.file_digest(f, 'sha256').hexdigest()
            if actual != expected:
                raise ValueError('archive digest mismatch')
            handles.append(fd)
        stage = Path(tempfile.mkdtemp(prefix='.metaclaw-qualification-stage-', dir=DEST.parent))
        os.chmod(stage, 0o700)
        fsync_dir(DEST.parent)
        tree = stage / 'tree'
        tree.mkdir(mode=0o755)
        os.chmod(tree, 0o755)
        for name in ('usr', 'usr/bin', 'usr/lib', 'usr/lib/podman', 'usr/lib/x86_64-linux-gnu'):
            (tree / name).mkdir(mode=0o755)
            os.chmod(tree / name, 0o755)
        found = set()
        def write(name, data, mode):
            if name in found:
                raise ValueError('selected member repeated across packages')
            path = tree / name
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as out:
                out.write(data)
                out.flush()
                os.fchmod(out.fileno(), mode)
                os.fsync(out.fileno())
            found.add(name)
        for fd in handles:
            os.lseek(fd, 0, os.SEEK_SET)
            proc = subprocess.Popen(['/usr/bin/dpkg-deb', '--fsys-tarfile', '/proc/self/fd/' + str(fd)], stdout=subprocess.PIPE, pass_fds=(fd,), env={'PATH': '/usr/bin:/bin'})
            try:
                members = scan(proc.stdout, FILES, LINKS, write)
            except Exception:
                proc.kill(); proc.wait(); raise
            if proc.wait() != 0:
                raise ValueError('package payload failed')
            for name in members & set(LINKS):
                if name in found:
                    raise ValueError('selected member repeated across packages')
                found.add(name)
        if found != set(FILES) | set(LINKS):
            raise ValueError('selected member missing')
        for name, target in LINKS.items():
            os.symlink(target, tree / name)
        for name in ('usr/bin', 'usr/lib/podman', 'usr/lib/x86_64-linux-gnu', 'usr/lib', 'usr', ''):
            fsync_dir(tree / name)
        fsync_dir(stage)
        publish_no_replace(tree, DEST)
        fsync_dir(DEST.parent)
        print('prepared fixed guest prefix; no units or package scripts installed')
    finally:
        for fd in handles:
            os.close(fd)


if __name__ == '__main__':
    main()
