#!/usr/bin/python3
"""Disposable no-NIC guest bootstrap. Host VM isolation is externally attested.

Runs through existing cloud-init only. Errors and timeouts never imply cleanup.
"""
import hashlib
import array
import fcntl
import json
import os
import stat
import subprocess
from pathlib import Path

ISO_SHA = '733f69788dd932bba4995b9eabda65f6d89569f71def4ca991d09c72ed324b39'
ISO_SIZE = 36923392
FILES = {
 'extract-guest-podman.py': '76bd3b5ca21c8a346157a6076f791ea37746e94860ca1594d2a3885c9eddfbaf',
 'runner.sh': '7f3b7362c846d6782a746336155a801ca563722766fc2724551bf0dc33432184',
 'guest.test': '7f2d42527f95a92708150752aa523e3d38e3116f6649071895578d29542f3967',
 'synthetic.oci.tar': '614408851026f406fa3848729c893ba29a7e963dbe2ed6bf9534a53e689029c0',
}
STAGES = {'preflight', 'media', 'identity', 'extract', 'runner', 'complete'}


def check_network(names, ipv4, ipv6):
    if names != ['lo']:
        raise ValueError('interfaces')
    lines = ipv4.strip().splitlines()
    if not lines or not lines[0].startswith('Iface'):
        raise ValueError('ipv4')
    for line in lines[1:]:
        fields = line.split()
        if len(fields) < 4 or (fields[1] == '00000000' and int(fields[3], 16) & 1):
            raise ValueError('ipv4 route')
    lines = ipv6.strip().splitlines()
    if not lines:
        raise ValueError('ipv6')
    for line in lines:
        fields = line.split()
        if len(fields) < 10 or (fields[0] == '0' * 32 and fields[1] == '00' and int(fields[8], 16) & 1):
            raise ValueError('ipv6 route')


def status_record(stage, success):
    if stage not in STAGES:
        raise ValueError('stage')
    return {'schema': 'metaclaw.no-start-qualification.v1', 'stage': stage,
            'result': 'passed' if success else 'unknown',
            'exact_container_absence': 'confirmed' if success else 'unknown',
            'broader_cleanup': 'unknown',
            'data_iso_sha256': ISO_SHA, 'test_sha256': FILES['guest.test'],
            'oci_sha256': FILES['synthetic.oci.tar']}


def run(*args, timeout=20, pass_fds=()):
    subprocess.run(args, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'}, timeout=timeout,
                   pass_fds=pass_fds)


def digest(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def digest_fd(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    with os.fdopen(os.dup(fd), 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def check_mountinfo(text, major_minor, flags):
    required = os.ST_RDONLY | os.ST_NOSUID | os.ST_NODEV | os.ST_NOEXEC
    if flags & required != required:
        raise ValueError('media mount flags')
    matches = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 10 or '-' not in fields:
            raise ValueError('malformed mountinfo')
        if fields[4] == '/run/metaclaw-seed':
            sep = fields.index('-')
            if sep + 2 >= len(fields):
                raise ValueError('malformed mountinfo source')
            matches.append((fields[2], fields[3], fields[sep + 1]))
    if matches != [(major_minor, '/', 'iso9660')]:
        raise ValueError('media mount identity')


def main():
    stage, success = 'preflight', False
    device_fd = None
    try:
        if os.geteuid() != 0 or Path('/sys/class/dmi/id/sys_vendor').read_text().strip() != 'QEMU':
            raise ValueError('guest identity')
        check_network(sorted(os.listdir('/sys/class/net')), Path('/proc/net/route').read_text(), Path('/proc/net/ipv6_route').read_text())
        stage = 'media'
        device = Path('/dev/disk/by-label/METACLAW_DATA')
        device_fd = os.open(device, os.O_RDONLY | os.O_CLOEXEC)
        info = os.fstat(device_fd)
        if not stat.S_ISBLK(info.st_mode):
            raise ValueError('media type')
        size = array.array('Q', [0])
        fcntl.ioctl(device_fd, 0x80081272, size, True)  # BLKGETSIZE64
        if size[0] != ISO_SIZE or digest_fd(device_fd) != ISO_SHA:
            raise ValueError('media digest')
        mount = Path('/run/metaclaw-seed')
        mount.mkdir(mode=0o700)
        run('/usr/bin/mount', '-t', 'iso9660', '-o', 'ro,nosuid,nodev,noexec', '/proc/self/fd/' + str(device_fd), str(mount), pass_fds=(device_fd,))
        expected_device = f'{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}'
        check_mountinfo(Path('/proc/self/mountinfo').read_text(), expected_device, os.statvfs(mount).f_flag)
        after = os.fstat(device_fd)
        label = device.stat()
        if (after.st_dev, after.st_ino, after.st_rdev) != (info.st_dev, info.st_ino, info.st_rdev) or (label.st_dev, label.st_ino, label.st_rdev) != (info.st_dev, info.st_ino, info.st_rdev) or os.stat(mount).st_dev != info.st_rdev or digest_fd(device_fd) != ISO_SHA:
            raise ValueError('media identity changed')
        if set(os.listdir(mount)) != set(FILES) | {'debs', 'manifest.json'}:
            raise ValueError('media layout')
        for name, expected in FILES.items():
            p = mount / name
            if p.is_symlink() or not p.is_file() or digest(p) != expected:
                raise ValueError('payload digest')
        stage = 'identity'
        # Disallow any existing account/name or range, rather than modifying it.
        import grp
        import pwd
        for lookup, key in ((pwd.getpwuid, 1000), (pwd.getpwnam, 'qualifier'), (grp.getgrgid, 1000), (grp.getgrnam, 'qualifier')):
            try:
                lookup(key)
            except KeyError:
                continue
            raise ValueError('identity conflict')
        for name in ('/etc/subuid', '/etc/subgid'):
            p = Path(name)
            if p.exists() and p.read_text().strip():
                raise ValueError('subid conflict')
        run('/usr/sbin/groupadd', '--gid', '1000', 'qualifier')
        run('/usr/sbin/useradd', '--uid', '1000', '--gid', '1000', '--no-create-home', '--shell', '/usr/sbin/nologin', '-K', 'SUB_UID_COUNT=0', '-K', 'SUB_GID_COUNT=0', 'qualifier')
        for name in ('/etc/subuid', '/etc/subgid'):
            Path(name).write_text('qualifier:100000:65536\n')
        stage = 'extract'
        run('/usr/bin/python3', str(mount / 'extract-guest-podman.py'), timeout=60)
        # Only the synthetic user can access the copied unprivileged inputs.
        stage_dir = Path('/run/qualification-input')
        stage_dir.mkdir(mode=0o700)
        os.chown(stage_dir, 1000, 1000)
        for name, mode in (('runner.sh', 0o500), ('guest.test', 0o500), ('synthetic.oci.tar', 0o400)):
            src = mount / name
            dst = stage_dir / name
            with open(src, 'rb') as inp, open(dst, 'xb') as out:
                while chunk := inp.read(1024 * 1024): out.write(chunk)
            os.chown(dst, 1000, 1000); os.chmod(dst, mode)
            if digest(dst) != FILES[name]: raise ValueError('staged digest')
        work = stage_dir / 'work'; work.mkdir(mode=0o700); os.chown(work, 1000, 1000)
        stage = 'runner'
        run('/usr/bin/timeout', '--signal=TERM', '--kill-after=10s', '120s', '/usr/bin/setpriv', '--reuid=1000', '--regid=1000', '--groups=1000', '--', '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'HOME=/run/qualification-input', '/bin/sh', str(stage_dir / 'runner.sh'), str(stage_dir / 'guest.test'), str(stage_dir / 'synthetic.oci.tar'), str(work), timeout=135)
        stage, success = 'complete', True
    except BaseException:
        pass
    finally:
        if device_fd is not None:
            os.close(device_fd)
    message = ('METACLAW_QUAL_V1 ' + json.dumps(status_record(stage, success), sort_keys=True, separators=(',', ':')) + '\n').encode()
    if len(message) <= 512:
        try:
            fd = os.open('/dev/ttyS0', os.O_WRONLY | os.O_NOCTTY | os.O_NONBLOCK)
            try: os.write(fd, message)
            finally: os.close(fd)
        except OSError:
            pass


if __name__ == '__main__':
    main()
