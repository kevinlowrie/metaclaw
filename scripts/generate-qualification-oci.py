#!/usr/bin/env python3
"""Generate a deterministic, synthetic OCI archive in a new private directory.

The executable contains only x86-64 exit(0); no container or image store is used.
"""
import argparse
import hashlib
import io
import json
import os
import struct
import tarfile
import tempfile
from pathlib import Path


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def executable():
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    code = bytes.fromhex("31ffb83c0000000f05")  # xor edi,edi; mov eax,60; syscall
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 2, 62, 1, 0x400078, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    program = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 120 + len(code), 120 + len(code), 4096)
    return header + program + code


def tar_bytes(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data, mode in sorted(files):
            member = tarfile.TarInfo(name)
            member.size, member.mode, member.uid, member.gid, member.mtime = len(data), mode, 0, 0, 0
            member.uname = member.gname = ""
            archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("parent", type=Path, help="existing absolute private output parent")
    args = parser.parse_args()
    parent = args.parent
    if not parent.is_absolute() or parent.is_symlink() or not parent.is_dir():
        parser.error("parent must be an existing absolute non-symlink directory")
    folder = Path(tempfile.mkdtemp(prefix="synthetic-oci-", dir=parent))
    os.chmod(folder, 0o700)
    elf = executable()
    layer = tar_bytes([("qualification", elf, 0o755)])
    config = encode({"architecture": "amd64", "os": "linux", "config": {"Entrypoint": ["/qualification"], "User": "65534:65534"}, "rootfs": {"type": "layers", "diff_ids": ["sha256:" + digest(layer)]}})
    config_desc = {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": "sha256:" + digest(config), "size": len(config)}
    layer_desc = {"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": "sha256:" + digest(layer), "size": len(layer)}
    manifest = encode({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": config_desc, "layers": [layer_desc]})
    descriptor = {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + digest(manifest), "size": len(manifest), "annotations": {"org.opencontainers.image.ref.name": "qualification:offline"}}
    index = encode({"schemaVersion": 2, "manifests": [descriptor]})
    files = [("oci-layout", encode({"imageLayoutVersion": "1.0.0"}), 0o644), ("index.json", index, 0o644)]
    files += [("blobs/sha256/" + digest(data), data, 0o644) for data in (config, layer, manifest)]
    archive = tar_bytes(files)
    archive_path = folder / "synthetic.oci.tar"
    with open(archive_path, "xb") as output:
        os.chmod(archive_path, 0o600)
        output.write(archive)
    with open(folder / "qualification.elf", "xb") as output:
        os.chmod(folder / "qualification.elf", 0o600)
        output.write(elf)
    print(json.dumps({"directory": str(folder), "archive": str(archive_path), "archive_sha256": digest(archive), "image_id": "sha256:" + digest(config), "layer_sha256": digest(layer)}, sort_keys=True))


if __name__ == "__main__":
    main()
