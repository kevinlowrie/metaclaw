#!/usr/bin/env python3
"""Independently validate the complete synthetic OCI tar without executing it."""
import hashlib
import io
import json
import os
import stat
import struct
import sys
import tarfile
from pathlib import Path


def check(condition, message):
    if not condition:
        raise ValueError(message)


def pairs(values):
    result = {}
    for key, value in values:
        check(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=pairs)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def contents(data, max_entries):
    result = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for item in archive:
            check(item.isfile() and item.name not in result and len(result) < max_entries, "unexpected tar member")
            check(item.uid == item.gid == item.mtime == 0 and item.uname == item.gname == "", "unexpected tar metadata")
            check(item.size <= 1_000_000, "member too large")
            stream = archive.extractfile(item)
            check(stream is not None, "member unavailable")
            result[item.name] = (stream.read(), item.mode)
    return result


def main():
    check(len(sys.argv) == 2, "usage: validate-qualification-oci.py /absolute/archive")
    path = Path(sys.argv[1])
    st = os.lstat(path)
    check(path.is_absolute() and stat.S_ISREG(st.st_mode) and st.st_size <= 2_000_000, "unsafe archive")
    outer = contents(path.read_bytes(), 5)
    check(len(outer) == 5 and all(mode == 0o644 for _, mode in outer.values()), "outer archive shape")
    check(decode(outer["oci-layout"][0]) == {"imageLayoutVersion": "1.0.0"}, "OCI version")
    index = decode(outer["index.json"][0])
    check(set(index) == {"schemaVersion", "manifests"} and index["schemaVersion"] == 2 and len(index["manifests"]) == 1, "index")
    used = {"oci-layout", "index.json"}
    def blob(desc, media):
        check(desc.get("mediaType") == media and isinstance(desc.get("digest"), str), "descriptor")
        ref = desc["digest"]
        check(ref.startswith("sha256:") and len(ref) == 71 and all(c in "0123456789abcdef" for c in ref[7:]), "digest format")
        name = "blobs/sha256/" + ref[7:]
        used.add(name)
        data = outer[name][0]
        check(len(data) == desc.get("size") and digest(data) == ref[7:], "blob integrity")
        return data
    manifest = decode(blob(index["manifests"][0], "application/vnd.oci.image.manifest.v1+json"))
    check(set(manifest) == {"schemaVersion", "mediaType", "config", "layers"} and manifest["schemaVersion"] == 2 and manifest["mediaType"] == "application/vnd.oci.image.manifest.v1+json" and len(manifest["layers"]) == 1, "manifest")
    config_data = blob(manifest["config"], "application/vnd.oci.image.config.v1+json")
    config = decode(config_data)
    layer = blob(manifest["layers"][0], "application/vnd.oci.image.layer.v1.tar")
    check(config == {"architecture": "amd64", "os": "linux", "config": {"Entrypoint": ["/qualification"], "User": "65534:65534"}, "rootfs": {"type": "layers", "diff_ids": ["sha256:" + digest(layer)]}}, "image config")
    check(set(outer) == used, "extra outer members")
    files = contents(layer, 1)
    check(set(files) == {"qualification"} and files["qualification"][1] == 0o755, "rootfs members")
    elf = files["qualification"][0]
    check(len(elf) == 129, "ELF size")
    header = struct.unpack("<16sHHIQQQIHHHHHH", elf[:64])
    check(header == (b"\x7fELF\x02\x01\x01" + bytes(9), 2, 62, 1, 0x400078, 64, 0, 0, 64, 56, 1, 0, 0, 0), "ELF header")
    check(struct.unpack("<IIQQQQQQ", elf[64:120]) == (1, 5, 0, 0x400000, 0x400000, 129, 129, 4096), "ELF program header")
    check(elf[120:] == bytes.fromhex("31ffb83c0000000f05"), "unexpected executable code")
    print(json.dumps({"archive_sha256": digest(path.read_bytes()), "image_id": "sha256:" + digest(config_data), "payload_sha256": digest(elf), "validated": True}, sort_keys=True))


if __name__ == "__main__":
    main()
