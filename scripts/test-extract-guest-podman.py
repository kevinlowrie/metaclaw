#!/usr/bin/env python3
"""Synthetic in-memory parser guards; never touches /opt or real packages."""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import tarfile
import tempfile
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location('guest_extractor', Path(__file__).with_name('extract-guest-podman.py'))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def archive(rows):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode='w') as tar:
        for name, kind, payload in rows:
            info = tarfile.TarInfo(name)
            if kind == 'link':
                info.type = tarfile.SYMTYPE; info.linkname = payload
                tar.addfile(info)
            else:
                info.mode = 0o755; info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
    return io.BytesIO(result.getvalue())


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.expected = {'usr/bin/tool': (0o755, 4, hashlib.sha256(b'test').hexdigest())}
        self.links = {'usr/lib/libx.so': 'libx.so.1'}
        self.written = []
    def scan(self, rows):
        return mod.scan(archive(rows), self.expected, self.links, lambda *args: self.written.append(args))
    def test_only_expected_payload_is_emitted(self):
        found = self.scan([('./usr/bin/tool','file',b'test'),('./usr/lib/libx.so','link','libx.so.1'),('./usr/lib/systemd/system/x.service','file',b'unit')])
        self.assertEqual(found, set(self.expected) | set(self.links))
        self.assertEqual([x[0] for x in self.written], ['usr/bin/tool'])
    def test_reject_traversal_and_duplicates(self):
        for rows in [[('../escape','file',b'x')],[('./usr/bin/tool','file',b'test'),('./usr/bin/tool','file',b'test')]]:
            with self.subTest(rows=rows), self.assertRaises(ValueError): self.scan(rows)
    def test_reject_wrong_type_link_and_digest(self):
        for rows in [[('./usr/bin/tool','link','tool')],[('./usr/lib/libx.so','link','/outside')],[('./usr/bin/tool','file',b'evil')]]:
            with self.subTest(rows=rows), self.assertRaises(ValueError): self.scan(rows)
    def test_limits_apply_to_all_tar_members(self):
        rows = [('./a','file',b'1234'),('./b','file',b'1234')]
        for kwargs in ({'max_members':1}, {'max_member_size':3}, {'max_total_size':7}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                mod.scan(archive(rows), self.expected, self.links, lambda *_: None, **kwargs)
    def test_root_owned_0600_only_when_mount_readonly(self):
        good = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0)
        self.assertTrue(mod.safe_archive(good, True))
        self.assertFalse(mod.safe_archive(good, False))
        self.assertFalse(mod.safe_archive(SimpleNamespace(st_mode=stat.S_IFREG | 0o622, st_uid=0), True))
        self.assertFalse(mod.safe_archive(SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=1), True))
    def test_atomic_publish_never_replaces_existing_path(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / 'source'; source.mkdir()
            destination = root / 'destination'; destination.mkdir()
            with self.assertRaises(OSError): mod.publish_no_replace(source, destination)
            self.assertTrue(source.is_dir()); self.assertTrue(destination.is_dir())
            destination.rmdir()
            mod.publish_no_replace(source, destination)
            self.assertFalse(source.exists()); self.assertTrue(destination.is_dir())

if __name__ == '__main__': unittest.main()
