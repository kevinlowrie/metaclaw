#!/usr/bin/env python3
"""Pure synthetic guard tests: no seed, VM, package, network or root actions."""
import importlib.util
import json
import os
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('guest_bootstrap', Path(__file__).with_name('nocloud-qualification-bootstrap.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

V4 = 'Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n'
V6 = '00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000000 00000000 00200200 lo\n'

class Guards(unittest.TestCase):
    def test_loopback_only(self):
        module.check_network(['lo'], V4, V6)
        with self.assertRaises(ValueError): module.check_network(['eth0','lo'], V4, V6)
    def test_default_routes_fail(self):
        with self.assertRaises(ValueError): module.check_network(['lo'], V4 + 'lo 00000000 00000000 0001 0 0 0 00000000\n', V6)
        with self.assertRaises(ValueError): module.check_network(['lo'], V4, V6.replace('00200200','00000001'))
    def test_failure_remains_unknown(self):
        d = module.status_record('runner', False)
        self.assertEqual((d['result'], d['exact_container_absence'], d['broader_cleanup']), ('unknown','unknown','unknown'))
        self.assertLessEqual(len(('METACLAW_QUAL_V1 '+json.dumps(d,sort_keys=True,separators=(',',':'))+'\n').encode()),512)
        with self.assertRaises(ValueError): module.status_record('unexpected', True)
    def test_success_does_not_claim_global_cleanup(self):
        d = module.status_record('complete', True)
        self.assertEqual((d['result'], d['exact_container_absence'], d['broader_cleanup']), ('passed','confirmed','unknown'))
    def test_mount_requires_exact_readonly_iso_device(self):
        line = '42 1 11:0 / /run/metaclaw-seed ro,nosuid,nodev,noexec - iso9660 /dev/sr0 ro\n'
        flags = os.ST_RDONLY | os.ST_NOSUID | os.ST_NODEV | os.ST_NOEXEC
        module.check_mountinfo(line, '11:0', flags)
        for text, actual in ((line, '11:1'), (line.replace('iso9660', 'ext4'), '11:0'), (line + line, '11:0'), (line.replace('/run/metaclaw-seed','/run/other'), '11:0')):
            with self.subTest(text=text, actual=actual), self.assertRaises(ValueError): module.check_mountinfo(text, actual, flags)
        with self.assertRaises(ValueError): module.check_mountinfo(line, '11:0', flags & ~os.ST_NODEV)

if __name__ == '__main__': unittest.main()
