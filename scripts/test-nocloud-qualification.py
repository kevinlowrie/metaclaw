#!/usr/bin/env python3
"""Pure synthetic guard tests: no seed, VM, package, network or root actions."""
import importlib.util
import json
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
        self.assertEqual((d['result'], d['cleanup']), ('unknown','unknown'))
        self.assertLessEqual(len(('METACLAW_QUAL_V1 '+json.dumps(d,sort_keys=True,separators=(',',':'))+'\n').encode()),512)
        with self.assertRaises(ValueError): module.status_record('unexpected', True)

if __name__ == '__main__': unittest.main()
