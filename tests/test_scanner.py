"""Test for WiFiScanner's vulnerability lookup against pins.csv."""
import importlib.util
import os
import unittest

_HERE = os.path.dirname(os.path.realpath(__file__))
_ONESHOT = os.path.join(os.path.dirname(_HERE), 'oneshot.py')
_spec = importlib.util.spec_from_file_location('oneshot', _ONESHOT)
oneshot = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(oneshot)


class TestPinDbCache(unittest.TestCase):
    def test_is_vuln_matches_known_prefix(self):
        scanner = oneshot.WiFiScanner('wlan0', [])
        if not scanner.vuln_prefixes:
            self.skipTest('pins.csv empty or missing')
        known = scanner.vuln_prefixes[0][0]
        self.assertTrue(scanner.is_vuln_from_pin_db(known + 'FFFFFF'))
        self.assertFalse(scanner.is_vuln_from_pin_db('ZZZZZZZZZZZZ'))


if __name__ == '__main__':
    unittest.main()
