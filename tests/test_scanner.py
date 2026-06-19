"""Tests for WiFiScanner's vuln lookup and the native interface up/down."""
import contextlib
import importlib.util
import io
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


class TestIfaceUp(unittest.TestCase):
    def test_no_external_binary(self):
        # The whole tool must shell out to nothing.
        with open(_ONESHOT) as f:
            src = f.read()
        self.assertNotIn('import subprocess', src)
        self.assertNotIn("['ip'", src)

    def test_missing_interface_returns_false(self):
        # ifaceUp uses an ioctl (no 'ip'); a bogus iface -> ENODEV -> False,
        # not a crash. (The GET ioctl fails before any privileged op, so this
        # works without root.)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(oneshot.ifaceUp('nonexistent-xyz0'))


if __name__ == '__main__':
    unittest.main()
