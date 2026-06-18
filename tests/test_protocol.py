"""Tests for the hardware-independent protocol/parsing layer of oneshot.py.

These drive the riskiest code — the wpa_supplicant output state machine
(__handle_wpas), the iw scan parser (iw_scanner), and the bruteforce retry
loop — using canned input, with no Wi-Fi hardware or root required.
"""
import contextlib
import importlib.util
import io
import os
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.realpath(__file__))
_ONESHOT = os.path.join(os.path.dirname(_HERE), 'oneshot.py')
_spec = importlib.util.spec_from_file_location('oneshot', _ONESHOT)
oneshot = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(oneshot)

Companion = oneshot.Companion
ConnectionStatus = oneshot.ConnectionStatus
PixiewpsData = oneshot.PixiewpsData
BruteforceStatus = oneshot.BruteforceStatus
WPSpin = oneshot.WPSpin
WiFiScanner = oneshot.WiFiScanner


def _bare_companion():
    """A Companion with just the attributes the parser needs (no __init__)."""
    c = Companion.__new__(Companion)
    c.print_debug = False
    c.interface = 'wlan0'
    c.pixie_creds = PixiewpsData()
    c.connection_status = ConnectionStatus()
    return c


class _FakeStream:
    def __init__(self, lines):
        self._it = iter(lines)

    def readline(self):
        return next(self._it, '')


class _FakeWpas:
    def __init__(self, lines):
        self.stdout = _FakeStream(lines)

    def wait(self):
        pass

    def terminate(self):
        pass


def _handle(companion, lines):
    """Feed lines through __handle_wpas one at a time (suppressing prints)."""
    companion.wpas = _FakeWpas(lines)
    handler = companion._Companion__handle_wpas
    with contextlib.redirect_stdout(io.StringIO()):
        for _ in lines:
            handler()


class TestGetHex(unittest.TestCase):
    def test_parses_hexdump_tail(self):
        self.assertEqual(oneshot.get_hex('WPS: Foo - hexdump(len=2): ab cd'), 'ABCD')


class TestCaptureHex(unittest.TestCase):
    def test_valid_value_is_stored(self):
        c = _bare_companion()
        nonce = 'aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99'
        with contextlib.redirect_stdout(io.StringIO()):
            c._capture_hex('WPS: Enrollee Nonce - hexdump(len=16): ' + nonce,
                           'e_nonce', 16 * 2, 'E-Nonce', pixiemode=False, verbose=False)
        self.assertEqual(c.pixie_creds.e_nonce, 'AABBCCDDEEFF00112233445566778899')

    def test_malformed_value_is_skipped_not_crashed(self):
        c = _bare_companion()
        # Too short: previously an assert would crash (or vanish under -O);
        # now it must simply not be stored.
        c._capture_hex('WPS: Enrollee Nonce - hexdump(len=2): aa bb',
                       'e_nonce', 16 * 2, 'E-Nonce', pixiemode=False, verbose=False)
        self.assertEqual(c.pixie_creds.e_nonce, '')


class TestHandleWpasStateMachine(unittest.TestCase):
    def test_received_m_message_tracked(self):
        c = _bare_companion()
        _handle(c, ['WPS: Received M5'])
        self.assertEqual(c.connection_status.last_m_message, 5)

    def test_building_message_tracked(self):
        c = _bare_companion()
        _handle(c, ['WPS: Building Message M2'])
        self.assertEqual(c.connection_status.last_m_message, 2)

    def test_wrong_pin_gives_wsc_nack(self):
        c = _bare_companion()
        c.connection_status.status = 'associating'   # must be non-empty to reach WPS-FAIL branch
        _handle(c, ['WPS-FAIL msg=8 config_error=0'])
        self.assertEqual(c.connection_status.status, 'WSC_NACK')

    def test_wps_locked_detected(self):
        c = _bare_companion()
        c.connection_status.status = 'associating'
        _handle(c, ['WPS-FAIL msg=5 config_error=15'])
        self.assertEqual(c.connection_status.status, 'WPS_FAIL')

    def test_got_psk(self):
        c = _bare_companion()
        # 'PASSWORD' as hex => 50 41 53 53 57 4f 52 44
        _handle(c, ['WPS: Network Key - hexdump(len=8): 50 41 53 53 57 4f 52 44'])
        self.assertEqual(c.connection_status.status, 'GOT_PSK')
        self.assertEqual(c.connection_status.wpa_psk, 'PASSWORD')

    def test_pixie_creds_collected(self):
        c = _bare_companion()
        nonce = 'aa bb cc dd ee ff 00 11 22 33 44 55 66 77 88 99'
        _handle(c, ['WPS: Enrollee Nonce - hexdump(len=16): ' + nonce])
        self.assertEqual(c.pixie_creds.e_nonce, 'AABBCCDDEEFF00112233445566778899')


class TestBruteforceTermination(unittest.TestCase):
    def test_first_half_aborts_after_max_failures(self):
        c = Companion.__new__(Companion)
        c.generator = WPSpin()
        c.connection_status = ConnectionStatus()
        c.bruteforce = BruteforceStatus()
        calls = []

        def fake_single_connection(bssid, pin):
            calls.append(pin)
            c.connection_status.status = 'WPS_FAIL'
            c.connection_status.last_m_message = 0

        c.single_connection = fake_single_connection
        with contextlib.redirect_stdout(io.StringIO()):
            result = c._Companion__first_half_bruteforce('AA:BB:CC:DD:EE:FF', '0000')
        # Must terminate (not recurse/loop forever) and stop at the retry cap.
        self.assertFalse(result)
        self.assertEqual(len(calls), Companion.MAX_WPS_FAIL_RETRIES + 1)


class TestIwScannerParsing(unittest.TestCase):
    SAMPLE = '\n'.join([
        'BSS aa:bb:cc:dd:ee:ff(on wlan0)',
        '\tsignal: -42.00 dBm',
        '\tSSID: TestNet',
        '\tWPS:\t * Version: 1.0',
        '\t * AP setup locked: 0x0',
        '\t * Model: SomeRouter',
        'BSS 11:22:33:44:55:66(on wlan0)',   # second BSS, no WPS -> filtered out
        '\tsignal: -70.00 dBm',
        '\tSSID: NoWpsNet',
    ])

    def test_parses_only_wps_networks(self):
        scanner = WiFiScanner('wlan0', [])
        fake_proc = mock.Mock(stdout=self.SAMPLE, returncode=0)
        with mock.patch.object(oneshot.subprocess, 'run', return_value=fake_proc):
            with contextlib.redirect_stdout(io.StringIO()):
                networks = scanner.iw_scanner()
        self.assertEqual(len(networks), 1)
        net = networks[1]
        self.assertEqual(net['BSSID'], 'AA:BB:CC:DD:EE:FF')
        self.assertEqual(net['ESSID'], 'TestNet')
        self.assertTrue(net['WPS'])
        self.assertEqual(net['Level'], -42)


class TestPinDbCache(unittest.TestCase):
    def test_is_vuln_matches_known_prefix(self):
        scanner = WiFiScanner('wlan0', [])
        if not scanner.vuln_prefixes:
            self.skipTest('pins.csv empty or missing')
        known = scanner.vuln_prefixes[0][0]
        self.assertTrue(scanner.is_vuln_from_pin_db(known + 'FFFFFF'))
        self.assertFalse(scanner.is_vuln_from_pin_db('ZZZZZZZZZZZZ'))


if __name__ == '__main__':
    unittest.main()
