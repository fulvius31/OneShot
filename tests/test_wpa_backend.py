"""Tests for the wpa_supplicant backend's debug-stream parser.

The live subprocess/control-socket path needs root + a wpa_supplicant binary and
is not tested here. The parser that turns wpa_supplicant's `-K -d` output into
Pixie-Dust inputs and the final PSK is pure logic, so it is fully covered.
"""
import importlib.util
import os
import shutil
import tempfile
import unittest

_HERE = os.path.dirname(os.path.realpath(__file__))
_ROOT = os.path.dirname(_HERE)


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_ROOT, name + '.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


oneshot = _load('oneshot')
wpa_backend = _load('wpa_backend')


class TestGetHex(unittest.TestCase):
    def test_hexdump_line(self):
        line = ('WPS: Enrollee Nonce - hexdump(len=16): '
                '11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 00')
        self.assertEqual(wpa_backend._get_hex(line),
                         '112233445566778899AABBCCDDEEFF00')


class TestParser(unittest.TestCase):
    def setUp(self):
        self.run_dir = tempfile.mkdtemp()
        # __init__ only writes a conf + makes a dir; it does NOT spawn wpa_supplicant.
        self.w = wpa_backend.WpaSupplicant('wlan0', self.run_dir, verbose=False)

    def tearDown(self):
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def _feed(self, lines, creds, status, pixiemode=False):
        for ln in lines:
            self.w._handle_line(ln, creds, status, pixiemode)

    def test_collects_all_pixie_inputs(self):
        creds = oneshot.PixiewpsData()
        status = oneshot.ConnectionStatus()
        n16 = ' '.join(['11'] * 16)
        n32 = ' '.join(['22'] * 32)
        n192 = ' '.join(['33'] * 192)
        self._feed([
            'WPS: Building Message M2',
            'WPS: Received M1',
            'WPS: Enrollee Nonce - hexdump(len=16): ' + n16,
            'WPS: DH own Public Key - hexdump(len=192): ' + n192,    # PKR
            'WPS: DH peer Public Key - hexdump(len=192): ' + n192,   # PKE
            'WPS: AuthKey - hexdump(len=32): ' + n32,
            'WPS: E-Hash1 - hexdump(len=32): ' + n32,
            'WPS: E-Hash2 - hexdump(len=32): ' + n32,
        ], creds, status, pixiemode=True)
        self.assertTrue(creds.got_all())
        self.assertEqual(len(creds.e_nonce), 32)     # 16 bytes hex
        self.assertEqual(len(creds.pke), 384)        # 192 bytes hex
        self.assertEqual(len(creds.pkr), 384)
        self.assertEqual(len(creds.authkey), 64)
        self.assertEqual(status.last_m_message, 1)   # last 'Received M1'

    def test_network_key_yields_psk(self):
        creds = oneshot.PixiewpsData()
        status = oneshot.ConnectionStatus()
        # 'password' in ASCII hex
        self._feed(['WPS: Network Key - hexdump(len=8): 70 61 73 73 77 6f 72 64'],
                   creds, status)
        self.assertEqual(status.status, 'GOT_PSK')
        self.assertEqual(status.wpa_psk, 'password')

    def test_wps_fail_wrong_pin(self):
        creds = oneshot.PixiewpsData()
        status = oneshot.ConnectionStatus()
        status.status = 'associating'   # WPS-FAIL only acts once the exchange started
        self._feed(['WPS-FAIL ... msg=8 config_error=0'], creds, status)
        self.assertEqual(status.status, 'WSC_NACK')

    def test_find_binary_prefers_explicit_existing(self):
        # A bogus explicit path falls through to the PATH/Android search, never crashes.
        self.assertTrue(wpa_backend._find_binary('/nonexistent/wpa_supplicant'))


if __name__ == '__main__':
    unittest.main()
