"""Tests for the pure parsing core of nl80211_scan.py.

The netlink socket I/O needs root + a Wi-Fi device, but the attribute and
information-element parsers are pure functions exercised here with canned
bytes built the same way the kernel frames them.
"""
import importlib.util
import os
import struct
import unittest

_HERE = os.path.dirname(os.path.realpath(__file__))
_MOD = os.path.join(os.path.dirname(_HERE), 'nl80211_scan.py')
_spec = importlib.util.spec_from_file_location('nl80211_scan', _MOD)
nl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(nl)


def wps_tlv(attr_type, value):
    return struct.pack('>HH', attr_type, len(value)) + value


def ie(eid, body):
    return bytes([eid, len(body)]) + body


def vendor_ie(oui, otype, body):
    return ie(nl.IE_VENDOR, oui + bytes([otype]) + body)


class TestAttrRoundtrip(unittest.TestCase):
    def test_parse_matches_build(self):
        buf = nl._attr(3, struct.pack('=I', 7)) + nl._attr(47, b'abc')
        attrs = nl._parse_attrs(buf)
        self.assertEqual(struct.unpack('=I', attrs[3])[0], 7)
        self.assertEqual(attrs[47], b'abc')   # odd length padded but value intact

    def test_nested_flag_is_masked(self):
        buf = nl._attr(nl.NL80211_ATTR_BSS | nl.NLA_F_NESTED, b'xy')
        attrs = nl._parse_attrs(buf)
        self.assertIn(nl.NL80211_ATTR_BSS, attrs)


class TestWpsParsing(unittest.TestCase):
    def test_version_locked_and_model(self):
        body = (wps_tlv(nl.WPS_ATTR_VERSION, b'\x10')
                + wps_tlv(nl.WPS_ATTR_AP_SETUP_LOCKED, b'\x01')
                + wps_tlv(nl.WPS_ATTR_MODEL_NAME, b'RT-AC51U')
                + wps_tlv(nl.WPS_ATTR_MODEL_NUMBER, b'1234')
                + wps_tlv(nl.WPS_ATTR_DEVICE_NAME, b'MyRouter'))
        net = nl._new_network()
        nl._parse_wps(body, net)
        self.assertEqual(net['WPS'], '1.0')
        self.assertTrue(net['WPS locked'])
        self.assertEqual(net['Model'], 'RT-AC51U')
        self.assertEqual(net['Model number'], '1234')
        self.assertEqual(net['Device name'], 'MyRouter')

    def test_presence_without_version(self):
        net = nl._new_network()
        nl._parse_wps(wps_tlv(nl.WPS_ATTR_MODEL_NAME, b'X'), net)
        self.assertTrue(net['WPS'])
        self.assertFalse(net['WPS locked'])


class TestIeParsing(unittest.TestCase):
    def test_wpa2_with_wps(self):
        wps_body = (wps_tlv(nl.WPS_ATTR_VERSION, b'\x10')
                    + wps_tlv(nl.WPS_ATTR_AP_SETUP_LOCKED, b'\x00'))
        ies = (ie(nl.IE_SSID, b'TestNet')
               + ie(nl.IE_RSN, b'\x01\x00\x00\x0f\xac\x04')
               + vendor_ie(nl.WFA_OUI, 4, wps_body))
        net = nl._new_network()
        nl._parse_ies(ies, net, capability=nl.CAP_PRIVACY)
        self.assertEqual(net['ESSID'], 'TestNet')
        self.assertEqual(net['Security type'], 'WPA2')
        self.assertTrue(net['WPS'])
        self.assertFalse(net['WPS locked'])

    def test_mixed_wpa_wpa2(self):
        ies = ie(nl.IE_RSN, b'\x01') + vendor_ie(nl.WFA_OUI, 1, b'\x01')
        net = nl._new_network()
        nl._parse_ies(ies, net, capability=0)
        self.assertEqual(net['Security type'], 'WPA/WPA2')

    def test_open_and_wep(self):
        net_open = nl._new_network()
        nl._parse_ies(ie(nl.IE_SSID, b'Free'), net_open, capability=0)
        self.assertEqual(net_open['Security type'], 'Open')

        net_wep = nl._new_network()
        nl._parse_ies(ie(nl.IE_SSID, b'Old'), net_wep, capability=nl.CAP_PRIVACY)
        self.assertEqual(net_wep['Security type'], 'WEP')

    def test_hidden_ssid(self):
        net = nl._new_network()
        nl._parse_ies(ie(nl.IE_SSID, b''), net, capability=0)
        self.assertEqual(net['ESSID'], '')


class TestBssParsing(unittest.TestCase):
    def test_full_bss(self):
        wps_body = wps_tlv(nl.WPS_ATTR_VERSION, b'\x10')
        ies = ie(nl.IE_SSID, b'Net1') + vendor_ie(nl.WFA_OUI, 4, wps_body)
        bss = (nl._attr(nl.NL80211_BSS_BSSID, b'\xaa\xbb\xcc\xdd\xee\xff')
               + nl._attr(nl.NL80211_BSS_SIGNAL_MBM, struct.pack('=i', -4200))
               + nl._attr(nl.NL80211_BSS_CAPABILITY, struct.pack('=H', nl.CAP_PRIVACY))
               + nl._attr(nl.NL80211_BSS_INFORMATION_ELEMENTS, ies))
        net = nl._parse_bss(nl._parse_attrs(bss))
        self.assertEqual(net['BSSID'], 'AA:BB:CC:DD:EE:FF')
        self.assertEqual(net['Level'], -42)
        self.assertEqual(net['ESSID'], 'Net1')
        self.assertTrue(net['WPS'])

    def test_bss_without_bssid_is_dropped(self):
        bss = nl._attr(nl.NL80211_BSS_FREQUENCY, struct.pack('=I', 2412))
        self.assertIsNone(nl._parse_bss(nl._parse_attrs(bss)))

    def test_beacon_ies_fallback(self):
        # A BSS carrying only beacon IEs (passive scan) must still parse;
        # guards NL80211_BSS_BEACON_IES against the wrong enum value.
        ies = ie(nl.IE_SSID, b'BeaconOnly')
        bss = (nl._attr(nl.NL80211_BSS_BSSID, b'\x11\x22\x33\x44\x55\x66')
               + nl._attr(nl.NL80211_BSS_BEACON_IES, ies))
        net = nl._parse_bss(nl._parse_attrs(bss))
        self.assertEqual(net['ESSID'], 'BeaconOnly')
        self.assertEqual(nl.NL80211_BSS_BEACON_IES, 11)


class TestScanErrors(unittest.TestCase):
    def test_unknown_interface_raises(self):
        with self.assertRaises(nl.Nl80211Error):
            nl.scan('definitely-not-an-iface-xyz')


if __name__ == '__main__':
    unittest.main()
