"""Tests for the native WPS engine (wps_crypto + wps_connect).

The live nl80211/AF_PACKET transport needs root + a real adapter and is not
tested here. Everything else — DH/KDF/key derivation, the WSC message layer,
and EAP/EAPOL framing — is validated in-process against a mirror Enrollee that
mimics what a real AP does, proving both sides derive the same AuthKey and the
E-Hash commitment formula matches.
"""
import importlib.util
import os
import struct
import unittest

_HERE = os.path.dirname(os.path.realpath(__file__))
_ROOT = os.path.dirname(_HERE)


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_ROOT, name + '.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


wc = _load('wps_crypto')
wps = _load('wps_connect')


class _MirrorEnrollee:
    """Minimal WPS Enrollee (the role a real AP plays) for end-to-end tests."""

    def __init__(self, pin='12345670'):
        self.pin = pin
        self.dh_priv, self.pke = wc.dh_keypair()
        self.nonce_e = os.urandom(wc.NONCE_LEN)
        self.mac = b'\xaa\xbb\xcc\xdd\xee\xff'
        self.es1 = os.urandom(wc.NONCE_LEN)
        self.es2 = os.urandom(wc.NONCE_LEN)
        self.authkey = None

    def build_m1(self):
        msg = (wps.attr_u8(wps.ATTR_VERSION, wps.WPS_VERSION)
               + wps.attr_u8(wps.ATTR_MSG_TYPE, wps.WPS_M1)
               + wps.attr(wps.ATTR_ENROLLEE_NONCE, self.nonce_e)
               + wps.attr(wps.ATTR_PUBLIC_KEY, self.pke)
               + wps.attr(wps.ATTR_MAC_ADDR, self.mac))
        self._m1 = msg
        return msg

    def recv_m2(self, m2, pkr):
        a = wps.attrs_dict(m2)
        nonce_r = a[wps.ATTR_REGISTRAR_NONCE]
        self.authkey, self.keywrapkey, self.emsk = wc.derive_keys(
            pkr, self.dh_priv, self.nonce_e, self.mac, nonce_r)
        # verify the registrar's Authenticator over (M1 || M2*)
        auth = a[wps.ATTR_AUTHENTICATOR]
        body = m2[:m2.index(struct.pack('>HH', wps.ATTR_AUTHENTICATOR, 8))]
        return wc.authenticator(self.authkey, self._m1, body) == auth

    def build_m3(self, pke, pkr):
        self.pke, self.pkr = pke, pkr
        psk1, psk2 = wc.derive_psk(self.authkey, self.pin)
        eh1 = wc.wps_hash(self.authkey, self.es1, psk1, pke, pkr)
        eh2 = wc.wps_hash(self.authkey, self.es2, psk2, pke, pkr)
        return (wps.attr_u8(wps.ATTR_VERSION, wps.WPS_VERSION)
                + wps.attr_u8(wps.ATTR_MSG_TYPE, wps.WPS_M3)
                + wps.attr(wps.ATTR_E_HASH1, eh1)
                + wps.attr(wps.ATTR_E_HASH2, eh2))

    def build_m5(self):
        # send the real E-S1 back (proves we used the same PIN half)
        inner = wps.attr(wps.ATTR_E_SNONCE1, self.es1)
        encr = wps.build_encrypted_settings(self.keywrapkey, self.authkey, inner)
        return (wps.attr_u8(wps.ATTR_MSG_TYPE, wps.WPS_M5)
                + wps.attr(wps.ATTR_ENCR_SETTINGS, encr))

    def build_m7(self, network_key=b'CorrectHorseBattery', ssid=b'TestNet'):
        # the AP's current credential travels in M7's Encrypted Settings
        inner = (wps.attr(wps.ATTR_E_SNONCE2, self.es2)
                 + wps.attr(wps.ATTR_SSID, ssid)
                 + wps.attr(wps.ATTR_NETWORK_KEY, network_key))
        encr = wps.build_encrypted_settings(self.keywrapkey, self.authkey, inner)
        return (wps.attr_u8(wps.ATTR_MSG_TYPE, wps.WPS_M7)
                + wps.attr(wps.ATTR_ENCR_SETTINGS, encr))


class TestDhAndKdf(unittest.TestCase):
    def test_dh_shared_is_symmetric(self):
        a_priv, a_pub = wc.dh_keypair()
        b_priv, b_pub = wc.dh_keypair()
        self.assertEqual(wc.dh_shared(b_pub, a_priv), wc.dh_shared(a_pub, b_priv))
        self.assertEqual(len(a_pub), 192)

    def test_kdf_length_and_determinism(self):
        key = b'\x11' * 32
        out = wc.wps_kdf(key, 80)
        self.assertEqual(len(out), 80)
        self.assertEqual(out, wc.wps_kdf(key, 80))

    def test_derive_psk_halves(self):
        ak = b'\x22' * 32
        psk1, psk2 = wc.derive_psk(ak, '12345670')
        self.assertEqual(len(psk1), 16)
        self.assertEqual(len(psk2), 16)
        self.assertNotEqual(psk1, psk2)


class TestEapFraming(unittest.TestCase):
    def test_eapol_start_roundtrip(self):
        etype, payload = wps.parse_eapol(wps.eapol_start())
        self.assertEqual(etype, wps.EAPOL_TYPE_START)
        self.assertEqual(payload, b'')

    def test_identity_response_roundtrip(self):
        frame = wps.eap_identity_response(7, wps.REGISTRAR_IDENTITY)
        _, payload = wps.parse_eapol(frame)
        info = wps.parse_eap(payload)
        self.assertEqual(info['code'], wps.EAP_CODE_RESPONSE)
        self.assertEqual(info['id'], 7)
        self.assertEqual(info['identity'], wps.REGISTRAR_IDENTITY)

    def test_wsc_response_roundtrip(self):
        frame = wps.eap_wsc_response(9, wps.WSC_MSG, b'hello-wsc')
        _, payload = wps.parse_eapol(frame)
        info = wps.parse_eap(payload)
        self.assertEqual(info['type'], wps.EAP_TYPE_EXPANDED)
        self.assertEqual(info['vendor'], wps.EAP_VENDOR_WFA)
        self.assertEqual(info['vendor_type'], wps.EAP_VENDOR_TYPE_WSC)
        self.assertEqual(info['op_code'], wps.WSC_MSG)
        self.assertEqual(info['message'], b'hello-wsc')


class TestRegistrarExchange(unittest.TestCase):
    def test_m1_m2_m3_and_pixie_data(self):
        enrollee = _MirrorEnrollee(pin='12345670')
        reg = wps.WpsRegistrar(registrar_mac=b'\x00\x11\x22\x33\x44\x55')

        # M1 (AP -> registrar)
        reg.process_m1(enrollee.build_m1())
        self.assertEqual(reg.pke, enrollee.pke)
        self.assertEqual(reg.nonce_e, enrollee.nonce_e)

        # M2 (registrar -> AP) — enrollee must derive the SAME AuthKey and
        # accept our Authenticator.
        m2 = reg.build_m2()
        self.assertTrue(enrollee.recv_m2(m2, reg.pkr), 'M2 authenticator rejected')
        self.assertEqual(reg.authkey, enrollee.authkey, 'AuthKey disagreement')

        # M3 (AP -> registrar)
        reg.process_m3(enrollee.build_m3(reg.pke, reg.pkr))

        data = reg.pixie_data()
        self.assertIsNotNone(data)
        # all six fields present, hex, correct lengths
        self.assertEqual(len(data['e_nonce']), 32)     # 16 bytes
        self.assertEqual(len(data['pke']), 384)        # 192 bytes
        self.assertEqual(len(data['pkr']), 384)
        self.assertEqual(len(data['authkey']), 64)     # 32 bytes
        self.assertEqual(len(data['e_hash1']), 64)
        self.assertEqual(len(data['e_hash2']), 64)

        # The decisive check: recompute E-Hash1 with the registrar-derived
        # AuthKey + the enrollee's secrets; it must equal what we received.
        psk1, psk2 = wc.derive_psk(reg.authkey, enrollee.pin)
        eh1 = wc.wps_hash(reg.authkey, enrollee.es1, psk1, reg.pke, reg.pkr)
        self.assertEqual(eh1.hex().upper(), data['e_hash1'])


class TestFullPinPath(unittest.TestCase):
    """Phase 2: M1..M7 with AES Encrypted Settings -> recovered PSK."""

    def test_psk_recovered_with_correct_pin(self):
        enrollee = _MirrorEnrollee(pin='12345670')
        reg = wps.WpsRegistrar(registrar_mac=b'\x00\x11\x22\x33\x44\x55', pin='12345670')

        reg.process_m1(enrollee.build_m1())
        self.assertTrue(enrollee.recv_m2(reg.build_m2(), reg.pkr))
        reg.process_m3(enrollee.build_m3(reg.pke, reg.pkr))

        reg.build_m4()                       # R-Hash1/2 + Encrypted{R-S1}
        reg.process_m5(enrollee.build_m5())  # verify first half
        self.assertTrue(reg.first_half_ok)
        reg.build_m6()
        reg.process_m7(enrollee.build_m7(network_key=b'CorrectHorseBattery',
                                         ssid=b'TestNet'))

        cred = reg.credential()
        self.assertEqual(cred['psk'], 'CorrectHorseBattery')
        self.assertEqual(cred['ssid'], 'TestNet')

    def test_m4_m6_carry_enrollee_nonce(self):
        # Mandatory ATTR_ENROLLEE_NONCE — real hostapd enrollees NACK without it.
        enrollee = _MirrorEnrollee(pin='12345670')
        reg = wps.WpsRegistrar(registrar_mac=b'\x00\x11\x22\x33\x44\x55', pin='12345670')
        reg.process_m1(enrollee.build_m1())
        enrollee.recv_m2(reg.build_m2(), reg.pkr)
        reg.process_m3(enrollee.build_m3(reg.pke, reg.pkr))
        for msg in (reg.build_m4(), (reg.process_m5(enrollee.build_m5()) or reg.build_m6())):
            self.assertEqual(wps.attrs_dict(msg).get(wps.ATTR_ENROLLEE_NONCE), reg.nonce_e)


class TestAssocIe(unittest.TestCase):
    def test_wsc_assoc_ie_uses_wps_oui(self):
        ie = wps.wsc_assoc_ie()
        self.assertEqual(ie[0], 0xDD)                       # vendor element
        self.assertEqual(ie[2:6], b'\x00\x50\xf2\x04')     # WPS OUI + type, not 00:37:2A

    def test_wrong_pin_fails_first_half(self):
        enrollee = _MirrorEnrollee(pin='12345670')
        reg = wps.WpsRegistrar(registrar_mac=b'\x00\x11\x22\x33\x44\x55', pin='00000000')
        reg.process_m1(enrollee.build_m1())
        enrollee.recv_m2(reg.build_m2(), reg.pkr)
        reg.process_m3(enrollee.build_m3(reg.pke, reg.pkr))
        reg.build_m4()
        with self.assertRaises(wps.WpsProtocolError):
            reg.process_m5(enrollee.build_m5())


class TestAes(unittest.TestCase):
    def test_fips197_vector(self):
        key = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        pt = bytes.fromhex('00112233445566778899aabbccddeeff')
        ct = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')
        self.assertEqual(wc.aes128_cbc_encrypt(key, b'\x00' * 16, pt), ct)
        self.assertEqual(wc.aes128_cbc_decrypt(key, b'\x00' * 16, ct), pt)


if __name__ == '__main__':
    unittest.main()
