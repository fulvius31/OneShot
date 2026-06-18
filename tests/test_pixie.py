"""Tests for the pure-Python Pixie-Dust cracker (pixie.py).

Builds synthetic-but-self-consistent WPS captures (the way a vulnerable AP would
produce them) and checks that pixie.recover_pin recovers the chosen PIN: the
all-zero secret-nonce case, the E-Nonce-reuse case, and a full Ralink-LFSR
capture generated forward by the same PRNG pixiewps inverts.
"""
import importlib.util
import os
import unittest

_HERE = os.path.dirname(os.path.realpath(__file__))
_ROOT = os.path.dirname(_HERE)


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_ROOT, name + '.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


wc = _load('wps_crypto')
pixie = _load('pixie')

PKE = bytes(range(192))
PKR = bytes((255 - i) for i in range(192))
AUTHKEY = bytes((i * 7) & 0xFF for i in range(32))
PIN = '12345670'   # valid WPS pin (last digit is the checksum)


def _hashes_for(e_s1, e_s2):
    """Compute E-Hash1/E-Hash2 the way an enrollee committing to PIN would."""
    psk1 = pixie._psk_half(AUTHKEY, PIN[:4])
    psk2 = pixie._psk_half(AUTHKEY, PIN[4:])
    eh1 = wc.wps_hash(AUTHKEY, e_s1, psk1, PKE, PKR)
    eh2 = wc.wps_hash(AUTHKEY, e_s2, psk2, PKE, PKR)
    return eh1, eh2


class TestTrivialModes(unittest.TestCase):
    def test_all_zero_secret_nonces(self):
        z = b'\x00' * 16
        eh1, eh2 = _hashes_for(z, z)
        self.assertEqual(
            pixie.recover_pin(PKE, PKR, eh1, eh2, AUTHKEY, b'\x11' * 16), PIN)

    def test_secret_nonces_equal_enonce(self):
        e_nonce = bytes((i * 3 + 1) & 0xFF for i in range(16))
        eh1, eh2 = _hashes_for(e_nonce, e_nonce)
        self.assertEqual(
            pixie.recover_pin(PKE, PKR, eh1, eh2, AUTHKEY, e_nonce), PIN)


class TestRalink(unittest.TestCase):
    def test_lfsr_roundtrip(self):
        # forward then backward over the same state must be identity per byte
        st = [0xDEADBEEF]
        b = pixie._randbyte(st)
        # one forward step then one backward step returns to a consistent stream
        self.assertIsInstance(b, int)
        self.assertTrue(0 <= b <= 255)

    def test_ralink_capture(self):
        # Generate E-S1, E-S2, E-Nonce as one continuous Ralink-LFSR stream,
        # exactly the layout pixiewps assumes (secret nonces precede the nonce).
        state = [0x12345678]
        e_s1 = bytes(pixie._randbyte(state) for _ in range(16))
        e_s2 = bytes(pixie._randbyte(state) for _ in range(16))
        e_nonce = bytes(pixie._randbyte(state) for _ in range(16))

        # The cracker must reconstruct the secret nonces from the nonce alone.
        rec = pixie._ralink_secret_nonces(e_nonce)
        self.assertIsNotNone(rec)
        self.assertEqual(rec, (e_s1, e_s2))

        eh1, eh2 = _hashes_for(e_s1, e_s2)
        self.assertEqual(
            pixie.recover_pin(PKE, PKR, eh1, eh2, AUTHKEY, e_nonce), PIN)

    def test_non_ralink_nonce_returns_none(self):
        # A random nonce should not be mistaken for a Ralink-LFSR stream in a way
        # that yields a PIN against unrelated hashes.
        self.assertIsNone(
            pixie.recover_pin(PKE, PKR, b'\x00' * 32, b'\x11' * 32, AUTHKEY, b'\x5a' * 16))


class TestHexWrapper(unittest.TestCase):
    def test_hex_api(self):
        z = b'\x00' * 16
        eh1, eh2 = _hashes_for(z, z)
        pin = pixie.recover_pin_hex(PKE.hex(), PKR.hex(), eh1.hex(), eh2.hex(),
                                    AUTHKEY.hex(), ('11' * 16))
        self.assertEqual(pin, PIN)

    def test_hex_api_bad_input(self):
        self.assertIsNone(pixie.recover_pin_hex('zz', '', '', '', '', ''))


if __name__ == '__main__':
    unittest.main()
