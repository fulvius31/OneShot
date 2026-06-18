"""Unit tests for OneShot's pure logic (PIN generation, MAC handling).

Run with either:
    python3 -m unittest discover -s tests
    python3 -m pytest tests/        (if pytest is installed)

These cover the deterministic, hardware-independent parts of oneshot.py:
the WPS PIN algorithms, the checksum, and the NetworkAddress helper — plus
regression guards for the bugs fixed in the engineering pass.
"""
import importlib.util
import os
import unittest

_HERE = os.path.dirname(os.path.realpath(__file__))
_ONESHOT = os.path.join(os.path.dirname(_HERE), 'oneshot.py')
_spec = importlib.util.spec_from_file_location('oneshot', _ONESHOT)
oneshot = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(oneshot)

NetworkAddress = oneshot.NetworkAddress
WPSpin = oneshot.WPSpin


class TestChecksum(unittest.TestCase):
    def test_known_values(self):
        cs = WPSpin.checksum
        # The standard WPS checksum: appended digit makes the 8-digit PIN valid.
        self.assertEqual(cs(0), 0)
        self.assertEqual(cs(1), 7)
        # checksum is a single digit 0..9
        for pin in (1234567, 7654321, 9999999, 1):
            self.assertIn(cs(pin), range(10))


class TestNetworkAddress(unittest.TestCase):
    def test_separator_equivalence(self):
        # Colon, dash and dot forms must all parse to the same integer (#5).
        colon = NetworkAddress('AA:BB:CC:DD:EE:FF')
        dash = NetworkAddress('AA-BB-CC-DD-EE-FF')
        dot = NetworkAddress('AABB.CCDD.EEFF')
        self.assertEqual(colon.integer, 0xAABBCCDDEEFF)
        self.assertEqual(dash.integer, colon.integer)
        self.assertEqual(dot.integer, colon.integer)

    def test_int_roundtrip(self):
        addr = NetworkAddress(0xAABBCCDDEEFF)
        self.assertEqual(addr.string, 'AA:BB:CC:DD:EE:FF')

    def test_iadd_returns_self(self):
        # '+=' must not clobber the variable to None (#6).
        addr = NetworkAddress('00:00:00:00:00:01')
        addr += 1
        self.assertIsInstance(addr, NetworkAddress)
        self.assertEqual(addr.integer, 2)

    def test_isub_returns_self(self):
        addr = NetworkAddress('00:00:00:00:00:05')
        addr -= 2
        self.assertIsInstance(addr, NetworkAddress)
        self.assertEqual(addr.integer, 3)

    def test_hashable(self):
        # Defining __eq__ requires __hash__ to stay usable in sets/dicts (#15d).
        a = NetworkAddress('00:11:22:33:44:55')
        b = NetworkAddress('00:11:22:33:44:55')
        self.assertEqual(hash(a), hash(b))
        self.assertEqual(len({a, b}), 1)


class TestPinGeneration(unittest.TestCase):
    def setUp(self):
        self.gen = WPSpin()

    def test_pin24_known_vector(self):
        # mac integer 1 -> pin24 = 1 -> checksum(1)=7 -> '00000017'
        self.assertEqual(self.gen.generate('pin24', '00:00:00:00:00:01'), '00000017')

    def test_all_algos_return_str(self):
        mac = '00:90:4C:C1:AC:21'
        for algo in self.gen.algos:
            pin = self.gen.generate(algo, mac)
            self.assertIsInstance(pin, str, f'{algo} returned a non-str: {pin!r}')

    def test_mac_algo_pins_are_valid_8_digit(self):
        mac = '00:90:4C:C1:AC:21'
        for algo, meta in self.gen.algos.items():
            if meta['mode'] != self.gen.ALGO_MAC or meta.get('needs'):
                continue
            pin = self.gen.generate(algo, mac)
            self.assertEqual(len(pin), 8, f'{algo}: {pin!r}')
            self.assertTrue(pin.isdigit(), f'{algo}: {pin!r}')
            # last digit must be the checksum of the first 7
            self.assertEqual(int(pin[7]), self.gen.checksum(int(pin[:7])), f'{algo}: {pin!r}')

    def test_empty_pin(self):
        self.assertEqual(self.gen.generate('pinEmpty', '00:90:4C:C1:AC:21'), '')

    def test_easybox_error_branch_is_str(self):
        # Regression for the int-vs-str inconsistency (#15c).
        import inspect
        src = inspect.getsource(WPSpin.pinEasybox)
        self.assertIn('return "12345670"', src)
        self.assertNotIn('return 12345670', src)


class TestArrisFib(unittest.TestCase):
    def test_base_and_sequence(self):
        fib = oneshot._arris_fib
        self.assertEqual([fib(n) for n in range(7)], [1, 1, 1, 2, 3, 5, 8])


def _calc_pre_multiplied(pin):
    """Independent reimplementation of the reference checksum (calculatePreMultiplied)."""
    pin *= 10
    accum = 0
    accum += 3 * ((pin // 10000000) % 10)
    accum += (pin // 1000000) % 10
    accum += 3 * ((pin // 100000) % 10)
    accum += (pin // 10000) % 10
    accum += 3 * ((pin // 1000) % 10)
    accum += (pin // 100) % 10
    accum += 3 * ((pin // 10) % 10)
    return (10 - accum % 10) % 10


class TestNewAlgorithms(unittest.TestCase):
    def setUp(self):
        self.gen = WPSpin()
        self.mac = '00:11:22:33:44:55'

    def _is_valid_pin(self, pin):
        return (len(pin) == 8 and pin.isdigit()
                and int(pin[7]) == self.gen.checksum(int(pin[:7])))

    def test_checksum_matches_reference(self):
        for p in (0, 1, 1234567, 7654321, 9999999, 8472405):
            self.assertEqual(self.gen.checksum(p), _calc_pre_multiplied(p))

    def test_bit_based_match_reference_substrings(self):
        # OneShot uses mac.integer masks; the reference uses hex substrings.
        # They must agree (differential check), and the final PIN must be valid.
        machex = self.mac.replace(':', '')
        for algo, start in [('pin36', 3), ('pin40', 2), ('pin44', 1), ('pin48', 0)]:
            raw = int(machex[start:], 16) % 10000000
            expected = '{:07d}{}'.format(raw, self.gen.checksum(raw))
            self.assertEqual(self.gen.generate(algo, self.mac), expected, algo)
            self.assertTrue(self._is_valid_pin(self.gen.generate(algo, self.mac)), algo)

    def test_fte_known_vector(self):
        # machex[6:8]='33', ssid[-2:]='AB' -> int('33AB',16)=13227 -> +7=13234
        raw = 13234
        expected = '{:07d}{}'.format(raw, self.gen.checksum(raw))
        self.assertEqual(self.gen.generate('pinFTE', self.mac, ssid='Jazztel_AB'), expected)

    def test_fte_requires_ssid(self):
        self.assertEqual(self.gen.generate('pinFTE', self.mac, ssid=None), '')
        self.assertEqual(self.gen.generate('pinFTE', self.mac, ssid='x'), '')

    def test_belkin_and_orange_are_valid_pins(self):
        for algo in ('pinBelkin', 'pinOrange'):
            pin = self.gen.generate(algo, self.mac, serial='1234567890')
            self.assertTrue(self._is_valid_pin(pin), '{}: {!r}'.format(algo, pin))
            # deterministic
            self.assertEqual(pin, self.gen.generate(algo, self.mac, serial='1234567890'))

    def test_serial_algos_require_serial(self):
        self.assertEqual(self.gen.generate('pinBelkin', self.mac, serial=None), '')
        self.assertEqual(self.gen.generate('pinOrange', self.mac, serial='12'), '')

    def test_suggested_list_gating(self):
        # Without ssid/serial, FTE/Belkin/Orange are skipped; all results valid 8-digit.
        plain = self.gen.getSuggestedList(self.mac)
        self.assertTrue(all(len(p) == 8 and p.isdigit() for p in plain if p))
        # With ssid, FTE appears; with serial, Belkin/Orange appear.
        with_ssid = self.gen.getSuggestedList(self.mac, ssid='Jazztel_AB')
        with_serial = self.gen.getSuggestedList(self.mac, serial='1234567890')
        self.assertGreater(len(with_ssid), len(plain))
        self.assertGreater(len(with_serial), len(plain))


class TestSecurityRegressions(unittest.TestCase):
    def test_pixie_cmd_is_arg_list(self):
        # get_pixie_cmd must return a list so subprocess runs without a shell (#7).
        data = oneshot.PixiewpsData()
        data.pke = data.pkr = data.e_hash1 = data.e_hash2 = data.authkey = data.e_nonce = 'AB'
        cmd = data.get_pixie_cmd()
        self.assertIsInstance(cmd, list)
        self.assertEqual(cmd[0], 'pixiewps')
        cmd_force = data.get_pixie_cmd(full_range=True)
        self.assertIn('--force', cmd_force)

    def test_no_shell_true_in_source(self):
        with open(_ONESHOT) as f:
            self.assertNotIn('shell=True', f.read())


if __name__ == '__main__':
    unittest.main()
