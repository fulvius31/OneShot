#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pure-Python nl80211 (generic netlink) Wi-Fi scanner.

Replaces shelling out to the ``iw`` binary. It talks nl80211 over generic
netlink straight to the kernel: resolve the family, (optionally) trigger an
active scan, wait for completion on the "scan" multicast group, then dump the
BSS table and parse each BSS's information elements — including the WPS IE
(version, AP Setup Locked, and device/model strings).

Each network is returned as a dict in the exact shape OneShot's WiFiScanner
expects, so the rest of the program is unchanged:

    {'BSSID', 'ESSID', 'Level', 'Security type',
     'WPS', 'WPS locked', 'Model', 'Model number', 'Device name'}

Requires root (CAP_NET_ADMIN) to trigger a scan; dumping cached results may
work unprivileged. On any setup failure it raises Nl80211Error so the caller
can fall back to ``iw``.

Can also be run standalone for debugging:  python3 nl80211_scan.py wlan0
"""
import os
import socket
import struct

# --- netlink core (linux/netlink.h) ---
NETLINK_GENERIC = 16

NLMSG_ERROR = 0x2
NLMSG_DONE = 0x3

NLM_F_REQUEST = 0x01
NLM_F_ACK = 0x04
NLM_F_ROOT = 0x100
NLM_F_MATCH = 0x200
NLM_F_DUMP = NLM_F_ROOT | NLM_F_MATCH

SOL_NETLINK = 270
NETLINK_ADD_MEMBERSHIP = 1

# Attribute type flags (linux/netlink.h)
NLA_F_NESTED = 0x8000
NLA_F_NET_BYTEORDER = 0x4000
NLA_TYPE_MASK = ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER) & 0xFFFF

# --- generic netlink controller (linux/genetlink.h) ---
GENL_ID_CTRL = 0x10
CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2
CTRL_ATTR_MCAST_GROUPS = 7
CTRL_ATTR_MCAST_GRP_NAME = 1
CTRL_ATTR_MCAST_GRP_ID = 2

# --- nl80211 (linux/nl80211.h) ---
NL80211_CMD_GET_SCAN = 32
NL80211_CMD_TRIGGER_SCAN = 33
NL80211_CMD_NEW_SCAN_RESULTS = 34
NL80211_CMD_SCAN_ABORTED = 35

NL80211_ATTR_IFINDEX = 3
NL80211_ATTR_SCAN_SSIDS = 45
NL80211_ATTR_BSS = 47

NL80211_BSS_BSSID = 1
NL80211_BSS_FREQUENCY = 2
NL80211_BSS_CAPABILITY = 5
NL80211_BSS_INFORMATION_ELEMENTS = 6
NL80211_BSS_SIGNAL_MBM = 7
NL80211_BSS_BEACON_IES = 11

# --- 802.11 information elements ---
IE_SSID = 0
IE_RSN = 48
IE_VENDOR = 221
WFA_OUI = b'\x00\x50\xf2'   # WPA = OUI+type 1, WPS = OUI+type 4
CAP_PRIVACY = 0x10

# --- WPS IE attributes (big-endian TLV) ---
WPS_ATTR_VERSION = 0x104A
WPS_ATTR_AP_SETUP_LOCKED = 0x1057
WPS_ATTR_DEVICE_NAME = 0x1011
WPS_ATTR_MANUFACTURER = 0x1021
WPS_ATTR_MODEL_NAME = 0x1023
WPS_ATTR_MODEL_NUMBER = 0x1024


class Nl80211Error(Exception):
    pass


def _align4(n):
    return (n + 3) & ~3


def _attr(attr_type, payload):
    """Build a netlink attribute (nlattr header + payload + padding)."""
    nla_len = len(payload) + 4
    out = struct.pack('=HH', nla_len, attr_type) + payload
    return out + b'\x00' * (_align4(nla_len) - nla_len)


def _parse_attrs(buf):
    """Parse a buffer of netlink attributes into {type: value_bytes}."""
    attrs = {}
    i = 0
    while i + 4 <= len(buf):
        nla_len, nla_type = struct.unpack_from('=HH', buf, i)
        if nla_len < 4:
            break
        attrs[nla_type & NLA_TYPE_MASK] = buf[i + 4:i + nla_len]
        i += _align4(nla_len)
    return attrs


def _genl_msg(family, cmd, seq, flags, attrs=b'', version=1):
    """Build a generic-netlink message (nlmsghdr + genlmsghdr + attrs)."""
    payload = struct.pack('=BBH', cmd, version, 0) + attrs
    total = 16 + len(payload)
    hdr = struct.pack('=IHHII', total, family, flags, seq, 0)
    return hdr + payload


def _parse_wps(buf, net):
    """Parse a WPS IE body (after OUI+type) into the network dict."""
    net['WPS'] = net.get('WPS') or '1.0'   # presence; refined by the Version attr
    i = 0
    while i + 4 <= len(buf):
        atype, alen = struct.unpack_from('>HH', buf, i)
        val = buf[i + 4:i + 4 + alen]
        if len(val) < alen:
            break
        i += 4 + alen
        if atype == WPS_ATTR_VERSION and val:
            net['WPS'] = '{}.{}'.format(val[0] >> 4, val[0] & 0xF)
        elif atype == WPS_ATTR_AP_SETUP_LOCKED and val:
            net['WPS locked'] = val[0] != 0
        elif atype == WPS_ATTR_DEVICE_NAME:
            net['Device name'] = val.decode('utf-8', errors='replace')
        elif atype == WPS_ATTR_MODEL_NAME:
            net['Model'] = val.decode('utf-8', errors='replace')
        elif atype == WPS_ATTR_MODEL_NUMBER:
            net['Model number'] = val.decode('utf-8', errors='replace')


def _parse_ies(ies, net, capability):
    """Parse 802.11 information elements into the network dict."""
    has_rsn = False
    has_wpa = False
    i = 0
    while i + 2 <= len(ies):
        eid = ies[i]
        elen = ies[i + 1]
        body = ies[i + 2:i + 2 + elen]
        if len(body) < elen:
            break
        i += 2 + elen
        if eid == IE_SSID:
            net['ESSID'] = body.decode('utf-8', errors='replace')
        elif eid == IE_RSN:
            has_rsn = True
        elif eid == IE_VENDOR and len(body) >= 4:
            oui, otype = body[:3], body[3]
            if oui == WFA_OUI and otype == 1:
                has_wpa = True
            elif oui == WFA_OUI and otype == 4:
                _parse_wps(body[4:], net)

    if has_rsn and has_wpa:
        net['Security type'] = 'WPA/WPA2'
    elif has_rsn:
        net['Security type'] = 'WPA2'
    elif has_wpa:
        net['Security type'] = 'WPA'
    elif capability & CAP_PRIVACY:
        net['Security type'] = 'WEP'
    else:
        net['Security type'] = 'Open'


def _new_network():
    return {
        'Security type': 'Unknown',
        'WPS': False,
        'WPS locked': False,
        'Model': '',
        'Model number': '',
        'Device name': '',
        'Level': 0,
    }


def _parse_bss(bss_attrs):
    """Turn a parsed NL80211_ATTR_BSS attribute table into a network dict."""
    bssid_raw = bss_attrs.get(NL80211_BSS_BSSID)
    if not bssid_raw or len(bssid_raw) < 6:
        return None
    net = _new_network()
    net['BSSID'] = ':'.join('%02X' % b for b in bssid_raw[:6])

    sig = bss_attrs.get(NL80211_BSS_SIGNAL_MBM)
    if sig and len(sig) >= 4:
        net['Level'] = struct.unpack('=i', sig[:4])[0] // 100

    capability = 0
    cap_raw = bss_attrs.get(NL80211_BSS_CAPABILITY)
    if cap_raw and len(cap_raw) >= 2:
        capability = struct.unpack('=H', cap_raw[:2])[0]

    ies = (bss_attrs.get(NL80211_BSS_INFORMATION_ELEMENTS)
           or bss_attrs.get(NL80211_BSS_BEACON_IES) or b'')
    _parse_ies(ies, net, capability)
    return net


def _send(sock, msg):
    sock.sendto(msg, (0, 0))


def _read_until_done(sock):
    """Yield (msg_type, payload) for each message until NLMSG_DONE/ERROR.

    Spans multiple recv() calls (a DUMP can be split across datagrams).
    Raises Nl80211Error on a non-zero NLMSG_ERROR.
    """
    while True:
        try:
            data = sock.recv(65536)
        except socket.timeout:
            raise Nl80211Error('netlink receive timed out')
        i = 0
        while i + 16 <= len(data):
            mlen, mtype = struct.unpack_from('=IH', data, i)[:2]
            if mlen < 16:
                return
            payload = data[i + 16:i + mlen]
            if mtype == NLMSG_DONE:
                return
            if mtype == NLMSG_ERROR:
                err = struct.unpack_from('=i', payload, 0)[0]
                if err != 0:
                    raise Nl80211Error('netlink error {} ({})'.format(err, os.strerror(-err)))
                return   # err == 0 -> ACK
            yield mtype, payload
            i += _align4(mlen)


def _resolve_family(sock, name):
    """Return (family_id, {mcast_group_name: id}) for a genl family."""
    msg = _genl_msg(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 1, NLM_F_REQUEST | NLM_F_ACK,
                    _attr(CTRL_ATTR_FAMILY_NAME, name.encode() + b'\x00'))
    _send(sock, msg)
    family_id = None
    mcast = {}
    for mtype, payload in _read_until_done(sock):
        if mtype != GENL_ID_CTRL:
            continue
        ctrl = _parse_attrs(payload[4:])   # skip genlmsghdr
        if CTRL_ATTR_FAMILY_ID in ctrl:
            family_id = struct.unpack('=H', ctrl[CTRL_ATTR_FAMILY_ID][:2])[0]
        if CTRL_ATTR_MCAST_GROUPS in ctrl:
            for _, grp in _parse_attrs(ctrl[CTRL_ATTR_MCAST_GROUPS]).items():
                g = _parse_attrs(grp)
                gname = g.get(CTRL_ATTR_MCAST_GRP_NAME, b'').rstrip(b'\x00').decode('utf-8', 'replace')
                gid = g.get(CTRL_ATTR_MCAST_GRP_ID)
                if gid:
                    mcast[gname] = struct.unpack('=I', gid[:4])[0]
    if family_id is None:
        raise Nl80211Error('nl80211 family not found (no Wi-Fi/cfg80211 support?)')
    return family_id, mcast


def _trigger_scan(sock, family_id, ifindex):
    """Trigger an active scan.

    Returns True if a scan-completion notification was already observed while
    reading the trigger ACK (so the caller can skip the explicit wait instead
    of blocking until timeout for a notification it already consumed).
    """
    attrs = _attr(NL80211_ATTR_IFINDEX, struct.pack('=I', ifindex))
    attrs += _attr(NL80211_ATTR_SCAN_SSIDS, _attr(1, b''))   # one wildcard SSID -> active scan
    _send(sock, _genl_msg(family_id, NL80211_CMD_TRIGGER_SCAN, 2,
                          NLM_F_REQUEST | NLM_F_ACK, attrs))
    results_ready = False
    for mtype, payload in _read_until_done(sock):
        if (mtype == family_id and payload
                and payload[0] in (NL80211_CMD_NEW_SCAN_RESULTS, NL80211_CMD_SCAN_ABORTED)):
            results_ready = True
    return results_ready


def _wait_for_results(sock, family_id, timeout):
    """Wait for a scan-completion notification. Returns True if results ready."""
    sock.settimeout(timeout)
    try:
        while True:
            data = sock.recv(65536)
            i = 0
            while i + 16 <= len(data):
                mlen, mtype = struct.unpack_from('=IH', data, i)[:2]
                if mlen < 16:
                    break
                payload = data[i + 16:i + mlen]
                if mtype == family_id and payload:
                    cmd = payload[0]
                    if cmd in (NL80211_CMD_NEW_SCAN_RESULTS, NL80211_CMD_SCAN_ABORTED):
                        return cmd == NL80211_CMD_NEW_SCAN_RESULTS
                i += _align4(mlen)
    except socket.timeout:
        return False
    finally:
        sock.settimeout(None)


def _get_scan(sock, family_id, ifindex):
    attrs = _attr(NL80211_ATTR_IFINDEX, struct.pack('=I', ifindex))
    _send(sock, _genl_msg(family_id, NL80211_CMD_GET_SCAN, 3,
                          NLM_F_REQUEST | NLM_F_DUMP, attrs))
    networks = []
    for mtype, payload in _read_until_done(sock):
        if mtype != family_id:
            continue
        attrs_d = _parse_attrs(payload[4:])   # skip genlmsghdr
        bss = attrs_d.get(NL80211_ATTR_BSS)
        if not bss:
            continue
        net = _parse_bss(_parse_attrs(bss))
        if net:
            networks.append(net)
    return networks


def scan(interface, trigger=True, timeout=10):
    """Scan ``interface`` via nl80211 and return a list of network dicts.

    Raises Nl80211Error on any setup failure (unknown interface, no nl80211,
    socket errors) so the caller can fall back to ``iw``.
    """
    try:
        ifindex = socket.if_nametoindex(interface)
    except OSError:
        raise Nl80211Error('interface {!r} not found'.format(interface))

    try:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    except OSError as e:
        raise Nl80211Error('cannot open netlink socket: {}'.format(e))

    try:
        sock.bind((0, 0))
        sock.settimeout(timeout)   # bound every blocking recv so we never hang forever
        family_id, mcast = _resolve_family(sock, 'nl80211')
        if trigger:
            scan_grp = mcast.get('scan')
            if scan_grp is not None:
                try:
                    sock.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, scan_grp)
                except OSError:
                    pass
            results_ready = False
            try:
                results_ready = _trigger_scan(sock, family_id, ifindex)
            except Nl80211Error:
                pass   # e.g. EBUSY: a scan is already running; wait/dump anyway
            if not results_ready:
                _wait_for_results(sock, family_id, timeout)
            sock.settimeout(timeout)   # _wait_for_results resets it to None in its finally
        return _get_scan(sock, family_id, ifindex)
    except OSError as e:
        raise Nl80211Error('netlink I/O error: {}'.format(e))
    finally:
        sock.close()


if __name__ == '__main__':
    import sys
    iface = sys.argv[1] if len(sys.argv) > 1 else 'wlan0'
    try:
        for n in scan(iface):
            print(n)
    except Nl80211Error as exc:
        sys.stderr.write('nl80211 scan failed: {}\n'.format(exc))
        sys.exit(1)
