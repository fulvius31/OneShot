#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WPS (Wi-Fi Simple Config) cryptography — pure Python, stdlib only.

Implements the key material a WPS External Registrar needs, byte-for-byte
compatible with hostap/wpa_supplicant (src/wps/wps_common.c):

  * Diffie-Hellman 1536-bit MODP Group 5 (RFC 3526)
  * DHKey  = SHA-256(g^ab mod p)            (shared secret zero-padded to 192 B)
  * KDK    = HMAC-SHA256_DHKey(N1 || EnrolleeMAC || N2)
  * AuthKey/KeyWrapKey/EMSK via the WPS KDF
  * PSK1/PSK2 from the device PIN
  * E-Hash/R-Hash commitments
  * AES-128-CBC (vendored) for Encrypted Settings (Phase 2)

Phase 1 (Pixie-Dust) uses only DH + KDF + HMAC-SHA256 (all hashlib/hmac).
AES is needed only for Phase 2 (decrypting the AP's credential / PSK).
"""
import hashlib
import hmac
import os
import struct

# Diffie-Hellman 1536-bit MODP Group 5 (RFC 3526), generator 2.
DH_PRIME = int(
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'
    '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
    'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'
    'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'
    'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'
    '83655D23DCA3AD961C62F356208552BB9ED529077096966D'
    '670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF', 16)
DH_GENERATOR = 2
DH_KEY_LEN = 192   # 1536 bits / 8

NONCE_LEN = 16
AUTHKEY_LEN = 32
KEYWRAPKEY_LEN = 16
EMSK_LEN = 32
PSK_LEN = 16
KDF_LABEL = b'Wi-Fi Easy and Secure Key Derivation'


def _be32(n):
    return struct.pack('>I', n)


def dh_keypair():
    """Return (private_int, public_bytes[192]) for DH group 5."""
    priv = int.from_bytes(os.urandom(DH_KEY_LEN), 'big') % (DH_PRIME - 2) + 1
    pub = pow(DH_GENERATOR, priv, DH_PRIME)
    return priv, pub.to_bytes(DH_KEY_LEN, 'big')


def dh_shared(peer_public_bytes, private_int):
    """Shared secret g^ab mod p, zero-padded big-endian to 192 bytes."""
    peer = int.from_bytes(peer_public_bytes, 'big')
    shared = pow(peer, private_int, DH_PRIME)
    return shared.to_bytes(DH_KEY_LEN, 'big')


def dhkey(shared_bytes):
    """DHKey = SHA-256(g^ab mod p)."""
    return hashlib.sha256(shared_bytes).digest()


def kdk(dhkey_bytes, nonce_e, enrollee_mac, nonce_r):
    """KDK = HMAC-SHA256_DHKey(N1 || EnrolleeMAC || N2)."""
    return hmac.new(dhkey_bytes, nonce_e + enrollee_mac + nonce_r,
                    hashlib.sha256).digest()


def wps_kdf(key, res_len, label=KDF_LABEL):
    """WPS KDF (wps_common.c wps_kdf): iterated HMAC-SHA256.

    block_i = HMAC-SHA256_key( BE32(i) || label || BE32(res_len*8) )
    """
    total_bits = _be32(res_len * 8)
    out = b''
    i = 1
    while len(out) < res_len:
        out += hmac.new(key, _be32(i) + label + total_bits, hashlib.sha256).digest()
        i += 1
    return out[:res_len]


def derive_keys(peer_public_bytes, private_int, nonce_e, enrollee_mac, nonce_r):
    """Return (authkey, keywrapkey, emsk) for the WPS session.

    @peer_public_bytes — the *enrollee's* DH public key (PKE) for a registrar.
    @private_int — our DH private key.
    @nonce_e — Enrollee Nonce (N1, from M1).
    @enrollee_mac — Enrollee MAC (6 bytes, from M1).
    @nonce_r — Registrar Nonce (N2, ours).
    """
    secret = dh_shared(peer_public_bytes, private_int)
    dk = dhkey(secret)
    k = kdk(dk, nonce_e, enrollee_mac, nonce_r)
    keys = wps_kdf(k, AUTHKEY_LEN + KEYWRAPKEY_LEN + EMSK_LEN)
    authkey = keys[:AUTHKEY_LEN]
    keywrapkey = keys[AUTHKEY_LEN:AUTHKEY_LEN + KEYWRAPKEY_LEN]
    emsk = keys[AUTHKEY_LEN + KEYWRAPKEY_LEN:]
    return authkey, keywrapkey, emsk


def derive_psk(authkey, pin):
    """PSK1/PSK2 from the device PIN (ASCII digits). hostap wps_derive_psk."""
    if isinstance(pin, str):
        pin = pin.encode()
    half = (len(pin) + 1) // 2
    psk1 = hmac.new(authkey, pin[:half], hashlib.sha256).digest()[:PSK_LEN]
    psk2 = hmac.new(authkey, pin[half:], hashlib.sha256).digest()[:PSK_LEN]
    return psk1, psk2


def wps_hash(authkey, snonce, psk_half, pke, pkr):
    """E-Hash/R-Hash = HMAC-SHA256_AuthKey(S || PSK || PKE || PKR)."""
    return hmac.new(authkey, snonce + psk_half + pke + pkr, hashlib.sha256).digest()


def authenticator(authkey, prev_msg, cur_msg):
    """Authenticator = HMAC-SHA256_AuthKey(M_prev || M_curr*)[:8]."""
    return hmac.new(authkey, prev_msg + cur_msg, hashlib.sha256).digest()[:8]


def kwa(authkey, key_wrap_data):
    """Key Wrap Authenticator = HMAC-SHA256_AuthKey(data)[:8]."""
    return hmac.new(authkey, key_wrap_data, hashlib.sha256).digest()[:8]
