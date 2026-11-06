#!/usr/bin/env python3
"""Reproducible independent-library reference for UNAPPROVED V02-B candidate.

SHA-256/HKDF/HMAC implemented with Python stdlib; XChaCha20-Poly1305 via
libsodium using ctypes; optional Argon2id via argon2-cffi. This is a
cross-library reference, NOT an independent cryptographic security audit,
a formal key-commitment proof, or an actual physical authenticator test.

Run: python3 tools/v02_verifier/reference_v02c.py --verify
Needs libsodium shared library, and argon2-cffi for Argon2id comparison.
Do not use the deterministic test nonces or inputs for real credentials.
"""
import argparse
import ctypes
import ctypes.util
import hashlib
import hmac
from pathlib import Path
import struct
import uuid

DOMAIN = b"Vaulty/V02-B/REVIEW-ONLY/slot/v1"
WRAP = b"Vaulty/V02-B/review-only/wrap-key"
COMMIT = b"Vaulty/V02-B/review-only/commitment-key"
VAULT = uuid.UUID("11111111-1111-4111-8111-111111111111")
ENTRY = uuid.UUID("22222222-2222-4222-8222-222222222222")
VIRTUAL = uuid.UUID("55555555-5555-4555-8555-555555555555")
SALT = bytes([3]) * 16

# (name, target, vault mode, route, entry mode/tier/recovery,
#  password parameters required, provider, first byte, second byte or None, secret byte)
CASES = (
    ("physical_vmk_normal", 1, 2, 2, None, True, "physical", 21, 34, 99),
    ("virtual_default_entry", 3, 1, 6, (1, 1, 1), False, "virtual", 42, 43, 44),
    ("code_only_password_vmk", 1, 1, 3, None, False, None, 63, None, 82),
    ("preload_seed_password", 4, 1, 1, None, True, None, 4, None, 10),
    ("password_vault_isolated_recovery", 3, 1, 5, (2, 2, 1), False, "physical", 11, 12, 13),
    ("hardware_code_password_admin", 1, 2, 4, None, True, None, 1, 2, 9),
)


def transcript(index, case):
    _, target, vault_mode, route, entry, password, provider, *_ = case
    slot = uuid.UUID(f"33333333-3333-4333-8333-{index + 1:012x}")
    result = bytearray(DOMAIN + struct.pack(">H", 1) + VAULT.bytes + slot.bytes)
    result += bytes([target]) + (ENTRY.bytes if target == 3 else bytes(16))
    result += bytes([vault_mode, route])
    result += (bytes([1, *entry]) if entry is not None else b"\0")
    if password:
        result += b"\1" + SALT + struct.pack(">III", 8192, 2, 1) + b"argon2id-v0x13"
    else:
        result += b"\0"
    if provider == "virtual":
        result += b"\1" + VIRTUAL.bytes + bytes([17]) * 32
    elif provider == "physical":
        cred = b"credential-A"
        result += b"\2" + struct.pack(">H", len(cred)) + cred
        result += bytes([7]) * 32 + bytes([9]) * 32 + bytes([2, 1, 1])
    else:
        result += b"\0"
    return bytes(result)


def hkdf_expand(prk, label):
    return hmac.digest(prk, label + b"\1", "sha256")


def factor_keys(descriptor, first, second):
    ikm = DOMAIN + (b"\1" if second is None else b"\2")
    ikm += first + (second if second is not None else b"")
    prk = hmac.digest(hashlib.sha256(descriptor).digest(), ikm, "sha256")
    return hkdf_expand(prk, WRAP), hkdf_expand(prk, COMMIT)


def xchacha_libsodium(plaintext, aad, nonce, key):
    path = ctypes.util.find_library("sodium")
    if not path:
        raise RuntimeError("libsodium shared library not found (fixture generation only)")
    lib = ctypes.CDLL(path)
    lib.sodium_init()
    func = lib.crypto_aead_xchacha20poly1305_ietf_encrypt
    func.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong),
        ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p,
        ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ]
    func.restype = ctypes.c_int
    output = ctypes.create_string_buffer(len(plaintext) + 16)
    length = ctypes.c_ulonglong()
    def buf(b):
        return ctypes.create_string_buffer(b, len(b))
    p, a, n, k = buf(plaintext), buf(aad), buf(nonce), buf(key)
    rc = func(output, ctypes.byref(length), p, len(plaintext),
              a, len(aad), None, n, k)
    if rc != 0 or length.value != len(plaintext) + 16:
        raise RuntimeError("libsodium XChaCha20-Poly1305 encryption failed")
    return output.raw[:length.value]


def generate():
    for index, case in enumerate(CASES):
        name, *_, first_byte, second_byte, secret_byte = case
        d = transcript(index, case)
        first = bytes([first_byte]) * 32
        second = bytes([second_byte]) * 32 if second_byte is not None else None
        wrap, commit_key = factor_keys(d, first, second)
        nonce = bytes([index + 1]) * 24  # FIXTURE ONLY
        ciphertext = xchacha_libsodium(bytes([secret_byte]) * 32, d, nonce, wrap)
        payload = DOMAIN + b"/mac-v1" + struct.pack(">I", len(d))
        payload += d + nonce + struct.pack(">I", len(ciphertext)) + ciphertext
        tag = hmac.digest(commit_key, payload, "sha256")
        yield " ".join((name, hashlib.sha256(d).hexdigest(),
                        wrap.hex(), commit_key.hex(), ciphertext.hex(), tag.hex()))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true", help="compare frozen GitHub fixture rows")
    args = ap.parse_args()
    actual = list(generate())
    if args.verify:
        fixture = Path(__file__).parent / "fixtures" / "v02c_kats.txt"
        expected = [s for s in fixture.read_text().splitlines()
                    if s and not s.startswith("#")]
        if actual != expected:
            raise SystemExit("V02-C reference vectors do not match committed fixture")
        print(f"V02-C: {len(actual)} Python/libsodium reference vectors match")
        try:
            from argon2.low_level import Type, hash_secret_raw
        except ImportError:
            print("Argon2id reference skipped: install argon2-cffi for independent-library check")
        else:
            x = hash_secret_raw(b"synthetic password", SALT, 2, 8192, 1, 32,
                                Type.ID, version=19).hex()
            expected_argon = "cb6636e19e33f61e6317f98d09e11a5f3ca42487b2db1c39f6e63a730cada520"
            if x != expected_argon:
                raise SystemExit("Argon2id reference mismatch")
            print("V02-C: Argon2id reference component matches")
    else:
        print("\n".join(actual))


if __name__ == "__main__":
    main()
