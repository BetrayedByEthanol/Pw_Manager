"""OPEN-01 candidate KEK transcript and deterministic interoperability vectors.

NOT SECURITY-REVIEWED. HKDF is standard, but this particular two-input combiner,
password bootstrapping, slot commitment and the complete protocol remain OPEN.
No private production material belongs in a vector file.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path

PREFIX = b"VAULTY-KEK-v0.4-CANDIDATE\x00"
VALID_MODES = {"two_factor", "recovery_code_only"}


def _frame(value: bytes) -> bytes:
    if len(value) > 65535:
        raise ValueError("Oversized transcript component")
    return len(value).to_bytes(2, "big") + value


def _context(vector: dict) -> bytes:
    # All names are encoded, length-prefixed and purpose-bound. Cryptographic
    # fields use bytes; IDs are textual here solely for an interoperable fixture.
    required = ("vault_id", "target_id", "slot_id", "purpose", "policy")
    values = []
    for name in required:
        value = vector[name]
        if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 255:
            raise ValueError(f"Invalid context field: {name}")
        values.append(_frame(value.encode("utf-8")))
    return b"".join(values)


def _extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.digest(salt, ikm, "sha256")


def _expand(prk: bytes, info: bytes, length: int) -> bytes:
    if not (1 <= length <= 255 * 32):
        raise ValueError("Invalid HKDF length")
    result = b""
    previous = b""
    for block in range(1, (length + 31) // 32 + 1):
        previous = hmac.digest(prk, previous + info + bytes([block]), "sha256")
        result += previous
    return result[:length]


def derive(vector: dict) -> dict:
    mode = vector["mode"]
    if mode not in VALID_MODES:
        raise ValueError(f"Invalid mode {mode}")
    ctx = _context(vector)
    salt = hashlib.sha256(PREFIX + b"SALT\x00" + ctx).digest()
    if mode == "two_factor":
        a, b = bytes.fromhex(vector["first_component_hex"]), bytes.fromhex(vector["prf_component_hex"])
        if len(a) != 32 or len(b) != 32:
            raise ValueError("Each independent KEK input must be 32 bytes")
        ikm = PREFIX + b"TWO-FACTOR\x00" + _frame(a) + _frame(b)
    else:
        if "first_component_hex" in vector or "prf_component_hex" in vector:
            raise ValueError("Code-only slots must not use a fake second factor")
        code = bytes.fromhex(vector["recovery_code_hex"])
        if len(code) != 32:
            raise ValueError("Recovery code must be 32 high-entropy bytes")
        ikm = PREFIX + b"CODE-ONLY\x00" + _frame(code)
    prk = _extract(salt, ikm)
    info = PREFIX + b"EXPAND\x00" + _frame(mode.encode("ascii")) + ctx
    # COMMIT KEY PROPOSAL ONLY: distinct HKDF-Expand domain, not a proof that
    # the surrounding AEAD/key-slot format is committing. The tag MUST cover
    # canonical byte encodings of the AEAD nonce, AAD, and wrapped ciphertext.
    nonce = bytes.fromhex(vector["nonce_hex"])
    aad = bytes.fromhex(vector["aad_hex"])
    ciphertext = bytes.fromhex(vector["ciphertext_hex"])
    if len(nonce) != 24 or not (1 <= len(ciphertext) <= 4096) or len(aad) > 4096:
        raise ValueError("Invalid commitment nonce/AAD/ciphertext lengths")
    commit_info = PREFIX + b"COMMIT-KEY\x00" + _frame(mode.encode("ascii")) + ctx
    commit_key = _expand(prk, commit_info, 32)
    commit_input = PREFIX + b"COMMIT-TAG\x00" + ctx + _frame(nonce) + _frame(aad) + _frame(ciphertext)
    return {"salt_hex": salt.hex(), "prk_hex": prk.hex(),
            "info_hex": info.hex(), "kek_hex": _expand(prk, info, 32).hex(),
            "commit_info_hex": commit_info.hex(), "commit_key_hex": commit_key.hex(),
            "commit_input_hex": commit_input.hex(),
            "commit_tag_hex": hmac.digest(commit_key, commit_input, "sha256").hex()}


def verify(doc: dict) -> None:
    if doc.get("version") != "VAULTY-OPEN-01-CANDIDATE-v1":
        raise ValueError("Invalid vector schema")
    for vector in doc["vectors"]:
        actual = derive(vector)
        for field, value in actual.items():
            if vector.get(field) != value:
                raise ValueError(f"Vector {vector.get('id')}: {field} mismatch")
    if not doc["vectors"]:
        raise ValueError("Missing vectors")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("vector_file", type=Path)
    args = ap.parse_args()
    try:
        doc = json.loads(args.vector_file.read_text(encoding="utf-8"))
        verify(doc)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print("FAIL:", exc)
        return 1
    print(f"PASS: {len(doc['vectors'])} KEK vectors match their frozen outputs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
