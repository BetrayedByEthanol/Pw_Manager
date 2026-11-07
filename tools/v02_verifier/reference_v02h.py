#!/usr/bin/env python3
"""Independently authored V3RV REVIEW-ONLY byte reference (no key operations).

Intentionally uses Python's struct/byte cursor instead of the Rust Reader.
This program neither authenticates envelopes nor derives KEKs; a valid parse
is NOT VERIFIED or READY. No production Argon2/PRF/commitment policy is set.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
from pathlib import Path
import random
import struct

MAGIC = b"V3RV"
HEADER = struct.Struct(">4sHHH")
SLOT_DOMAIN = b"Vaulty/V02-G/REVIEW-ONLY/slot-context/v1"
COMMIT_DOMAIN = b"Vaulty/V02-G/REVIEW-ONLY/commitment-context/v1"
FIXTURE = Path(__file__).with_name("fixtures") / "v02h_wire_vectors.txt"


class Reject(ValueError):
    pass


class Cursor:
    def __init__(self, data: bytes):
        self.data, self.at = data, 0

    def take(self, n: int) -> bytes:
        if n < 0 or n > len(self.data) - self.at:
            raise Reject("truncated/oversize input")
        result = self.data[self.at:self.at + n]
        self.at += n
        return result

    def num(self, n: int = 1) -> int:
        return int.from_bytes(self.take(n), "big")

    def done(self) -> None:
        if self.at != len(self.data):
            raise Reject("trailing bytes")


def integer(n: int, size: int = 1) -> bytes:
    return n.to_bytes(size, "big")


def ident(n: int) -> bytes:
    return bytes((n,)) * 16


def valid(d: dict) -> None:
    root, slot, target, target_id = d["vault"], d["slot"], d["target"], d["target_id"]
    mode, route, entry = d["mode"], d["route"], d["entry"]
    if len(root) != 16 or len(slot) != 16 or not any(root) or not any(slot):
        raise Reject("bad vault/slot identity")
    if len(target_id) != 16 or ((target == 3) != any(target_id)):
        raise Reject("bad target identity")
    if mode not in (1, 2) or target not in (1, 2, 3, 4) or route not in range(1, 10):
        raise Reject("unknown policy selector")
    if (target == 3) != (entry is not None):
        raise Reject("entry policy mismatch")
    if entry is not None:
        em, tier, recovery = entry
        if em not in (1, 2, 3, 4) or tier not in (1, 2) or recovery not in (1, 2, 3, 4):
            raise Reject("entry tags")
    else:
        em, tier, recovery = None, None, None
    if target != 3:
        eligible = route in ((1, 3) if mode == 1 else (2, 4, 5))
    elif tier == 2 and em not in (2, 4):
        eligible = False
    elif route in (3, 4, 5):
        eligible = recovery != 4 and route in ((3, 5) if mode == 1 else (4, 5))
        if tier == 2:
            eligible = eligible and route == 5
    else:
        eligible = route == {1: 6, 2: 7, 3: 8, 4: 9}[em]
        if tier == 2:
            eligible = eligible and route in (7, 9)
    if not eligible:
        raise Reject("ineligible target/route")
    recovery_route = route in (3, 4, 5)
    if d["purpose"] != (2 if recovery_route else 1):
        raise Reject("purpose/route contradiction")
    scope = d["scope"]
    if recovery_route:
        if scope is None:
            raise Reject("recovery missing scope")
        kind, owner = scope
        if kind not in (1, 2, 3) or len(owner) != 16 or not any(owner):
            raise Reject("invalid scope owner")
        if entry is None or recovery == 1:
            if kind != 1 or owner != root:
                raise Reject("wrong vault recovery owner")
        elif recovery == 2:
            if kind != 2:
                raise Reject("group scope required")
        elif recovery == 3:
            if kind != 3 or owner != target_id:
                raise Reject("entry scope mismatch")
        else:
            raise Reject("STRICT_NONE recovery")
    elif scope is not None:
        raise Reject("unexpected normal scope")
    parent = d["ancestor"]
    if parent is not None and (len(parent) != 16 or not any(parent) or parent == slot):
        raise Reject("invalid ancestor")
    pwd_required = route in (1, 2, 4, 8, 9)
    pwd = d["password"]
    if pwd_required != (pwd is not None):
        raise Reject("password recipe mismatch")
    if pwd is not None:
        enc, salt, mem, passes, lanes = pwd
        if (enc != 1 or len(salt) != 16 or not any(salt) or
                not 8192 <= mem <= 262144 or not 2 <= passes <= 8 or
                not 1 <= lanes <= 4 or mem < 8 * lanes):
            raise Reject("unapproved/bad candidate KDF fields")
    p = d["provider"]
    physical = route in (2, 5, 7, 9)
    virtual = route in (1, 6, 8) and not (target == 4 and mode == 1 and route == 1)
    if physical:
        if p["tag"] != 2:
            raise Reject("physical recipe without physical descriptor")
        credential = p["credential"]
        if (not 1 <= len(credential) <= 128 or len(p["rp"]) != 32 or not any(p["rp"])
                or len(p["prf"]) != 32 or not any(p["prf"]) or p["scope"] not in (1, 2)
                or p["up"] is not True or type(p["uv"]) is not bool
                or (tier == 2 and p["scope"] != 2)):
            raise Reject("untrusted physical binding invalid")
    elif virtual:
        if p["tag"] != 1 or len(p["id"]) != 16 or not any(p["id"]) or len(p["hash"]) != 32 or not any(p["hash"]):
            raise Reject("virtual recipe invalid")
    elif p["tag"] != 0:
        raise Reject("unexpected provider")


def encode_descriptor(d: dict) -> bytes:
    valid(d)
    o = bytearray()
    o += d["vault"] + d["slot"] + integer(d["target"]) + d["target_id"]
    o += integer(d["mode"]) + integer(d["route"])
    entry = d["entry"]
    o += b"\x00" if entry is None else b"\x01" + bytes(entry)
    o += integer(d["purpose"])
    scope = d["scope"]
    o += b"\x00" if scope is None else integer(scope[0]) + scope[1]
    parent = d["ancestor"]
    o += b"\x00" if parent is None else b"\x01" + parent
    pwd = d["password"]
    if pwd is None:
        o += b"\x00"
    else:
        enc, salt, mem, passes, lanes = pwd
        o += b"\x01" + integer(enc) + b"\x01" + salt
        o += integer(mem, 4) + integer(passes, 4) + integer(lanes)
    p = d["provider"]
    o += integer(p["tag"])
    if p["tag"] == 1:
        o += p["id"] + p["hash"]
    elif p["tag"] == 2:
        o += integer(len(p["credential"]), 2) + p["credential"]
        o += p["rp"] + p["prf"] + integer(p["scope"]) + integer(p["up"]) + integer(p["uv"])
    if len(o) > 1024:
        raise Reject("oversized descriptor")
    return bytes(o)


def decode_descriptor(data: bytes) -> dict:
    if len(data) > 1024:
        raise Reject("descriptor size")
    r = Cursor(data)
    d = {"vault": r.take(16), "slot": r.take(16), "target": r.num(),
         "target_id": r.take(16), "mode": r.num(), "route": r.num()}
    tag = r.num()
    if tag not in (0, 1):
        raise Reject("entry presence")
    d["entry"] = tuple(r.take(3)) if tag else None
    d["purpose"] = r.num()
    kind = r.num()
    if kind not in (0, 1, 2, 3):
        raise Reject("scope tag")
    d["scope"] = (kind, r.take(16)) if kind else None
    tag = r.num()
    if tag not in (0, 1):
        raise Reject("ancestor presence")
    d["ancestor"] = r.take(16) if tag else None
    tag = r.num()
    if tag not in (0, 1):
        raise Reject("password presence")
    if tag:
        enc, kdf = r.num(), r.num()
        if kdf != 1:
            raise Reject("unknown KDF suite")
        d["password"] = (enc, r.take(16), r.num(4), r.num(4), r.num())
    else:
        d["password"] = None
    p = {"tag": r.num()}
    if p["tag"] == 1:
        p["id"], p["hash"] = r.take(16), r.take(32)
    elif p["tag"] == 2:
        n = r.num(2)
        if n > 128:
            raise Reject("credential size")
        p["credential"] = r.take(n)
        p["rp"], p["prf"] = r.take(32), r.take(32)
        p["scope"] = r.num()
        up, uv = r.num(), r.num()
        if up > 1 or uv > 1:
            raise Reject("noncanonical boolean")
        p["up"], p["uv"] = bool(up), bool(uv)
    elif p["tag"] != 0:
        raise Reject("provider selector")
    d["provider"] = p
    r.done()
    if encode_descriptor(d) != data:
        raise Reject("noncanonical descriptor")
    return d


def encode_frame(d: dict, nonce: bytes, ciphertext: bytes, commitment: bytes) -> bytes:
    desc = encode_descriptor(d)
    if len(nonce) != 24 or not any(nonce) or len(ciphertext) != 48 or len(commitment) != 32:
        raise Reject("bad envelope size/nonce")
    result = HEADER.pack(MAGIC, 1, 1, len(desc)) + desc + nonce + integer(48, 2) + ciphertext + commitment
    if len(result) > 2048:
        raise Reject("oversized frame")
    return result


def decode_frame(data: bytes) -> tuple[dict, bytes, bytes, bytes]:
    if len(data) > 2048:
        raise Reject("oversized input")
    r = Cursor(data)
    magic, version, suite, dlen = HEADER.unpack(r.take(HEADER.size))
    if (magic, version, suite) != (MAGIC, 1, 1) or dlen > 1024:
        raise Reject("unknown/wrong review version")
    d = decode_descriptor(r.take(dlen))
    nonce = r.take(24)
    if r.num(2) != 48:
        raise Reject("invalid key ciphertext length")
    ciphertext, commitment = r.take(48), r.take(32)
    r.done()
    if encode_frame(d, nonce, ciphertext, commitment) != data:
        raise Reject("noncanonical frame")
    return d, nonce, ciphertext, commitment


def contexts(d: dict, nonce: bytes, ciphertext: bytes) -> tuple[bytes, bytes]:
    desc = encode_descriptor(d)
    slot = SLOT_DOMAIN + HEADER.pack(MAGIC, 1, 1, len(desc)) + desc
    comm = COMMIT_DOMAIN + slot + nonce + integer(48, 2) + ciphertext
    return slot, comm


def examples() -> dict[str, tuple[dict, bytes, bytes, bytes]]:
    root, entry, group = ident(1), ident(3), ident(4)
    base = dict(vault=root, slot=ident(2), target=3, target_id=entry,
                mode=1, route=5, entry=(2, 2, 3), purpose=2,
                scope=(3, entry), ancestor=None, password=None,
                provider=dict(tag=2, credential=b"synthetic-credential",
                              rp=bytes([6])*32, prf=bytes([7])*32,
                              scope=2, up=True, uv=True))
    cases = {"isolated_independent": copy.deepcopy(base)}
    d = copy.deepcopy(base)
    d.update(slot=ident(5), entry=(2, 1, 1), route=3, scope=(1, root),
             provider=dict(tag=0))
    cases["standard_weaker_recovery"] = d
    d = copy.deepcopy(base)
    d.update(slot=ident(6), target=1, target_id=bytes(16), mode=1,
             route=1, entry=None, purpose=1, scope=None,
             password=(1, bytes([9])*16, 65536, 3, 1),
             provider=dict(tag=1, id=ident(7), hash=bytes([8])*32))
    cases["virtual_vmk_normal"] = d
    d = copy.deepcopy(base)
    d.update(slot=ident(8), target=3, target_id=ident(9), mode=2,
             route=9, entry=(4, 1, 1), purpose=1, scope=None,
             password=(1, bytes([10])*16, 65536, 3, 1),
             provider=dict(tag=2, credential=b"custom-credential",
                           rp=bytes([6])*32, prf=bytes([11])*32,
                           scope=2, up=True, uv=True))
    cases["custom_physical_normal"] = d
    d = copy.deepcopy(base)
    d.update(slot=ident(10), target_id=ident(11), mode=2, route=5,
             entry=(2, 2, 2), purpose=2, scope=(2, group),
             provider=dict(tag=2, credential=b"group-credential",
                           rp=bytes([6])*32, prf=bytes([12])*32,
                           scope=2, up=True, uv=False))
    cases["isolated_group_recovery"] = d
    return {name: (desc, bytes([i+12])*24, bytes([i+20])*48,
                   bytes([i+30])*32)
            for i, (name, desc) in enumerate(cases.items())}


def fixture_lines() -> list[str]:
    lines = []
    for name, (desc, nonce, ct, tag) in examples().items():
        wire = encode_frame(desc, nonce, ct, tag)
        slot, commit = contexts(desc, nonce, ct)
        lines.append("|".join((name, wire.hex(), hashlib.sha256(slot).hexdigest(),
                               hashlib.sha256(commit).hexdigest())))
    return lines


def verify() -> None:
    expected = FIXTURE.read_text(encoding="ascii").splitlines()
    if expected != fixture_lines():
        raise Reject("frozen V02-H fixtures differ from independently encoded reference")
    for line in expected:
        name, wire_hex, slot_sha, comm_sha = line.split("|")
        raw = bytes.fromhex(wire_hex)
        desc, nonce, ct, tag = decode_frame(raw)
        if encode_frame(desc, nonce, ct, tag) != raw:
            raise Reject(f"roundtrip mismatch: {name}")
        slot, commit = contexts(desc, nonce, ct)
        if hashlib.sha256(slot).hexdigest() != slot_sha or hashlib.sha256(commit).hexdigest() != comm_sha:
            raise Reject(f"context mismatch: {name}")
        for length in range(len(raw)):
            try:
                decode_frame(raw[:length])
            except Reject:
                continue
            raise Reject(f"accepted truncated {name} at offset {length}")
        for suffix in (b"\x00", b"\x00"*3000):
            try:
                decode_frame(raw + suffix)
            except Reject:
                continue
            raise Reject(f"accepted trailing/oversized bytes in {name}")
    rng = random.Random(20261107)
    accepted = 0
    for _ in range(1800):
        name, (d, nonce, ct, tag) = rng.choice(list(examples().items()))
        wire = bytearray(encode_frame(d, nonce, ct, tag))
        position = rng.randrange(len(wire))
        wire[position] ^= 1 << rng.randrange(8)
        try:
            mutated = decode_frame(bytes(wire))
        except Reject:
            continue
        accepted += 1
        # Opaque ciphertext, nonce and a valid altered descriptor may parse;
        # no authenticated/committing verdict may ever be inferred.
        if encode_frame(*mutated) != bytes(wire):
            raise Reject("accepted a noncanonical mutated wire")
    print(f"V02-H: {len(expected)} independently encoded frozen V3RV wire vectors PASS; "
          f"{1800} seeded byte mutations PASS (parse-valid={accepted}, not authenticated)")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    x = p.add_mutually_exclusive_group(required=True)
    x.add_argument("--print-fixtures", action="store_true")
    x.add_argument("--verify", action="store_true")
    args = p.parse_args()
    if args.print_fixtures:
        print("\n".join(fixture_lines()))
    else:
        verify()


if __name__ == "__main__":
    main()
