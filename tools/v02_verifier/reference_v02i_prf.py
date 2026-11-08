#!/usr/bin/env python3
"""V02-I independently written, REVIEW-ONLY public PRF input reference.

Inputs/digests are not authenticator PRF *outputs*, no real FIDO2 operation,
assertion, owner authorization, credential provisioning or security approval.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
from pathlib import Path
import unittest

DOMAIN = b"Vaulty/V02-I/REVIEW-ONLY/prf-input/v1"
PREFIX = b"WebAuthn PRF\x00"
FIXTURE = Path(__file__).with_name("fixtures") / "v02i_prf_vectors.txt"


class Invalid(ValueError):
    pass


def id(n: int) -> bytes:
    return bytes([n]) * 16


def example() -> dict:
    return {
        "vault": id(1), "slot": id(2), "target": 3, "target_id": id(3),
        "purpose": 1, "tier": 2, "scope": 3, "owner": id(3),
        "credential": b"synthetic-main", "rp": bytes([7]) * 32, "assurance": 1,
    }


def encode_context(obj: dict) -> bytes:
    o = obj
    if (len(o["vault"]) != 16 or not any(o["vault"])
        or len(o["slot"]) != 16 or not any(o["slot"])
        or o["target"] not in (1, 2, 3, 4)
        or len(o["target_id"]) != 16
        or o["purpose"] not in (1, 2)
        or o["tier"] not in (0, 1, 2)
        or o["scope"] not in (1, 3)
        or len(o["owner"]) != 16
        or not 1 <= len(o["credential"]) <= 128
        or len(o["rp"]) != 32 or not any(o["rp"])
        or o["assurance"] not in (1, 2)):
        raise Invalid("invalid untrusted PRF input")
    if o["target"] == 3:
        if (not any(o["target_id"]) or o["tier"] == 0 or o["scope"] != 3
            or o["owner"] != o["target_id"]):
            raise Invalid("entry input must be distinct and entry-scoped")
    elif (any(o["target_id"]) or o["tier"] != 0 or o["scope"] != 1
          or o["owner"] != o["vault"]):
        raise Invalid("root input must be vault-scoped")
    return b"".join((
        DOMAIN, (1).to_bytes(2, "big"), o["vault"], o["slot"],
        bytes((o["target"],)), o["target_id"],
        bytes((o["purpose"], o["tier"], o["scope"])), o["owner"],
        len(o["credential"]).to_bytes(2, "big"), o["credential"], o["rp"],
        bytes((o["assurance"],)),
    ))


def ctap_salt(obj: dict) -> bytes:
    # WebAuthn Level 3 PRF eval.first is hashed by the client as:
    # SHA256(UTF8("WebAuthn PRF") || 0x00 || eval.first).
    # Native CTAP must request this hashed salt for proposed UV equivalence.
    return hashlib.sha256(PREFIX + encode_context(obj)).digest()


def examples() -> dict[str, dict]:
    result = {}
    a = example()
    result["isolated-main"] = copy.deepcopy(a)
    x = copy.deepcopy(a); x["target_id"] = id(4); x["owner"] = id(4)
    result["isolated-entry-b"] = x
    x = copy.deepcopy(a); x["slot"] = id(8); x["credential"] = b"synthetic-backup"
    result["isolated-backup"] = x
    x = copy.deepcopy(a); x["purpose"] = 2
    result["isolated-recovery"] = x
    x = copy.deepcopy(a); x["assurance"] = 2
    result["isolated-touch"] = x
    x = copy.deepcopy(a)
    x.update(target=1, target_id=bytes(16), tier=0, scope=1, owner=id(1))
    result["vault-vmk"] = x
    return result


def frozen_lines() -> list[str]:
    return [
        "|".join((label, encode_context(item).hex(), ctap_salt(item).hex()))
        for label, item in examples().items()
    ]


class SecurityLimits(unittest.TestCase):
    def test_reference_vectors_do_not_change_without_explicit_review(self):
        self.assertEqual(FIXTURE.read_text(encoding="ascii").splitlines(), frozen_lines())
        self.assertEqual(len(frozen_lines()), 6)

    def test_distinct_entries_slots_credentials_and_purpose_do_not_share_input(self):
        salts = [ctap_salt(v) for v in examples().values()]
        self.assertEqual(len(set(salts)), 6)
        self.assertEqual(len(salts[0]), 32)

    def test_forged_owner_or_scopes_cannot_form_candidate_input(self):
        for change in ({"scope": 1}, {"owner": id(55)}, {"target_id": bytes(16)},
                       {"credential": b""}, {"credential": b"x"*129},
                       {"rp": bytes(32)}, {"vault": bytes(16)}, {"slot": bytes(16)}):
            x = example()
            x.update(change)
            with self.subTest(change=change):
                with self.assertRaises(Invalid):
                    encode_context(x)

    def test_group_recovery_code_may_be_shared_but_isolated_prf_stays_entry_scoped(self):
        x = example()
        x["purpose"] = 2
        self.assertNotEqual(ctap_salt(x), ctap_salt(example()))
        x["scope"] = 1
        with self.assertRaises(Invalid):
            encode_context(x)

    def test_web_authn_is_uv_branch_and_native_touch_only_is_a_separate_policy(self):
        x = example()
        x["assurance"] = 2
        self.assertNotEqual(ctap_salt(x), ctap_salt(example()))
        # Software flags and valid SHA256 are NOT proof of UP, UV, or PRF.
        self.assertEqual(x["assurance"], 2)


def main() -> None:
    p = argparse.ArgumentParser()
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--print-fixtures", action="store_true")
    g.add_argument("--verify", action="store_true")
    args = p.parse_args()
    if args.print_fixtures:
        print("\n".join(frozen_lines()))
        return
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SecurityLimits)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    print("V02-I: 6 synthetic PRF input/CTAP salt vectors match (NOT hardware-derived)")
if __name__ == "__main__":
    main()
