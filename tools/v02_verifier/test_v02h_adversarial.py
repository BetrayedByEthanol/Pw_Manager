#!/usr/bin/env python3
"""V02-H adversarial, INDEPENDENT REVIEW MODEL for V3RV.

The graph and KDF planner here are **not runtime authorization code**.
They document failure modes and test a suggested fail-closed preflight.
No cryptographic authentication, proof of hardware, or approved KDF budget.
"""
from __future__ import annotations

import copy
import unittest

import reference_v02h as wire


class RejectPolicy(ValueError):
    pass


def graph_preflight(records: list[dict]) -> None:
    """Review-only declared ancestor integrity; **not** proof of factors."""
    if len(records) > 256:
        raise RejectPolicy("too many slots")
    nodes = {}
    for record in records:
        wire.valid(record)
        slot = record["slot"]
        if slot in nodes:
            raise RejectPolicy("duplicate slot ID")
        nodes[slot] = record
    state: dict[bytes, int] = {}

    def visit(slot: bytes) -> None:
        if state.get(slot) == 1:
            raise RejectPolicy("cycle")
        if state.get(slot) == 2:
            return
        state[slot] = 1
        child = nodes[slot]
        parent_id = child["ancestor"]
        if parent_id is not None:
            parent = nodes.get(parent_id)
            if parent is None:
                raise RejectPolicy("dangling ancestor")
            if parent["vault"] != child["vault"]:
                raise RejectPolicy("cross-vault parent")
            # Do not accept an apparently unscoped ancestor for entry recovery
            # across unrelated root IDs without a separate effective-route
            # authorization graph. The candidate does not encode enough
            # ownership to authenticate this relationship.
            if child["target"] == 3 and child["purpose"] == 2:
                if child["scope"] is None:
                    raise RejectPolicy("missing recovery root owner")
            visit(parent_id)
        state[slot] = 2

    for slot in nodes:
        visit(slot)


def select_kdf_work(records: list[dict], selected: list[bytes],
                    max_evals: int, max_kib_passes: int,
                    max_single_kib: int) -> int:
    """Synthetic pre-Argon2 budget; NOT a production-default cost decision.

    The trusted future controller must select the route; an attacker-supplied
    header never enumerates every possible slot or chooses its own budget.
    """
    if max_evals <= 0 or max_kib_passes <= 0 or max_single_kib <= 0:
        raise RejectPolicy("invalid test-only work bounds")
    # For an attacker-controlled request, reject duplicates before hashing.
    if len(selected) > max_evals or len(selected) != len(set(selected)):
        raise RejectPolicy("excessive selected routes")
    nodes = {}
    for d in records:
        wire.valid(d)  # syntactic checks BEFORE any expensive operation
        if d["slot"] in nodes:
            raise RejectPolicy("duplicate slot")
        nodes[d["slot"]] = d
    work = 0
    for slot in selected:
        if slot not in nodes:
            raise RejectPolicy("unrecognized slot")
        params = nodes[slot]["password"]
        if params is None:
            continue
        _, _, memory, passes, _ = params
        if memory > max_single_kib:
            raise RejectPolicy("single KDF exceeds memory allowance")
        work += memory * passes
        if work > max_kib_passes:
            raise RejectPolicy("aggregate pre-auth KDF budget exceeded")
    return work


class AdversarialScenarios(unittest.TestCase):
    def setUp(self):
        self.sample = wire.examples()

    def desc(self, name: str) -> dict:
        return copy.deepcopy(self.sample[name][0])

    def test_independent_wire_golden_vectors_and_one_bit_mutations(self):
        for name, (d, nonce, ct, tag) in self.sample.items():
            raw = wire.encode_frame(d, nonce, ct, tag)
            self.assertEqual(wire.decode_frame(raw), (d, nonce, ct, tag))
            # A parse-valid modified ciphertext is expected: this is an
            # UNAUTHENTICATED WIRE CODEC, NOT A DEK-unlock test.
            changed = bytearray(raw)
            changed[-33] ^= 1
            parsed = wire.decode_frame(bytes(changed))
            self.assertNotEqual(parsed[2], ct)
            self.assertNotEqual(wire.contexts(*parsed[:3])[1],
                                wire.contexts(d, nonce, ct)[1])
            self.assertNotIn("commitment_verified", vars(wire))

    def test_negative_scope_policy_and_sealed_routes(self):
        x = self.desc("isolated_independent")
        x["scope"] = (1, x["vault"])
        with self.assertRaises(wire.Reject):
            wire.valid(x)
        x = self.desc("isolated_independent")
        x["route"] = 3
        x["provider"] = {"tag": 0}
        with self.assertRaises(wire.Reject):
            wire.valid(x)
        x = self.desc("isolated_independent")
        x["entry"] = (2, 2, 4)
        with self.assertRaises(wire.Reject):
            wire.valid(x)
        x = self.desc("virtual_vmk_normal")
        x["mode"] = 2
        with self.assertRaises(wire.Reject):
            wire.valid(x)
        x = self.desc("isolated_group_recovery")
        x["provider"]["scope"] = 1
        with self.assertRaises(wire.Reject):
            wire.valid(x)

    def test_ancestor_graph_rejects_duplicates_cycles_orphans_and_cross_vault(self):
        a = self.desc("virtual_vmk_normal")
        b = self.desc("standard_weaker_recovery")
        c = self.desc("isolated_independent")
        self.assertIsNone(graph_preflight([a, b, c]))
        with self.assertRaisesRegex(RejectPolicy, "duplicate"):
            graph_preflight([a, a])
        b["ancestor"] = bytes([99])*16
        with self.assertRaisesRegex(RejectPolicy, "dangling"):
            graph_preflight([a, b, c])
        b["ancestor"] = a["slot"]
        a["ancestor"] = b["slot"]
        with self.assertRaisesRegex(RejectPolicy, "cycle"):
            graph_preflight([a, b, c])
        a["ancestor"] = None
        a["vault"] = bytes([77])*16
        with self.assertRaisesRegex(RejectPolicy, "cross-vault"):
            graph_preflight([a, b, c])

    def test_code_only_vmk_is_not_an_entry_dek(self):
        vmk = self.desc("virtual_vmk_normal")
        vmk.update(route=3, password=None, provider={"tag": 0},
                   purpose=2, scope=(1, vmk["vault"]))
        wire.valid(vmk)
        entry = self.desc("isolated_independent")
        with self.assertRaises(wire.Reject):
            wire.valid({**entry, "route": 3, "provider": {"tag": 0}})
        # No graph edge is automatically created from root VMK recovery to
        # entry DEK recovery; separate independently provisioned slots needed.
        self.assertIsNone(entry["ancestor"])

    def test_prf_salt_reuse_is_still_unverified_hardware_scope(self):
        a = self.desc("isolated_independent")
        b = copy.deepcopy(a)
        b["slot"] = bytes([91])*16
        b["target_id"] = bytes([92])*16
        b["scope"] = (3, b["target_id"])
        wire.valid(b)
        self.assertEqual(a["provider"]["prf"], b["provider"]["prf"])
        # Legitimate by the current structural parser, but OPEN-15 must
        # approve/enforce per-entry PRF separation before real hardware use.

    def test_hostile_256_slot_work_is_rejected_without_hashing(self):
        one = self.desc("virtual_vmk_normal")
        one["password"] = (1, bytes([9])*16, 262144, 8, 4)
        records = []
        for n in range(256):
            d = copy.deepcopy(one)
            d["slot"] = (n+1).to_bytes(16, "big")
            records.append(d)
        # Illustrative low-work policy, *NOT* a production KDF choice:
        with self.assertRaisesRegex(RejectPolicy, "selected"):
            select_kdf_work(records, [x["slot"] for x in records],
                            max_evals=2, max_kib_passes=131072, max_single_kib=65536)
        with self.assertRaisesRegex(RejectPolicy, "memory"):
            select_kdf_work(records, [records[0]["slot"]],
                            max_evals=2, max_kib_passes=131072, max_single_kib=65536)
        small = copy.deepcopy(records[0])
        small["password"] = (1, bytes([9])*16, 8192, 2, 1)
        self.assertEqual(select_kdf_work([small], [small["slot"]],
                                         max_evals=2, max_kib_passes=131072,
                                         max_single_kib=65536), 16384)
        with self.assertRaisesRegex(RejectPolicy, "selected"):
            select_kdf_work([small], [small["slot"], small["slot"]],
                            max_evals=2, max_kib_passes=131072, max_single_kib=65536)

    def test_version_and_resource_limits_reject_unauthenticated_inputs(self):
        raw = wire.encode_frame(*self.sample["custom_physical_normal"])
        mutants = [
            b"VLY2" + raw[4:],
            raw[:4] + b"\x00\x02" + raw[6:],
            raw[:6] + b"\xff\xff" + raw[8:],
            raw[:8] + b"\xff\xff" + raw[10:],
            raw + b"\x00",
            raw + (b"\x00"*2048),
        ]
        for data in mutants:
            with self.subTest(length=len(data)):
                with self.assertRaises(wire.Reject):
                    wire.decode_frame(data)


if __name__ == "__main__":
    unittest.main()
