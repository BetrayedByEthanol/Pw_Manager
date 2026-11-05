"""Vaulty OPEN-18: read-only reference checker for policy access routes.

This is not an authorization engine. Inputs must be the *authenticated* policy snapshot,
not a browser request or an unauthenticated vault header.
"""
from __future__ import annotations

import argparse
import itertools
import json
from dataclasses import dataclass, replace
from pathlib import Path

MAX_ROUTES = 4096
KINDS = {"master_password", "entry_password", "physical_fido2", "virtual_prf",
         "recovery_code", "loaded_session"}
POLICIES = {"ENTRY_DEFAULT_VIRTUAL", "ENTRY_PASSWORD_VIRTUAL",
            "ENTRY_DEFAULT_PHYSICAL", "ENTRY_PASSWORD_PHYSICAL"}
RECOVERY = {"SHARED", "GROUP", "INDEPENDENT", "STRICT_NONE"}
INDEPENDENT = {"master_password", "entry_password", "physical_fido2", "recovery_code"}


class PolicyError(ValueError):
    """A malformed or unsafe-to-analyze policy graph; fail closed."""


@dataclass(frozen=True)
class Route:
    factors: frozenset[str] = frozenset()
    keys: frozenset[str] = frozenset()
    slots: frozenset[str] = frozenset()
    recovery_slots: frozenset[str] = frozenset()
    entry_recovery: bool = False
    outer_recovery: bool = False
    used_compromise: bool = False

    def and_(self, other: "Route") -> "Route":
        return Route(self.factors | other.factors, self.keys | other.keys,
                     self.slots | other.slots, self.recovery_slots | other.recovery_slots,
                     self.entry_recovery or other.entry_recovery,
                     self.outer_recovery or other.outer_recovery,
                     self.used_compromise or other.used_compromise)


def validate(data: dict) -> None:
    if not isinstance(data, dict) or data.get("schema") != "vaulty-route-v1":
        raise PolicyError("Unsupported route-graph schema")
    factors, keys, entries = data.get("factors"), data.get("keys"), data.get("entries")
    if not isinstance(factors, dict) or not isinstance(keys, dict) or not isinstance(entries, list):
        raise PolicyError("factors/keys must be objects; entries must be an array")
    if len(factors) > 256 or len(keys) > 256 or len(entries) > 256:
        raise PolicyError("Graph exceeds bounded limits")
    for fid, f in factors.items():
        if not isinstance(fid, str) or not isinstance(f, dict) or f.get("kind") not in KINDS:
            raise PolicyError(f"Invalid factor {fid!r}")
        if f.get("status", "active") not in {"active", "revoked", "suspended", "disabled"}:
            raise PolicyError(f"Invalid factor status: {fid}")
        if not isinstance(f.get("available", True), bool):
            raise PolicyError(f"Invalid availability: {fid}")
    seen_slots = set()
    for kid, key in keys.items():
        if not isinstance(kid, str) or not isinstance(key, dict) or not isinstance(key.get("slots"), list):
            raise PolicyError(f"Invalid key {kid!r}")
        if len(key["slots"]) > 32:
            raise PolicyError(f"Too many slots for {kid}")
        for slot in key["slots"]:
            if not isinstance(slot, dict) or not isinstance(slot.get("id"), str):
                raise PolicyError(f"Invalid slot for {kid}")
            if slot["id"] in seen_slots:
                raise PolicyError(f"Duplicate slot id {slot['id']}")
            seen_slots.add(slot["id"])
            if slot.get("kind") not in {"normal", "recovery", "resident"}:
                raise PolicyError(f"Invalid slot kind: {slot['id']}")
            if slot.get("status", "active") not in {"active", "revoked", "suspended", "disabled"}:
                raise PolicyError(f"Invalid slot status: {slot['id']}")
            states = slot.get("states", ["loaded", "cold"])
            if not isinstance(states, list) or not states or any(x not in {"loaded", "cold"} for x in states):
                raise PolicyError(f"Invalid slot states: {slot['id']}")
            if slot["kind"] == "resident" and "cold" in states:
                raise PolicyError(f"Resident slot cannot be used before LOADED: {slot['id']}")
            reqs = slot.get("requires")
            if not isinstance(reqs, list) or not reqs or len(reqs) > 16:
                raise PolicyError(f"Invalid requirements for {slot['id']}")
            for ref in reqs:
                if not isinstance(ref, str) or ":" not in ref:
                    raise PolicyError(f"Invalid reference {ref!r}")
                typ, name = ref.split(":", 1)
                if typ == "factor" and name in factors or typ == "key" and name in keys:
                    continue
                raise PolicyError(f"Unresolved requirement {ref} in {slot['id']}")
    entry_ids = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            raise PolicyError("Invalid entry ID")
        if entry["id"] in entry_ids:
            raise PolicyError(f"Duplicate entry {entry['id']}")
        entry_ids.add(entry["id"])
        if entry.get("dek") not in keys or entry.get("policy") not in POLICIES or entry.get("recovery_policy") not in RECOVERY:
            raise PolicyError(f"Invalid entry configuration: {entry['id']}")
        if entry["policy"].startswith("ENTRY_DEFAULT_") and entry.get("first_key") not in keys:
            raise PolicyError(f"Default entry needs an explicit first_key: {entry['id']}")
        if entry["policy"].startswith("ENTRY_PASSWORD_"):
            fid = entry.get("entry_password_factor")
            if fid not in factors or factors[fid]["kind"] != "entry_password":
                raise PolicyError(f"Custom entry needs a typed entry_password_factor: {entry['id']}")
    if "VMK" not in keys:
        raise PolicyError("Cold-open access requires a VMK graph")
    # Recovery codes must declare ownership to qualify as independent.
    # Old policy fixtures without scope remain valid for SHARED and GROUP.
    for fid, f in factors.items():
        if f["kind"] == "recovery_code":
            scope = f.get("scope", "vault")
            if scope not in {"vault", "group", "entry"}:
                raise PolicyError(f"Invalid recovery code scope for {fid}")
            if scope == "entry" and (not isinstance(f.get("entry_id"), str) or
                                     f["entry_id"] not in entry_ids):
                raise PolicyError(f"Unresolved entry-scoped recovery code {fid}")
            if scope == "group" and (not isinstance(f.get("group_id"), str) or
                                     not f["group_id"]):
                raise PolicyError(f"Unresolved group-scoped recovery code {fid}")


def _routes_for_key(data: dict, kid: str, state: str, available_only: bool,
                    cache: dict, stack: tuple[str, ...], compromised: str | None = None) -> list[Route]:
    if compromised == f"key:{kid}":
        # Possession of a key skips its ancestor slot prerequisites, not the
        # remaining requirements to unwrap any other key/DEK.
        return [Route(keys=frozenset({kid}), used_compromise=True)]
    if kid in stack:
        raise PolicyError("Cycle in key prerequisites: " + " -> ".join((*stack, kid)))
    if kid in cache:
        return cache[kid]
    result = set()
    for slot in data["keys"][kid]["slots"]:
        if slot.get("status", "active") != "active" or state not in slot.get("states", ["loaded", "cold"]):
            continue
        selections = [Route(keys=frozenset({kid}), slots=frozenset({slot["id"]}),
                            recovery_slots=frozenset({slot["id"]}) if slot["kind"] == "recovery" else frozenset())]
        for ref in slot["requires"]:
            typ, name = ref.split(":", 1)
            if typ == "factor":
                factor = data["factors"][name]
                if compromised == ref:
                    options = [Route(used_compromise=True)]
                elif (factor.get("status", "active") != "active" or
                        (available_only and not factor.get("available", True))):
                    options = []
                else:
                    options = [Route(factors=frozenset({name}))]
            else:
                options = _routes_for_key(data, name, state, available_only, cache, (*stack, kid), compromised)
            if len(selections) * len(options) > MAX_ROUTES:
                raise PolicyError("Route expansion exceeds limit; no partial assurance result allowed")
            selections = [a.and_(b) for a, b in itertools.product(selections, options)]
            if not selections:
                break
        result.update(selections)
        if len(result) > MAX_ROUTES:
            raise PolicyError("Route expansion exceeds limit; no partial assurance result allowed")
    cache[kid] = sorted(result, key=lambda r: (sorted(r.factors), sorted(r.slots)))
    return cache[kid]


def _serialize(data: dict, route: Route) -> dict:
    kinds = [data["factors"][fid]["kind"] for fid in route.factors]
    independent = sorted(fid for fid in route.factors if data["factors"][fid]["kind"] in INDEPENDENT)
    return {"factors": sorted(route.factors), "factor_kinds": sorted(set(kinds)),
            "keys": sorted(route.keys), "slots": sorted(route.slots),
            "recovery_slots": sorted(route.recovery_slots),
            "recovery": bool(route.recovery_slots or "recovery_code" in kinds),
            "entry_recovery": route.entry_recovery,
            "outer_recovery": route.outer_recovery,
            "requires_physical": "physical_fido2" in kinds,
            "independent_factors": independent, "independent_factor_count": len(independent)}


def _minimal(data: dict, routes: list[Route]) -> list[dict]:
    """Subset-minimal complete factor sets (a partial order, not a security score).

    Identical factor sets can still represent distinct slots/recovery mechanisms;
    preserve their provenance so the UI can disclose every bypass.
    """
    return [_serialize(data, r) for r in routes if not any(
        other.factors < r.factors for other in routes)]


def _weakest(data: dict, routes: list[Route]) -> list[dict]:
    """Operational ordering, NOT an entropy or compromise-probability estimate.

    Hardware-avoiding paths rank weaker; next choose fewer independent factors.
    Return *every* tied route rather than invent a code-vs-password ordering.
    """
    if not routes:
        return []
    summarized = [_serialize(data, r) for r in routes]
    rank = lambda r: (int(r["requires_physical"]), r["independent_factor_count"])
    floor = min(map(rank, summarized))
    return [r for r in summarized if rank(r) == floor]


def analyze(data: dict, entry_id: str, state: str = "loaded") -> dict:
    validate(data)
    if state not in {"loaded", "cold"}:
        raise PolicyError("state must be 'loaded' or 'cold'")
    matching = [e for e in data["entries"] if e["id"] == entry_id]
    if not matching:
        raise PolicyError(f"Unknown entry {entry_id}")
    entry = matching[0]
    def is_recovery(r: Route) -> bool:
        return bool(r.recovery_slots or any(data["factors"][fid]["kind"] == "recovery_code" for fid in r.factors))
    def compute(available_only: bool) -> tuple[list[Route], list[Route]]:
        cache = {}
        dek = [replace(r, entry_recovery=is_recovery(r)) for r in
               _routes_for_key(data, entry["dek"], state, available_only, cache, ())]
        if state == "cold":
            vmk = [replace(r, outer_recovery=is_recovery(r)) for r in
                   _routes_for_key(data, "VMK", state, available_only, cache, ())]
            if len(dek) * len(vmk) > MAX_ROUTES:
                raise PolicyError("Cold-open route expansion exceeds limit")
            full = sorted({a.and_(b) for a, b in itertools.product(dek, vmk)},
                          key=lambda r: (sorted(r.factors), sorted(r.slots)))
        else:
            full = dek
        return dek, full
    dek, full = compute(False)
    _, usable = compute(True)
    issues = []
    if not full:
        issues.append("NO_CONFIGURED_COMPLETE_ROUTE")
    if not usable:
        issues.append("NO_CURRENTLY_USABLE_COMPLETE_ROUTE")
    if any("VMK" in r.keys for r in dek):
        issues.append("ENTRY_KEK_DEPENDS_ON_VMK")
    strict_bypass = [r for r in dek if r.entry_recovery]
    if entry["recovery_policy"] == "STRICT_NONE" and strict_bypass:
        issues.append("STRICT_NONE_HAS_COMPLETE_RECOVERY_PATH")
    # An entry-owned recovery code may never authorize a different entry.
    if any(any(data["factors"][fid]["kind"] == "recovery_code"
                   and data["factors"][fid].get("scope") == "entry"
                   and data["factors"][fid].get("entry_id") != entry_id
                   for fid in r.factors) for r in dek):
        issues.append("ENTRY_CODE_SCOPE_MISMATCH")
    if entry["recovery_policy"] == "INDEPENDENT":
        # A compliant route must go directly through an entry-DEK recovery slot,
        # whose independently provisioned code is scoped to this exact entry.
        # Recovery from VERS/provider ancestors is NOT entry-isolated, even if
        # a second independent recovery slot is also configured.
        independent_paths = []
        for r in strict_bypass:
            owned_codes = {fid for fid in r.factors
                           if data["factors"][fid]["kind"] == "recovery_code"
                           and data["factors"][fid].get("scope") == "entry"
                           and data["factors"][fid].get("entry_id") == entry_id}
            direct_slots = {s["id"] for s in data["keys"][entry["dek"]]["slots"]
                            if s["kind"] == "recovery" and s.get("status", "active") == "active"
                            and state in s.get("states", ["loaded", "cold"])}
            # A DEK recovery slot with inherited recovery/key dependencies is
            # not independently recoverable through the entry-owned code alone.
            direct_ok = any(s["id"] in r.recovery_slots
                            and s["id"] in direct_slots
                            and any(ref == f"factor:{fid}" for ref in s["requires"] for fid in owned_codes)
                            and all(ref.startswith("factor:") for ref in s["requires"])
                            for s in data["keys"][entry["dek"]]["slots"])
            if not owned_codes or not direct_ok or any(
                    data["factors"][fid]["kind"] == "recovery_code" and fid not in owned_codes
                    for fid in r.factors) or any(
                    slotid not in direct_slots for slotid in r.recovery_slots):
                independent_paths.append(r)
        if not strict_bypass:
            issues.append("INDEPENDENT_MISSING_ENTRY_RECOVERY")
        elif independent_paths:
            issues.append("INDEPENDENT_RECOVERY_SCOPE_BYPASS")
    normal = [r for r in dek if not r.entry_recovery]
    if not normal:
        issues.append("NO_NORMAL_ENTRY_ROUTE")
    req_hardware = entry["policy"].endswith("_PHYSICAL")
    req_default = entry["policy"].startswith("ENTRY_DEFAULT_")
    for r in normal:
        kinds = {data["factors"][fid]["kind"] for fid in r.factors}
        if req_default and entry["first_key"] not in r.keys:
            issues.append("NORMAL_ROUTE_MISSING_VERS_ROOT")
        if not req_default and entry["entry_password_factor"] not in r.factors:
            issues.append("NORMAL_ROUTE_MISSING_ENTRY_PASSWORD")
        if req_hardware and "physical_fido2" not in kinds:
            issues.append("NORMAL_ROUTE_MISSING_PHYSICAL_PRF")
        if not req_hardware and "virtual_prf" not in kinds:
            issues.append("NORMAL_ROUTE_MISSING_VIRTUAL_PRF")
    # Physical is mandatory only if *every* DEK route requires it; outer VMK
    # hardware is irrelevant to an already LOADED entry's protection.
    physical_mandatory = bool(dek) and all(_serialize(data, r)["requires_physical"] for r in dek)
    bypass = [r for r in dek if req_hardware and not _serialize(data, r)["requires_physical"]]
    return {"entry": entry_id, "state": state, "configured_routes": [_serialize(data, r) for r in full],
            "usable_routes": [_serialize(data, r) for r in usable],
            "minimal_configured": _minimal(data, full), "minimal_usable": _minimal(data, usable),
            "weakest_configured": _weakest(data, full), "weakest_usable": _weakest(data, usable),
            "entry_hardware_mandatory_on_all_paths": physical_mandatory,
            "hardware_bypass_routes": [_serialize(data, r) for r in bypass],
            "strict_entry_recovery_bypass_routes": [_serialize(data, r) for r in strict_bypass] if entry["recovery_policy"] == "STRICT_NONE" else [],
            "issues": sorted(set(issues))}



def blast_radius(data: dict, state: str = "loaded") -> dict:
    """Configured material-dependency fanout and residual factor sets.

    This is *not* a quantitative compromise probability. `dependent_entries`
    names entries with an active complete route referencing the material.
    `exposed_without_other_factors` means possession of this one material
    leaves an entry-DEK route requiring zero further factors. Compromising a
    VMK is different from compromising an entry DEK: VMK does not unwrap DEKs.
    Results for physical factors describe compromise of that authenticator's
    authorized outputs, NOT compromise of a single domain-scoped PRF output.
    """
    validate(data)
    if state not in {"loaded", "cold"}:
        raise PolicyError("state must be 'loaded' or 'cold'")
    base = {}
    for entry in data["entries"]:
        base[entry["id"]] = _routes_for_key(data, entry["dek"], state, False, {}, ())
    result = {}
    for material in ([f"factor:{k}" for k in sorted(data["factors"])] +
                     [f"key:{k}" for k in sorted(data["keys"])]):
        typ, name = material.split(":", 1)
        impacted, exposed, residual = [], [], {}
        for entry in data["entries"]:
            ident = entry["id"]
            dependent = any(name in (r.factors if typ == "factor" else r.keys)
                            for r in base[ident])
            # Direct DEK possession is exposure even when all wrapping slots
            # are unavailable, because no slot authorization remains necessary.
            if typ == "key" and name == entry["dek"]:
                dependent = True
            if not dependent:
                continue
            impacted.append(ident)
            possible = [r for r in _routes_for_key(data, entry["dek"], state, False, {}, (), material)
                        if r.used_compromise]
            minimum = sorted({tuple(sorted(r.factors)) for r in possible if
                              not any(x.factors < r.factors for x in possible)})
            residual[ident] = [list(factors) for factors in minimum]
            if () in minimum:
                exposed.append(ident)
        if impacted:
            result[material] = {"dependent_entries": sorted(impacted),
                                "dependent_count": len(impacted),
                                "exposed_without_other_factors": sorted(exposed),
                                "exposed_count": len(exposed),
                                "remaining_factor_sets": residual}
    return {"state": state, "entry_count": len(data["entries"]),
            "by_material": result}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("policy", type=Path, help="Authenticated policy snapshot JSON")
    ap.add_argument("--entry", help="Entry to check; omit with --blast-radius")
    ap.add_argument("--blast-radius", action="store_true", help="Show configured material fanout")
    ap.add_argument("--state", choices=["loaded", "cold"], default="loaded")
    args = ap.parse_args()
    try:
        if args.policy.stat().st_size > 1_048_576:
            raise PolicyError("Policy JSON too large")
        if not args.entry and not args.blast_radius:
            raise PolicyError("--entry is required without --blast-radius")
        policy = json.loads(args.policy.read_text(encoding="utf-8"))
        result = blast_radius(policy, args.state) if args.blast_radius else analyze(policy, args.entry, args.state)
    except (OSError, json.JSONDecodeError, PolicyError) as exc:
        print(json.dumps({"error": str(exc)}))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if any(issue not in {"NO_CURRENTLY_USABLE_COMPLETE_ROUTE"} for issue in result.get("issues", [])) else 0


if __name__ == "__main__":
    raise SystemExit(main())
