"""Run: python -m unittest -v test_probes (no third-party packages required)."""
from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

import kek_vectors
from route_graph import PolicyError, analyze

HERE = Path(__file__).parent
POLICY = json.loads((HERE / "fixtures/routes.json").read_text())
VECTORS = json.loads((HERE / "fixtures/kek_vectors.json").read_text())


class RouteGraphTests(unittest.TestCase):
    def policy(self):
        return copy.deepcopy(POLICY)

    def test_code_only_dek_recovery_is_weakest_for_physical_entry(self):
        report = analyze(self.policy(), "sensitive")
        self.assertFalse(report["entry_hardware_mandatory_on_all_paths"])
        self.assertTrue(report["hardware_bypass_routes"])
        self.assertTrue(all(r["factors"] == ["recovery_code"] for r in report["weakest_configured"]))
        self.assertEqual(report["issues"], [])

    def test_subset_minimal_paths_preserve_incomparable_requirements(self):
        report = analyze(self.policy(), "sensitive")
        minimal = report["minimal_configured"]
        self.assertTrue(any(r["factors"] == ["recovery_code"] for r in minimal))
        self.assertTrue(any(r["requires_physical"] for r in minimal))
        self.assertFalse(any(set(r["factors"]) == {"recovery_code", "yubikey"} for r in minimal))

    def test_strict_direct_custom_password_hardware_has_no_recovery(self):
        report = analyze(self.policy(), "strict")
        self.assertTrue(report["entry_hardware_mandatory_on_all_paths"])
        self.assertFalse(report["strict_entry_recovery_bypass_routes"])
        self.assertEqual(report["issues"], [])

    def test_strict_detects_recovered_shared_ancestor(self):
        report = analyze(self.policy(), "strict-bug")
        self.assertIn("STRICT_NONE_HAS_COMPLETE_RECOVERY_PATH", report["issues"])
        self.assertTrue(any("vers-code" in r["recovery_slots"] for r in report["strict_entry_recovery_bypass_routes"]))

    def test_recovering_only_vmk_does_not_recover_strict_entry_dek(self):
        report = analyze(self.policy(), "strict", "cold")
        # Code-only VMK recovery can reveal the outer body, but the DEK still
        # requires custom password plus YubiKey; strict entry recovery stays absent.
        self.assertEqual(report["issues"], [])
        paths_with_code = [r for r in report["configured_routes"] if "recovery_code" in r["factors"]]
        self.assertTrue(paths_with_code)
        self.assertTrue(all(r["outer_recovery"] and not r["entry_recovery"] for r in paths_with_code))
        self.assertTrue(all({"entry_pw", "yubikey"} <= set(r["factors"]) for r in paths_with_code))

    def test_loaded_virtual_uses_no_master_password(self):
        report = analyze(self.policy(), "ordinary", "loaded")
        normal = [r for r in report["configured_routes"] if not r["recovery"]]
        self.assertTrue(normal)
        self.assertTrue(any("master" not in r["factors"] for r in normal))

    def test_cold_requires_vmk_route_and_loaded_does_not(self):
        cold = analyze(self.policy(), "strict", "cold")
        loaded = analyze(self.policy(), "strict", "loaded")
        self.assertTrue(all("VMK" in r["keys"] for r in cold["configured_routes"]))
        self.assertTrue(all("VMK" not in r["keys"] for r in loaded["configured_routes"]))

    def test_revoked_slot_cannot_grant_dek_recovery(self):
        p = self.policy()
        p["keys"]["DEK-sensitive"]["slots"][1]["status"] = "revoked"
        # VERS code path still requires actual hardware, so no physical bypass.
        report = analyze(p, "sensitive")
        self.assertTrue(report["entry_hardware_mandatory_on_all_paths"])
        self.assertFalse(report["hardware_bypass_routes"])

    def test_unavailable_hardware_is_not_silent_virtual_fallback(self):
        p = self.policy()
        p["factors"]["yubikey"]["available"] = False
        report = analyze(p, "strict")
        self.assertNotEqual(report["configured_routes"], [])
        self.assertEqual(report["usable_routes"], [])
        self.assertIn("NO_CURRENTLY_USABLE_COMPLETE_ROUTE", report["issues"])

    def test_cyclic_key_graph_rejected(self):
        p = self.policy()
        p["keys"]["VERS"]["slots"][0]["requires"].append("key:DEK-ordinary")
        with self.assertRaisesRegex(PolicyError, "Cycle"):
            analyze(p, "ordinary")

    def test_unknown_reference_rejected(self):
        p = self.policy()
        p["keys"]["DEK-strict"]["slots"][0]["requires"].append("factor:unregistered")
        with self.assertRaisesRegex(PolicyError, "Unresolved"):
            analyze(p, "strict")

    def test_normal_physical_slot_cannot_be_satisfied_by_virtual(self):
        p = self.policy()
        p["keys"]["DEK-sensitive"]["slots"][0]["requires"] = ["key:VERS", "factor:virtual"]
        report = analyze(p, "sensitive")
        self.assertIn("NORMAL_ROUTE_MISSING_PHYSICAL_PRF", report["issues"])

    def test_entry_dek_must_not_use_vmk_as_ancestor(self):
        p = self.policy()
        p["keys"]["DEK-strict"]["slots"][0]["requires"].append("key:VMK")
        report = analyze(p, "strict")
        self.assertIn("ENTRY_KEK_DEPENDS_ON_VMK", report["issues"])

    def test_code_only_vmk_without_entry_recovery_is_not_code_only_entry(self):
        p = self.policy()
        p["keys"]["DEK-sensitive"]["slots"] = p["keys"]["DEK-sensitive"]["slots"][:1]
        p["keys"]["VERS"]["slots"] = p["keys"]["VERS"]["slots"][:2]
        report = analyze(p, "sensitive", "cold")
        self.assertTrue(all("yubikey" in r["factors"] for r in report["configured_routes"]))
        self.assertTrue(report["entry_hardware_mandatory_on_all_paths"])

    def test_duplicated_slot_id_rejected(self):
        p = self.policy()
        p["keys"]["DEK-strict"]["slots"][0]["id"] = "vmk-code"
        with self.assertRaisesRegex(PolicyError, "Duplicate slot"):
            analyze(p, "strict")

    def test_resident_secret_cannot_be_usable_cold(self):
        p = self.policy()
        p["keys"]["VERS"]["slots"][0]["states"] = ["loaded", "cold"]
        with self.assertRaisesRegex(PolicyError, "Resident slot"):
            analyze(p, "ordinary")

    def test_unknown_entry_fails_closed(self):
        with self.assertRaisesRegex(PolicyError, "Unknown entry"):
            analyze(self.policy(), "does-not-exist")

    def test_bounded_route_expansion_fails_closed(self):
        p = self.policy()
        p["keys"]["many"] = {"slots": []}
        for n in range(5):
            p["keys"][f"layer-{n}"] = {"slots": [
                {"id": f"layer-{n}-s{j}", "kind": "normal", "requires": ["factor:session"]}
                for j in range(9)]}
        p["keys"]["many"]["slots"].append({"id": "many-slot", "kind": "normal", "requires":
                                                 [f"key:layer-{n}" for n in range(5)]})
        p["keys"]["DEK-ordinary"]["slots"][0]["requires"] = ["key:VERS", "key:VIRTUAL_PROVIDER", "key:many"]
        with self.assertRaisesRegex(PolicyError, "exceeds limit"):
            analyze(p, "ordinary")


class KekVectorTests(unittest.TestCase):
    def test_nine_frozen_vectors(self):
        kek_vectors.verify(VECTORS)
        self.assertEqual(len(VECTORS["vectors"]), 9)

    def test_hkdf_rfc5869_case_1(self):
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        prk = kek_vectors._extract(salt, ikm)
        self.assertEqual(prk.hex(), "077709362c2e32df0ddc3f0dc47bba63"
                                     "90b6c73bb50f9c3122ec844ad7c2b3e5")
        self.assertEqual(kek_vectors._expand(prk, info, 42).hex(),
                         "3cb25f25faacd57a90434f64d0362f2a"
                         "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865")

    def test_factor_order_and_binding_not_interchangeable(self):
        v = copy.deepcopy(VECTORS["vectors"][0])
        original = kek_vectors.derive(v)["kek_hex"]
        first, second = v["first_component_hex"], v["prf_component_hex"]
        v["first_component_hex"], v["prf_component_hex"] = second, first
        self.assertNotEqual(original, kek_vectors.derive(v)["kek_hex"])
        v["first_component_hex"], v["prf_component_hex"] = first, second
        for field, other in (("target_id", "entry-other"), ("slot_id", "slot-other"),
                             ("vault_id", "other-vault"), ("purpose", "wrap-vmk"),
                             ("policy", "ENTRY_DEFAULT_PHYSICAL")):
            vv = dict(v, **{field: other})
            self.assertNotEqual(original, kek_vectors.derive(vv)["kek_hex"], field)

    def test_code_only_is_separate_transcript_not_placeholder_factor(self):
        v = copy.deepcopy(VECTORS["vectors"][4])
        v["prf_component_hex"] = "00" * 32
        with self.assertRaisesRegex(ValueError, "fake second factor"):
            kek_vectors.derive(v)

    def test_recovery_target_and_slot_are_separated(self):
        one, two = VECTORS["vectors"][-2:]
        self.assertNotEqual(one["kek_hex"], two["kek_hex"])

    def test_argon2id_sample_matches_if_library_available(self):
        try:
            from argon2.low_level import Type, hash_secret_raw
        except ImportError:
            self.skipTest("argon2-cffi optional for password-input vector generation")
        params = VECTORS["argon2id_test_parameters"]
        for v in VECTORS["vectors"]:
            if "argon2id_password" not in v:
                continue
            derived = hash_secret_raw(v["argon2id_password"].encode("utf-8"),
                                      bytes.fromhex(v["argon2id_salt_hex"]),
                                      time_cost=params["time_cost"], memory_cost=params["memory_kib"],
                                      parallelism=params["parallelism"], hash_len=params["hash_len"],
                                      type=Type.ID, version=params["version"])
            self.assertEqual(derived.hex(), v["first_component_hex"])

    def test_hkdf_independent_library_if_available(self):
        try:
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            from cryptography.hazmat.primitives import hashes
        except ImportError:
            self.skipTest("cryptography optional independent HKDF check")
        for v in VECTORS["vectors"]:
            # Derive using a library implementation independent of our own HKDF.
            context = kek_vectors._context(v)
            prefix = kek_vectors.PREFIX
            if v["mode"] == "two_factor":
                ikm = prefix + b"TWO-FACTOR\0" + kek_vectors._frame(bytes.fromhex(v["first_component_hex"])) + kek_vectors._frame(bytes.fromhex(v["prf_component_hex"]))
            else:
                ikm = prefix + b"CODE-ONLY\0" + kek_vectors._frame(bytes.fromhex(v["recovery_code_hex"]))
            result = HKDF(algorithm=hashes.SHA256(), length=32,
                          salt=bytes.fromhex(v["salt_hex"]),
                          info=prefix + b"EXPAND\0" + kek_vectors._frame(v["mode"].encode()) + context).derive(ikm)
            self.assertEqual(result.hex(), v["kek_hex"])



class AdditionalRouteTests(unittest.TestCase):
    def policy(self):
        return copy.deepcopy(POLICY)

    def test_independent_direct_code_allowed(self):
        from route_graph import analyze
        a = analyze(self.policy(), "independent")
        self.assertEqual(a["issues"], [])
        self.assertEqual(a["weakest_configured"][0]["factors"], ["ind_code"])

    def test_independent_shared_vault_code_denied(self):
        a = self.policy()
        a["keys"]["DEK-independent"]["slots"][1]["requires"] = ["factor:recovery_code"]
        self.assertIn("INDEPENDENT_RECOVERY_SCOPE_BYPASS", analyze(a,"independent")["issues"])

    def test_independent_recovery_via_vers_denied(self):
        a = self.policy()
        a["keys"]["DEK-independent"]["slots"].append(
            {"id":"ind-ancestor","kind":"recovery","requires":["key:VERS"]})
        self.assertIn("INDEPENDENT_RECOVERY_SCOPE_BYPASS", analyze(a,"independent")["issues"])

    def test_independent_no_recovery_denied(self):
        a = self.policy()
        a["keys"]["DEK-independent"]["slots"] = a["keys"]["DEK-independent"]["slots"][:1]
        self.assertIn("INDEPENDENT_MISSING_ENTRY_RECOVERY", analyze(a,"independent")["issues"])

    def test_independent_code_must_have_own_scope(self):
        a = self.policy()
        del a["factors"]["ind_code"]["scope"]
        self.assertIn("INDEPENDENT_RECOVERY_SCOPE_BYPASS", analyze(a,"independent")["issues"])

    def test_independent_code_wrong_entry_rejected(self):
        a = self.policy()
        a["factors"]["ind_code"]["entry_id"] = "ordinary"
        self.assertIn("INDEPENDENT_RECOVERY_SCOPE_BYPASS", analyze(a,"independent")["issues"])
        self.assertIn("ENTRY_CODE_SCOPE_MISMATCH", analyze(a,"independent")["issues"])

    def test_independent_code_cannot_recover_other_entry(self):
        a = self.policy()
        a["keys"]["DEK-ordinary"]["slots"].append(
            {"id":"other-recovery","kind":"recovery","requires":["factor:ind_code"]})
        self.assertIn("ENTRY_CODE_SCOPE_MISMATCH", analyze(a,"ordinary")["issues"])

    def test_blast_radius_shared_vers_is_not_sufficient_alone(self):
        from route_graph import blast_radius
        b = blast_radius(self.policy())
        vers = b["by_material"]["key:VERS"]
        self.assertGreaterEqual(vers["dependent_count"],2)
        self.assertEqual(vers["exposed_count"],0)
        self.assertIn(["yubikey"], vers["remaining_factor_sets"]["sensitive"])
        self.assertNotIn("strict", vers["dependent_entries"])

    def test_blast_radius_entry_code_only_one_entry(self):
        from route_graph import blast_radius
        b=blast_radius(self.policy())
        own=b["by_material"]["factor:ind_code"]
        self.assertEqual(own["dependent_entries"],["independent"])
        self.assertEqual(own["exposed_without_other_factors"],["independent"])
        self.assertNotIn("key:VMK",b["by_material"])

    def test_blast_radius_physical_requires_another_factor_for_strict(self):
        from route_graph import blast_radius
        b=blast_radius(self.policy())
        y=b["by_material"]["factor:yubikey"]
        self.assertIn(["entry_pw"],y["remaining_factor_sets"]["strict"])
        self.assertNotIn("strict",y["exposed_without_other_factors"])

    def test_blast_radius_ignores_alternative_unrelated_slot(self):
        from route_graph import blast_radius
        p=self.policy()
        p["keys"]["VERS"]["slots"]=[s for s in p["keys"]["VERS"]["slots"] if s["id"] != "vers-code"]
        b=blast_radius(p)
        y=b["by_material"]["factor:yubikey"]
        self.assertNotIn(["recovery_code"],y["remaining_factor_sets"]["sensitive"])

    def test_blast_radius_dek_compromise_direct(self):
        from route_graph import blast_radius
        b=blast_radius(self.policy())
        self.assertEqual(b["by_material"]["key:DEK-strict"]["exposed_without_other_factors"],["strict"])

class CommitmentVectorTests(unittest.TestCase):
    def test_commit_key_separated_from_kek(self):
        for v in VECTORS["vectors"]:
            self.assertNotEqual(v["commit_key_hex"], v["kek_hex"])
            self.assertEqual(kek_vectors.derive(v)["commit_tag_hex"], v["commit_tag_hex"])

    def test_commit_transcript_binds_nonce_aad_and_ciphertext(self):
        base = VECTORS["vectors"][0]
        for field in ("nonce_hex","aad_hex","ciphertext_hex","slot_id","target_id"):
            mutated = copy.deepcopy(base)
            if field.endswith("_hex"):
                mutated[field] = "ff" + mutated[field][2:] if mutated[field] else "ff"
            else:
                mutated[field] += "-changed"
            self.assertNotEqual(kek_vectors.derive(base)["commit_tag_hex"],
                                kek_vectors.derive(mutated)["commit_tag_hex"], field)

    def test_commit_key_cross_checked_with_crypto_hkdf(self):
        try:
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            from cryptography.hazmat.primitives import hashes
        except ImportError:
            self.skipTest("cryptography optional")
        for v in VECTORS["vectors"]:
            ctx = kek_vectors._context(v)
            prefix = kek_vectors.PREFIX
            if v["mode"] == "two_factor":
                ikm = (prefix + b"TWO-FACTOR\0" + kek_vectors._frame(bytes.fromhex(v["first_component_hex"]))
                       + kek_vectors._frame(bytes.fromhex(v["prf_component_hex"])))
            else:
                ikm = prefix + b"CODE-ONLY\0" + kek_vectors._frame(bytes.fromhex(v["recovery_code_hex"]))
            expected = HKDF(algorithm=hashes.SHA256(),length=32,
                            salt=bytes.fromhex(v["salt_hex"]),
                            info=bytes.fromhex(v["commit_info_hex"])).derive(ikm)
            self.assertEqual(expected.hex(),v["commit_key_hex"])

class SharedConformanceTests(unittest.TestCase):
    def test_fixture_expected_reports(self):
        from route_graph import analyze
        cases = json.loads((HERE / "fixtures/conformance.json").read_text())
        self.assertEqual(len(cases["cases"]), 14)
        for case in cases["cases"]:
            with self.subTest(case=case["id"]):
                policy = json.loads((HERE / "fixtures" / case["file"]).read_text())
                result = analyze(policy, case["entry"], case["state"])
                self.assertEqual(result["issues"], case["issues"])
                self.assertEqual(result["entry_hardware_mandatory_on_all_paths"],
                                 case["entry_hardware_mandatory_on_all_paths"])
                self.assertEqual(len(result["hardware_bypass_routes"]), case["hardware_bypass_count"])
                self.assertEqual(sum(r["entry_recovery"] for r in result["configured_routes"]),
                                 case["entry_recovery_count"])
                self.assertEqual(sorted(r["factors"] for r in result["weakest_configured"]),
                                 case["weakest_factor_sets"])

    def test_fixture_expected_blast_radius(self):
        from route_graph import blast_radius
        c = json.loads((HERE / "fixtures/conformance.json").read_text())
        b = blast_radius(POLICY)
        self.assertEqual(set(b["by_material"]), set(c["loaded_blast_radius"]))
        for material, value in c["loaded_blast_radius"].items():
            for key in ("dependent_entries", "exposed_without_other_factors", "remaining_factor_sets"):
                self.assertEqual(b["by_material"][material][key], value[key], (material,key))


if __name__ == "__main__":
    unittest.main()
