"""Negative tests for the SEC-00 fail-closed infrastructure contract."""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import validate_contract as v


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lock, cls.policy = v.load_contract()

    def errors(self, lock=None, policy=None):
        return v.validate(v.ROOT, lock or self.lock, policy or self.policy)

    def test_preparation_contract_valid(self):
        self.assertEqual([], self.errors())

    def test_not_release_approved(self):
        policy = copy.deepcopy(self.policy)
        policy["production_crypto_approved"] = True
        self.assertTrue(any("SEC00_UNSAFE_POLICY" in e for e in self.errors(policy=policy)))

    def test_cannot_enable_undeployed_pr_gate(self):
        policy = copy.deepcopy(self.policy)
        policy["execution"]["pr"]["enabled"] = True
        self.assertTrue(any("SEC00_PREMATURE_GATE" in e for e in self.errors(policy=policy)))

    def test_no_partial_unapproved_tool_pin(self):
        lock = copy.deepcopy(self.lock)
        lock["tools"]["gitleaks"]["version"] = "1.2.3"
        self.assertTrue(any("SEC00_TOOL_PENDING_PIN" in e for e in self.errors(lock=lock)))

    def test_no_untrusted_image_tag(self):
        lock = copy.deepcopy(self.lock)
        lock["images"]["static"]["reference"] = "registry.local/vaulty/security-static:latest"
        self.assertTrue(any("SEC00_IMAGE_UNPUBLISHED" in e for e in self.errors(lock=lock)))

    def test_published_image_requires_matching_digest(self):
        lock = copy.deepcopy(self.lock)
        lock["images"]["static"].update(
            status="published",
            digest="sha256:" + "a" * 64,
            reference="registry.local/vaulty/security-static@sha256:" + "b" * 64,
        )
        self.assertTrue(any("SEC00_IMAGE_MISMATCH" in e for e in self.errors(lock=lock)))

    def test_pr_cannot_receive_signing_keys(self):
        policy = copy.deepcopy(self.policy)
        policy["trust_boundaries"]["pr"]["signing_keys"] = True
        self.assertTrue(any("SEC00_SIGNING_BOUNDARY" in e for e in self.errors(policy=policy)))

    def test_release_requires_explicit_future_approval(self):
        self.assertTrue(v.validate(v.ROOT, self.lock, self.policy, require_approved=True))

    def test_all_rust_manifests_present(self):
        lock = copy.deepcopy(self.lock)
        lock["rust_manifests"].pop()
        self.assertTrue(any("SEC00_MANIFESTS" in e for e in self.errors(lock=lock)))

    def test_all_five_rust_packages_have_committed_lockfiles(self):
        for manifest in self.lock["rust_manifests"]:
            lock_path = (v.ROOT / manifest).parent / "Cargo.lock"
            with self.subTest(manifest=manifest):
                self.assertTrue(lock_path.is_file(), f"missing {lock_path}")


if __name__ == "__main__":
    unittest.main()
