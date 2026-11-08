"""V02-I review-only hardware/PRF policy boundaries; not security tests.

Checks that an entry's absent backup is never described as READY, and that
hardware UV/UP policy and WebAuthn/native compatibility remain review gated.
"""
from pathlib import Path
import unittest
import review_bundle

ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class V02IReviewPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = read("docs/security/V02I-fido2-prf-isolation-and-hardware-assurance.md")
        self.decisions = read("docs/decisions/register.md")
        self.acceptance = read("docs/roadmap/acceptance-register.md")
        self.spec = read("docs/specification/v0.4.5.md")

    def test_vault_key_registration_does_not_claim_entry_access(self):
        for term in ("does NOT automatically create a per-entry DEK slot",
                     "backup **NOT ENROLLED FOR THIS ENTRY / PENDING**",
                     "one physical route per credential",
                     "two trusted vault keys",
                     "STRICT_NONE",
                     "Option A"):
            self.assertIn(term, self.policy)
        self.assertIn("MUST perform a fresh registered physical FIDO2 operation", self.spec)
        self.assertIn("ISOLATED code-only entry recovery is forbidden", self.spec)

    def test_proposed_salt_and_uv_profile_are_not_approved(self):
        for term in ("OPEN-HW-ASSURANCE", "OPEN-PRF-SALT",
                     "**PROVISIONAL protocol candidate**",
                     "**OPEN owner decision**",
                     "not a final wire version",
                     "only under `#[cfg(test)]`",
                     "UV_REQUIRED", "UP_ONLY_TOUCH",
                     "WebAuthn PRF client request: eval.first = raw_input",
                     'Native CTAP hmac-secret request: salt32 = SHA256("WebAuthn PRF"'):
            self.assertIn(term, self.policy)
        for name in ("OPEN-01", "OPEN-15", "G1", "G2", "G3"):
            self.assertIn("BLOCKED", review_bundle.BLOCKED[name])
        self.assertIn("**BLOCKED — independent security/device review**", self.decisions)

    def test_frozen_prf_reference_is_pinned_to_commit(self):
        for path in (
            "src/v02/v02i_prf_review.rs",
            "tools/v02_verifier/reference_v02i_prf.py",
            "tools/v02_verifier/fixtures/v02i_prf_vectors.txt",
            "tools/v02_verifier/test_v02i_policy_contract.py",
            "docs/security/V02I-fido2-prf-isolation-and-hardware-assurance.md",
        ):
            self.assertIn(path, review_bundle.FILE_ALLOWLIST)
        self.assertIn("OPEN-15", self.policy)
        self.assertIn("No real credential handling.", self.policy)

    def test_hardware_policy_stays_separate_from_owner_recovery_choice(self):
        self.assertIn("OPEN-REC-CONSENT", self.policy)
        self.assertIn("Weaker Standard recovery remains an owner choice",
                      self.policy)
        self.assertIn("P6/HMAC", self.acceptance)
        self.assertIn("OPEN-HW-ASSURANCE", self.decisions)

    def test_no_fake_device_evidence_is_recorded(self):
        self.assertIn("NOT EXECUTED", self.policy)
        self.assertIn("NO HARDWARE TESTS", self.policy)
        self.assertIn("OPEN-15", self.decisions)
        self.assertIn("NO", self.policy)


if __name__ == "__main__":
    unittest.main()
