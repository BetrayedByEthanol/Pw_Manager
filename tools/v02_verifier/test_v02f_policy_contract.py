"""V02-F documentation/approval-boundary checks ONLY.

These tests detect accidental policy-state drift; they do NOT establish any
cryptographic property, runtime authorization or owner consent.
"""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "v02_verifier"))
import review_bundle  # noqa: E402


def document(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def markdown_row(content: str, first_field: str) -> str:
    prefix = f"| {first_field} |"
    matching = [line for line in content.splitlines() if line.startswith(prefix)]
    if len(matching) != 1:
        raise AssertionError(f"expected one row with key {first_field}; got {len(matching)}")
    return matching[0]


class V02FPolicyBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.spec = document("docs/specification/v0.4.5.md")
        self.decisions = document("docs/decisions/register.md")
        self.packet = document("docs/security/V02F-recovery-assurance-and-cryptographic-policy.md")

    def test_existing_approved_recovery_invariants_remain_explicit(self):
        for invariant in (
            "Code-only administrative recovery is permitted **only for password-only vaults**",
            "ISOLATED code-only entry recovery is forbidden",
            "STRICT_NONE` NEVER authorizes a software-only normal access path",
            "Creating **new or replacement code-dependent** recovery envelopes",
            "Recovery routes are **not implicit**",
            "MUST provision **both** separate administrative two-factor routes",
        ):
            self.assertIn(invariant, self.spec, invariant)
        self.assertIn("DEC-REC-A", self.decisions)
        self.assertIn("DEC-REC-S2", self.decisions)

    def test_owner_and_external_review_gates_remain_open(self):
        for key in ("OPEN-REC-CONSENT", "OPEN-KDF-PROFILE", "OPEN-PASSWORD-ENC"):
            row = markdown_row(self.decisions, key)
            self.assertIn("**OPEN", row, key)
        for key in ("**OPEN-01**", "**OPEN-15**"):
            row = markdown_row(self.decisions, key)
            self.assertIn("**BLOCKED", row, key)
        for key in ("OPEN-REC-CONSENT", "OPEN-KDF-PROFILE", "OPEN-PASSWORD-ENC"):
            self.assertIn("`"+key+"`", self.packet)

    def test_policy_packet_is_clear_about_unapproved_changes(self):
        for constraint in (
            "NO NEW OWNER APPROVAL OR PRODUCTION CRYPTOGRAPHY",
            "NO new owner approval",
            "unpreselected per-entry",
            "no silently chosen STRICT_NONE",
            "NFC",
            "UTF-8",
            "benchmark",
            "64 MiB",
            "not a protocol or trusted JSON parser",
            "OPEN-15",
            "OPEN-01",
            "V02-G",
            "V02-H",
            "VLY2",
            "F-1",
        ):
            self.assertIn(constraint.lower(), self.packet.lower(), constraint)

    def test_manifest_includes_policy_packet_and_no_release_approval(self):
        self.assertIn("docs/security/V02F-recovery-assurance-and-cryptographic-policy.md",
                      review_bundle.FILE_ALLOWLIST)
        self.assertIn("tools/v02_verifier/test_v02f_policy_contract.py",
                      review_bundle.FILE_ALLOWLIST)
        for key in ("OPEN-01", "OPEN-15", "G1", "G2", "G3"):
            self.assertIn("BLOCKED", review_bundle.BLOCKED[key])


if __name__ == "__main__":
    unittest.main()
