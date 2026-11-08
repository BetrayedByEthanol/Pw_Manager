"""V02-H round-two findings: review/approval-boundary documentation tests.

These are static ledger checks only. They DO NOT validate cryptographic
commitment, consent, KDF resource enforcement, real FIDO2, or hardware.
"""
import unittest
from pathlib import Path

import review_bundle


ROOT = Path(__file__).resolve().parents[2]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class RoundTwoDispositionTests(unittest.TestCase):
    def setUp(self):
        self.disposition = read("docs/security/V02H-round-two-review-disposition.md")
        self.acceptance = read("docs/roadmap/acceptance-register.md")
        self.decisions = read("docs/decisions/register.md")

    def test_all_nine_findings_and_w1_are_individually_registered(self):
        for n in range(1, 10):
            ident = f"F-{n}"
            matches = [line for line in self.disposition.splitlines()
                       if line.startswith("| **" + ident + " —")]
            self.assertEqual(len(matches), 1, f"{ident} must have exactly one disposition row")
            self.assertIn(f"| {ident} /", self.acceptance)
        self.assertIn("| W1 / SEC-17", self.acceptance)
        self.assertIn("SEC-14", self.acceptance)
        self.assertIn("SEC-15", self.acceptance)
        self.assertIn("SEC-16", self.acceptance)

    def test_owner_consents_to_weaker_standard_recovery_before_provision(self):
        for term in (
            "Q1 — F-1 remains an owner-controlled",
            "explicit informed",
            "OPEN-REC-CONSENT",
            "no implicit weak slot",
            "no silent",
            "ISOLATED",
            "Code-only VMK recovery alone does not unlock",
        ):
            self.assertIn(term, self.disposition)
        self.assertIn("| F-1 / SEC-14 | **OPEN — OWNER POLICY CHOICE**", self.acceptance)
        self.assertIn("**OPEN — owner decision required before provisioning**",
                      self.decisions)

    def test_p6_hmac_and_v3rv_are_not_cryptographic_approval(self):
        for term in (
            "Q2 — Neither V02-B HMAC/P6 nor V3RV",
            "not a proof of multi-key commitment",
            "no authenticated seal/open",
            "OPEN-01/OPEN-15 and G1–G3 remain **BLOCKED**",
        ):
            self.assertIn(term, self.disposition)
        self.assertIn("| F-6 / SEC-05 | **PARTIAL — REVIEW-ONLY WIRE**",
                      self.acceptance)
        self.assertIn("**BLOCKED — independent cryptographic review**", self.decisions)
        self.assertIn("**BLOCKED — independent security/device review**", self.decisions)

    def test_all_review_inputs_pinned_and_gates_still_blocked(self):
        self.assertIn("9d854a6d43c6cb486afc0dba25bb0a89f3197480",
                      self.disposition)
        self.assertIn("docs/security/V02H-round-two-review-disposition.md",
                      review_bundle.FILE_ALLOWLIST)
        self.assertIn("tools/v02_verifier/test_v02_round2_register.py",
                      review_bundle.FILE_ALLOWLIST)
        for gate in ("OPEN-01", "OPEN-15", "G1", "G2", "G3"):
            self.assertIn("BLOCKED", review_bundle.BLOCKED[gate])
        self.assertIn("per actual encryption key", self.disposition)


if __name__ == "__main__":
    unittest.main()
