"""V02-H round-two findings: review/approval-boundary documentation tests.

These are static ledger checks only. They DO NOT validate cryptographic
commitment, consent, KDF resource enforcement, real FIDO2, or hardware.
"""
import re
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
        # Enumerate the *entire* round-two disposition table; F-10 or a
        # duplicate F-2 must fail instead of being ignored by substring tests.
        block = self.disposition.split("## Accepted F-1–F-9 dispositions", 1)[1]
        block = block.split("## Additional W1/probe observations", 1)[0]
        source_ids = re.findall(r"^\| \*\*(F-\d+) —", block, flags=re.MULTILINE)
        expected_sources = [f"F-{n}" for n in range(1, 10)]
        self.assertEqual(len(source_ids), len(set(source_ids)), "duplicate finding in source")
        self.assertEqual(set(source_ids), set(expected_sources),
                         "unexpected, absent or renamed F finding")

        block = self.acceptance.split("## 2l. Round-two findings acceptance", 1)[1]
        block = block.split("## 3. Security findings register", 1)[0]
        rows = [tuple(cell.strip() for cell in line.strip("|").split("|"))
                for line in block.splitlines()
                if re.match(r"^\| (?:F-\d+|W1) /", line)]
        self.assertTrue(all(len(row) == 3 for row in rows),
                        "round-two table has malformed fields")
        actual_ids = [row[0] for row in rows]
        self.assertEqual(len(actual_ids), len(set(actual_ids)),
                         "duplicate finding→SEC mapping row")

        expected = {
            "F-1": "SEC-14",
            "F-2": "SEC-15",
            "F-3": "SEC-06",
            "F-4": "SEC-06",
            "F-5": "A02E-01",
            "F-6": "SEC-05",
            "F-7": "SEC-06",
            "F-8": "SEC-09",
            "F-9": "SEC-16",
            "W1": "SEC-17",
        }
        self.assertEqual({row[0] for row in rows},
                         {f"{k} / {v}" for k, v in expected.items()},
                         "finding-to-security-register mappings must be exact")
        mapped = {row[0]: row[1] for row in rows}
        self.assertEqual(mapped["F-1 / SEC-14"], "**OPEN — OWNER POLICY CHOICE**")
        self.assertEqual(mapped["F-5 / A02E-01"],
                         "**CLOSED — structural route validator only**")
        self.assertEqual(mapped["F-6 / SEC-05"], "**PARTIAL — REVIEW-ONLY WIRE**")

    def test_security_register_has_unique_ids_and_expected_severities(self):
        block = self.acceptance.split("## 3. Security findings register", 1)[1]
        block = block.split("## 4. Verification gaps", 1)[0]
        rows = [tuple(cell.strip() for cell in line.strip("|").split("|"))
                for line in block.splitlines()
                if re.match(r"^\| SEC-\d+ \|", line)]
        ids = [row[0] for row in rows]
        self.assertEqual(len(ids), len(set(ids)), "duplicate SEC identifier")
        self.assertTrue(all(len(row) == 5 for row in rows),
                        "SEC table columns must remain unambiguous")
        expected = {f"SEC-{n:02d}": ("P2" if n in (7, 8, 9, 11, 12, 13) else "P1")
                    for n in range(1, 18)}
        self.assertEqual({row[0]: row[1] for row in rows}, expected,
                         "SEC register IDs/severities must be explicitly reviewed")
        # Three separate hardware observations intentionally refer to SEC-06.
        self.assertEqual(sum(row[0] == "SEC-06" for row in rows), 1)

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
        self.assertIn("docs/roadmap/acceptance-register.md",
                      review_bundle.FILE_ALLOWLIST)
        for gate in ("OPEN-01", "OPEN-15", "G1", "G2", "G3"):
            self.assertIn("BLOCKED", review_bundle.BLOCKED[gate])
        self.assertIn("per actual encryption key", self.disposition)


if __name__ == "__main__":
    unittest.main()
