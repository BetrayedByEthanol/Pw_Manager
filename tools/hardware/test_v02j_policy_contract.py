"""V02-J review-only contract assertions. No FIDO2 device is accessed."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "v02_verifier"))
import review_bundle  # noqa: E402


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class HardwarePolicyBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.packet = read("docs/security/V02J-isolated-fido2-hardware-verification.md")
        self.decisions = read("docs/decisions/register.md")
        self.acceptance = read("docs/roadmap/acceptance-register.md")

    def test_matrix_has_all_nine_unevaluated_cases(self):
        rows = [line for line in self.packet.splitlines()
                if line.startswith("| I-P")]
        self.assertEqual([row.split("|")[1].strip() for row in rows],
                         [f"I-P{i:02d}" for i in range(1, 10)])
        self.assertIn("None of I-P01–09 is automatically PASS", self.packet)
        self.assertIn("NOT EXECUTED ON HARDWARE", self.packet)
        self.assertIn("No WebAuthn/browser", self.packet)

    def test_review_only_does_not_approve_uv_salt_crypto_or_recovery(self):
        for marker in ("OPEN-HW-ASSURANCE", "OPEN-PRF-SALT", "OPEN-REC-CONSENT",
                       "OPEN-01", "OPEN-15", "G1", "G2", "G3", "Option A",
                       "S1/S2/R1", "NOT Vaulty runtime authentication"):
            self.assertIn(marker.lower(), self.packet.lower())
        self.assertIn("**BLOCKED — independent security/device review**", self.decisions)
        for gate in ("OPEN-01", "OPEN-15", "G1", "G2", "G3"):
            self.assertIn("BLOCKED", review_bundle.BLOCKED[gate])
        self.assertIn("OPEN-15", self.acceptance)

    def test_hardware_is_opt_in_and_not_on_ci(self):
        src = read("tools/hardware/fido2_v02j.py")
        for guard in ('--hardware-test', 'stdin.isatty()', 'os.environ.get("CI")',
                      '"entry_route_ready": False', '"open_15_approved": False',
                      '"open_01_approved": False', 'subprocess.run(', 'check=False'):
            self.assertIn(guard, src)
        self.assertNotIn("src/v02/v02j", src)

    def test_hardware_only_files_are_pinned_in_git_blob_inventory(self):
        for path in (
            "docs/security/V02J-isolated-fido2-hardware-verification.md",
            "tools/hardware/fido2_v02j.py",
            "tools/hardware/test_fido2_v02j.py",
            "tools/hardware/test_v02j_policy_contract.py",
        ):
            self.assertIn(path, review_bundle.FILE_ALLOWLIST)

    def test_untrusted_device_test_does_not_claim_browser_or_attestation(self):
        for marker in ("attestation certificate chain", "No WebAuthn/browser",
                       "does not guarantee zeroization",
                       "not a PASS", "not an independent OPEN-15 approval"):
            self.assertIn(marker.lower(), self.packet.lower())


if __name__ == "__main__":
    unittest.main()
