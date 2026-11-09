"""SEC-01A source-level and fail-closed contract tests; no network/scan required."""
import json
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / ".security" / "sec01a-static.json"


class SEC01AStaticContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.candidate = json.loads(CONFIG.read_text(encoding="utf-8"))
        cls.npm = json.loads((ROOT / "package-lock.json").read_text(encoding="utf-8"))
        cls.package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))

    def test_candidate_never_claims_protected_gate(self):
        self.assertEqual("CANDIDATE_NOT_ENFORCED", self.candidate["status"])
        self.assertIsNone(self.candidate["runner"]["published_image_digest"])
        self.assertIs(self.candidate["runner"]["protected_check_enabled"], False)
        self.assertIs(self.candidate["runner"]["registered_and_isolated"], False)

    def test_npm_dev_dependencies_are_exact_and_locked(self):
        requested = self.package["devDependencies"]
        resolved = self.npm["packages"][""]["devDependencies"]
        self.assertEqual({"eslint": "10.14.0", "web-ext": "10.8.0"}, requested)
        self.assertEqual(requested, resolved)
        self.assertGreater(len(self.npm["packages"]), 300)
        for name, item in self.npm["packages"].items():
            if item.get("resolved", "").startswith("https://registry.npmjs.org/"):
                self.assertRegex(item.get("integrity", ""), r"^sha512-")

    def test_reviewed_binary_asset_sha256_values_are_recorded(self):
        for name in ("gitleaks", "cargo-deny"):
            with self.subTest(tool=name):
                item = self.candidate[name]
                self.assertTrue(item["url"].startswith("https://github.com/"))
                self.assertRegex(item["sha256"], r"^[0-9a-f]{64}$")
                self.assertIn(self.candidate["tools"][name], item["url"])

    def test_every_scanner_has_real_command(self):
        body = (ROOT / "scripts/security/run-static.sh").read_text(encoding="utf-8")
        for command in ("cargo clippy", "cargo deny", "gitleaks git", "semgrep scan",
                        "npm run lint:js", "npm run lint:firefox"):
            with self.subTest(command=command):
                self.assertIn(command, body)
        self.assertIn("--locked", body)
        self.assertIn("--redact", body)
        self.assertIn("SHALLOW_GIT_HISTORY", body)

    def test_original_sec00_pr_gate_still_fails_closed(self):
        result = subprocess.run(["bash", "scripts/security/run.sh", "pr"],
                                cwd=ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 78)
        self.assertIn("NOT_CONFIGURED", result.stderr)

    def test_manual_github_workflow_not_automatic(self):
        body = (ROOT / ".github/workflows/sec01a-security-manual.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", body)
        self.assertNotIn("  pull_request:", body)
        self.assertNotIn("  push:", body)
        self.assertIn("static-pr", body)
        self.assertIn("persist-credentials: false", body)

    def test_forgejo_has_no_untrusted_fallback(self):
        body = (ROOT / ".forgejo/workflows/sec01a-static-security.yml").read_text(encoding="utf-8")
        self.assertIn("runs-on: vaulty-pr", body)
        self.assertNotIn("runs-on: docker", body)
        self.assertNotIn("privileged: true", body)
        self.assertIn("static-pr", body)

    def test_custom_image_builder_requires_pinned_bases(self):
        body = (ROOT / "scripts/security/build-static-image.sh").read_text(encoding="utf-8")
        self.assertIn("sha256:", body)
        self.assertIn("--pull=never", body)
        self.assertIn("SEC01A_BASE_NOT_DIGEST_PINNED", body)

    def test_runbooks_cover_each_location(self):
        root = ROOT / "security_checks_doc"
        expected = [
            "README.md", "01-development-machine.md", "02-repository.md",
            "03-container-and-zot.md", "04-forgejo-runner.md",
            "05-forgejo-workflows.md", "06-github-actions.md",
            "07-security-lab.md", "08-renovate.md",
            "09-acceptance-and-evidence.md", "10-check-command-reference.md",
        ]
        self.assertTrue(all((root / f).is_file() for f in expected))

    def test_security_images_not_falsely_approved(self):
        inventory = json.loads((ROOT / ".security/tools.lock.json").read_text())
        self.assertEqual("unpublished", inventory["images"]["static"]["status"])
        self.assertIsNone(inventory["images"]["static"]["digest"])

    def test_unapproved_oci_candidate_requires_explicit_consent(self):
        proc = subprocess.run(
            ["bash", "scripts/security/run-static-container.sh", "--image",
             "localhost/vaulty/security-static:sec01a"],
            cwd=ROOT, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(78, proc.returncode)
        self.assertIn("CANDIDATE_CONSENT_REQUIRED", proc.stderr)

    def test_nonlocal_oci_candidate_rejected_before_podman(self):
        proc = subprocess.run(
            ["bash", "scripts/security/run-static-container.sh", "--image",
             "registry.example/vaulty/security-static:latest", "--candidate"],
            cwd=ROOT, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(78, proc.returncode)
        self.assertIn("LOCAL_IMAGE_ONLY", proc.stderr)

    def test_install_requires_explicit_candidate_consent(self):
        proc = subprocess.run(
            ["bash", "scripts/security/install-static-tools.sh", "--apply", "--confirm"],
            cwd=ROOT, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(78, proc.returncode)
        self.assertIn("CANDIDATE_CONSENT_REQUIRED", proc.stderr)

if __name__ == "__main__":
    unittest.main()
