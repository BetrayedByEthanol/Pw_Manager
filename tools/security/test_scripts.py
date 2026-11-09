"""End-to-end CLI failure modes; no scanners, containers or package installs."""
import os
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts/security"


def run(*args):
    return subprocess.run(["bash", *map(str, args)], cwd=ROOT,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=15, check=False)


class ScriptTests(unittest.TestCase):
    def test_contract_dispatch_passes(self):
        # Running the validation script directly avoids recursive unittest discovery.
        proc = run(SCRIPTS / "run.sh", "doctor")
        self.assertEqual(0, proc.returncode, proc.stderr)

    def test_pr_gate_fails_closed(self):
        proc = run(SCRIPTS / "run.sh", "pr")
        self.assertEqual(78, proc.returncode)
        self.assertIn("NOT_CONFIGURED", proc.stderr)

    def test_release_gate_fails_closed(self):
        proc = run(SCRIPTS / "run.sh", "release-verify")
        self.assertEqual(78, proc.returncode)

    def test_unapproved_digest_rejected_without_podman(self):
        image = "registry.example/vaulty/security-static@sha256:" + "a" * 64
        proc = run(SCRIPTS / "run-container.sh", "--image", image)
        self.assertEqual(78, proc.returncode, proc.stderr)
        self.assertIn("NOT_APPROVED", proc.stderr)

    def test_mutable_tag_rejected(self):
        proc = run(SCRIPTS / "run-container.sh", "--image", "registry.example/vaulty/security-static:latest")
        self.assertEqual(78, proc.returncode, proc.stderr)
        self.assertIn("UNPINNED", proc.stderr)

    def test_unapproved_tools_reported(self):
        proc = run(SCRIPTS / "check-versions.sh")
        self.assertNotEqual(0, proc.returncode)
        self.assertIn("NOT_APPROVED", proc.stderr)

    @unittest.skipUnless(Path("/etc/os-release").is_file() and
                         any(line.startswith(("ID=ubuntu", "ID=debian"))
                             for line in Path("/etc/os-release").read_text().splitlines()),
                         "only Debian/Ubuntu bootstrap is supported")
    def test_bootstrap_default_read_only(self):
        proc = run(SCRIPTS / "bootstrap-dev.sh", "--profile", "minimal", "--plan")
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertIn("Would execute:", proc.stdout)


if __name__ == "__main__":
    unittest.main()
