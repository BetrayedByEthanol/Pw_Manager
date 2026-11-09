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



class RustBaselineLoaderTests(unittest.TestCase):
    """Simulate missing/failed Python while Cargo remains on PATH."""

    def _run_baseline(self, python_mode):
        import shutil
        import sys
        import tempfile

        with tempfile.TemporaryDirectory(prefix="sec00-baseline-") as temp:
            bindir = Path(temp)
            real_dirname = shutil.which("dirname")
            self.assertIsNotNone(real_dirname)
            (bindir / "dirname").symlink_to(real_dirname)

            call_log = bindir / "cargo-calls.txt"
            fake_cargo = bindir / "cargo"
            fake_cargo.write_text(
                "#!/bin/sh\n"
                + "printf '%s\\n' \"$*\" >> " + repr(str(call_log)) + "\n",
                encoding="utf-8",
            )
            fake_cargo.chmod(0o755)

            fake_python = bindir / "python3"
            if python_mode == "valid":
                fake_python.symlink_to(sys.executable)
            elif python_mode == "empty":
                fake_python.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                fake_python.chmod(0o755)
            elif python_mode == "failed":
                fake_python.write_text("#!/bin/sh\nexit 21\n", encoding="utf-8")
                fake_python.chmod(0o755)
            elif python_mode != "missing":
                self.fail(f"unexpected python_mode: {python_mode}")

            environment = os.environ.copy()
            environment["PATH"] = str(bindir)
            process = subprocess.run(
                ["/bin/bash", str(SCRIPTS / "run-cargo-all.sh")],
                cwd=ROOT,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=15,
                check=False,
            )
            calls = call_log.read_text(encoding="utf-8").splitlines() if call_log.exists() else []
            return process, calls

    def test_rust_baseline_rejects_missing_python_before_cargo(self):
        process, calls = self._run_baseline("missing")
        self.assertEqual(78, process.returncode, process.stderr)
        self.assertIn("SEC00_MANIFEST_LOAD_FAILED", process.stderr)
        self.assertNotIn("Rust baseline complete", process.stdout)
        self.assertEqual([], calls)

    def test_rust_baseline_rejects_failed_python_before_cargo(self):
        process, calls = self._run_baseline("failed")
        self.assertEqual(78, process.returncode, process.stderr)
        self.assertIn("SEC00_MANIFEST_LOAD_FAILED", process.stderr)
        self.assertNotIn("Rust baseline complete", process.stdout)
        self.assertEqual([], calls)

    def test_rust_baseline_rejects_empty_manifest_output(self):
        process, calls = self._run_baseline("empty")
        self.assertEqual(78, process.returncode, process.stderr)
        self.assertIn("SEC00_MANIFEST_EMPTY", process.stderr)
        self.assertNotIn("Rust baseline complete", process.stdout)
        self.assertEqual([], calls)

    def test_rust_baseline_runs_all_five_manifests_with_locked_flags(self):
        process, calls = self._run_baseline("valid")
        self.assertEqual(0, process.returncode, process.stderr)
        self.assertIn("Rust baseline complete", process.stdout)
        self.assertEqual(10, len(calls), calls)
        self.assertTrue(all("--locked" in command for command in calls), calls)
        self.assertEqual(5, sum(command.startswith("check ") for command in calls))
        self.assertEqual(5, sum(command.startswith("test ") for command in calls))


if __name__ == "__main__":
    unittest.main()
