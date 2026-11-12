"""SEC-01A source-level and fail-closed contract tests; no network/scan required."""
import io
import json
import re
import subprocess
import tarfile
import tempfile
import tomllib
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

    def test_toml_security_policy_files_parse(self):
        for filename in ("deny.toml", ".gitleaks.toml"):
            with self.subTest(filename=filename):
                result = tomllib.loads((ROOT / filename).read_text(encoding="utf-8"))
                self.assertIsInstance(result, dict)
                self.assertTrue(result)
        policy = tomllib.loads((ROOT / "deny.toml").read_text(encoding="utf-8"))
        for group in ("advisories", "bans", "licenses", "sources"):
            self.assertIn(group, policy)
        # cargo-deny 0.20.2 removed the former licenses.unlicensed lint key.
        # Unlicensed packages are denied by default unless explicitly clarified.
        self.assertNotIn("unlicensed", policy["licenses"])

    def _extract_fake_archive(self, tool, member):
        with tempfile.TemporaryDirectory(prefix="sec01a-archive-") as td:
            root = Path(td)
            archive = root / "release.tar.gz"
            data = b"fixture-executable-content-not-live-binary\\n"
            with tarfile.open(archive, "w:gz") as tar:
                info = tarfile.TarInfo(member)
                info.mode = 0o755
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            dest = root / "bin"
            proc = subprocess.run(
                ["bash", str(ROOT / "scripts/security/extract-static-tool.sh"),
                 str(archive), tool, str(dest)],
                cwd=ROOT, capture_output=True, text=True, timeout=10,
            )
            binary = dest / tool
            return proc, binary.read_bytes() if binary.is_file() else None

    def test_cargo_deny_versioned_release_archive_extracts_exact_member(self):
        proc, data = self._extract_fake_archive(
            "cargo-deny", "cargo-deny-0.20.2-x86_64-unknown-linux-musl/cargo-deny"
        )
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertEqual(b"fixture-executable-content-not-live-binary\\n", data)

    def test_gitleaks_flat_release_archive_extracts_exact_member(self):
        proc, data = self._extract_fake_archive("gitleaks", "gitleaks")
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertEqual(b"fixture-executable-content-not-live-binary\\n", data)

    def test_cargo_deny_flat_archive_is_rejected(self):
        proc, data = self._extract_fake_archive("cargo-deny", "cargo-deny")
        self.assertEqual(78, proc.returncode)
        self.assertIn("SEC01A_ARCHIVE_MEMBER_MISSING", proc.stderr)
        self.assertIsNone(data)

    def test_both_install_paths_use_reviewed_archive_helper(self):
        helper = "extract-static-tool.sh"
        self.assertIn(
            helper,
            (ROOT / "scripts/security/install-static-tools.sh").read_text(encoding="utf-8"),
        )
        oci = (ROOT / "containers/security/Containerfile.static").read_text(encoding="utf-8")
        self.assertIn("COPY scripts/security/" + helper, oci)
        self.assertIn("bash /usr/local/share/vaulty/" + helper, oci)

    def test_unmaintained_scope_matches_pinned_cargo_deny_policy(self):
        policy = tomllib.loads((ROOT / "deny.toml").read_text(encoding="utf-8"))
        self.assertEqual("workspace", policy["advisories"]["unmaintained"])
        self.assertIn(
            policy["advisories"]["unmaintained"],
            {"all", "workspace", "transitive", "none"},
        )

    def test_extension_icon_matches_manifest_declared_48_px_size(self):
        """Read PNG IHDR using the standard library; no image tools in contract CI."""
        import struct
        import zlib

        manifest = json.loads((ROOT / "extenstion/manifest.json").read_text(encoding="utf-8"))
        icon_path = "icons/icon48.png"
        self.assertEqual(icon_path, manifest["icons"]["48"])
        self.assertEqual(icon_path, manifest["action"]["default_icon"]["48"])
        image = (ROOT / "extenstion" / icon_path).read_bytes()
        self.assertTrue(image.startswith(b"\\x89PNG\\r\\n\\x1a\\n"))
        self.assertEqual(b"IHDR", image[12:16])
        self.assertEqual((48, 48), struct.unpack(">II", image[16:24]))
        self.assertEqual(zlib.crc32(image[12:29]) & 0xFFFFFFFF,
                         struct.unpack(">I", image[29:33])[0])

    def test_semgrep_extension_paths_are_explicitly_root_anchored(self):
        """Avoid changed Semgrepignore-v2 semantics for unanchored paths."""
        rules = (ROOT / ".security/semgrep/vaulty-browser.yml").read_text(encoding="utf-8")
        self.assertEqual(3, rules.count('include: ["/extenstion/*.js"]'))
        self.assertNotIn("include: [extenstion/*.js]", rules)

    def test_manifest_preserves_both_browser_background_engines(self):
        """Firefox uses scripts and Chromium uses MV3 service_worker."""
        manifest = json.loads((ROOT / "extenstion/manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(["background.js"], manifest["background"]["scripts"])
        self.assertEqual("background.js", manifest["background"]["service_worker"])

    def test_privacy_declaration_does_not_falsely_claim_no_transmission(self):
        """Native messaging exists; a no-data claim needs a separate reviewed audit."""
        manifest = json.loads((ROOT / "extenstion/manifest.json").read_text(encoding="utf-8"))
        self.assertIn("nativeMessaging", manifest["permissions"])
        declaration = manifest["browser_specific_settings"]["gecko"].get("data_collection_permissions")
        if declaration is not None:
            self.assertNotEqual(["none"], declaration.get("required"),
                                "Native-messaging data flows need explicit privacy review")

    def test_renovate_is_proposal_only(self):
        config = json.loads((ROOT / "renovate.json").read_text(encoding="utf-8"))
        self.assertIs(config.get("automerge"), False)
        self.assertIs(config.get("dependencyDashboard"), True)

    def test_reviewed_binary_asset_sha256_values_are_recorded(self):
        for name in ("gitleaks", "cargo-deny"):
            with self.subTest(tool=name):
                item = self.candidate[name]
                self.assertTrue(item["url"].startswith("https://github.com/"))
                self.assertRegex(item["sha256"], r"^[0-9a-f]{64}$")
                self.assertIn(self.candidate["tools"][name], item["url"])

    def test_every_scanner_has_real_command(self):
        body = (ROOT / "scripts/security/run-static.sh").read_text(encoding="utf-8")
        inventory = json.loads((ROOT / ".security/tools.lock.json").read_text(encoding="utf-8"))
        for manifest in inventory["rust_manifests"]:
            self.assertIn("  " + manifest + "\n", body)
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
