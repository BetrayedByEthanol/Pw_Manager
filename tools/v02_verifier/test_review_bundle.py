"""Synthetic review inventory tamper tests; no external review is implied."""
import json
import subprocess
from pathlib import Path
import tempfile
import unittest

import review_bundle as rb


class ReviewBundleTests(unittest.TestCase):
    PATHS = ("source.rs", "docs/review.md")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "source.rs").write_text("synthetic source\n")
        (self.root / "docs").mkdir()
        (self.root / "docs/review.md").write_text("not independently reviewed\n")
        subprocess.run(["git", "-C", str(self.root), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "--", *self.PATHS],
                       check=True)
        subprocess.run(
            ["git", "-C", str(self.root),
             "-c", "user.name=V02-D Synthetic Test",
             "-c", "user.email=review-test@example.invalid",
             "commit", "-q", "-m", "synthetic manifest fixture"],
            check=True,
        )
        self.COMMIT = rb.git_commit(self.root)
        self.document = rb.canonical(rb.inventory(self.root, self.COMMIT, self.PATHS))

    def test_accepts_only_exact_contents_and_declared_blocked_gates(self):
        rb.check_manifest(self.root, self.COMMIT, self.document, self.PATHS)
        payload = json.loads(self.document)
        self.assertEqual(payload["release_gates"], rb.BLOCKED)
        self.assertFalse(payload["approved_wire_format"])
        self.assertFalse(payload["production_credential_activation"])

    def test_rejects_changed_source_and_mismatched_commit(self):
        (self.root / "source.rs").write_text("changed source\n")
        with self.assertRaises(ValueError):
            rb.check_manifest(self.root, self.COMMIT, self.document, self.PATHS)
        (self.root / "source.rs").write_text("synthetic source\n")
        with self.assertRaises(ValueError):
            rb.check_manifest(self.root, "b" * 40, self.document, self.PATHS)

    def test_rejects_claimed_approval_and_noncanonical_json(self):
        payload = json.loads(self.document)
        payload["release_gates"]["OPEN-01"] = "APPROVED"
        with self.assertRaises(ValueError):
            rb.check_manifest(self.root, self.COMMIT, rb.canonical(payload), self.PATHS)
        with self.assertRaises(ValueError):
            rb.check_manifest(self.root, self.COMMIT,
                              self.document.replace(b"  ", b"   ", 1), self.PATHS)

    def test_rejects_symlink_and_path_traversal(self):
        (self.root / "source.rs").unlink()
        (self.root / "source.rs").symlink_to("docs/review.md")
        with self.assertRaises(ValueError):
            rb.inventory(self.root, self.COMMIT, self.PATHS)
        with self.assertRaises(ValueError):
            rb.inventory(self.root, self.COMMIT, ("../outside.rs",))
        with self.assertRaises(ValueError):
            rb.inventory(self.root, self.COMMIT, ("docs/review.md", "docs/review.md"))

    def test_rejects_staged_changes_and_untracked_files_with_commit_claim(self):
        (self.root / "source.rs").write_text("staged change not in HEAD\n")
        subprocess.run(["git", "-C", str(self.root), "add", "--", "source.rs"],
                       check=True)
        with self.assertRaisesRegex(ValueError, "committed blob"):
            rb.inventory(self.root, self.COMMIT, self.PATHS)
        subprocess.run(["git", "-C", str(self.root), "reset", "--hard", "-q",
                        self.COMMIT], check=True)
        (self.root / "untracked.rs").write_text("untracked bytes\n")
        with self.assertRaisesRegex(ValueError, "committed blob"):
            rb.inventory(self.root, self.COMMIT, ("untracked.rs",))

    def test_rejects_unlisted_and_missing_sources(self):
        with self.assertRaises(ValueError):
            rb.check_manifest(self.root, self.COMMIT, self.document, ("source.rs",))
        (self.root / "source.rs").unlink()
        with self.assertRaises(ValueError):
            rb.inventory(self.root, self.COMMIT, self.PATHS)


if __name__ == "__main__":
    unittest.main()
