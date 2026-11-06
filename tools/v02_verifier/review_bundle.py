#!/usr/bin/env python3
"""Create/verify a deterministic, synthetic-only V02-D review inventory.

This identifies precisely which source/fixtures/documents an external reviewer
was given. It is NOT a signature, security approval, hardware evidence, SBOM,
or endorsement of the candidate cryptographic construction.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

SCHEMA = "vaulty-v02d-review-inventory-v1"
MAX_FILE_BYTES = 2 * 1024 * 1024
FILE_ALLOWLIST = (
    "Cargo.toml",
    "Cargo.lock",
    "src/v02/model.rs",
    "src/v02/codec.rs",
    "src/v02/mod.rs",
    "src/v02/v02b.rs",
    "src/v02/v02c_tests.rs",
    "src/v02/v02d_tests.rs",
    "tools/v02_verifier/Cargo.toml",
    "tools/v02_verifier/reference_v02c.py",
    "tools/v02_verifier/review_bundle.py",
    "tools/v02_verifier/test_review_bundle.py",
    "tools/v02_verifier/fixtures/v02c_kats.txt",
    "tools/security_probes/CRYPTO_REVIEW_REQUEST.md",
    "docs/specification/v0.4.5.md",
    "docs/architecture/v0.4.5.md",
    "docs/architecture/v02a-crypto-keyslot-review.md",
    "docs/architecture/v02b-keyslot-candidate.md",
    "docs/security/V02C-cryptographic-conformance.md",
    "docs/security/V02D-independent-review-handoff.md",
    "docs/decisions/register.md",
    ".github/workflows/v02-candidate.yml",
    ".forgejo/workflows/v02-candidate.yml",
)
BLOCKED = {
    "OPEN-01": "BLOCKED: no independent cryptographic approval",
    "OPEN-15": "BLOCKED: no real-device FIDO2 security approval",
    "G1": "BLOCKED",
    "G2": "BLOCKED",
    "G3": "BLOCKED",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_sources(root: Path, commit: str,
                 paths: tuple[str, ...]) -> dict[str, dict[str, object]]:
    root = root.resolve(strict=True)
    if len(paths) != len(set(paths)):
        raise ValueError("duplicate review inventory path")
    result = {}
    for rel in sorted(paths):
        relative = Path(rel)
        if relative.is_absolute() or ".." in relative.parts or "." in relative.parts:
            raise ValueError(f"unsafe manifest path: {rel}")
        path = root / relative
        if path.is_symlink() or not path.is_file() or root not in path.resolve().parents:
            raise ValueError(f"missing/linked/out-of-tree review file: {rel}")
        if path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"review source too large: {rel}")
        data = path.read_bytes()
        if not data:
            raise ValueError(f"empty review source: {rel}")
        # A clean-working-tree claim is insufficient: the bytes MUST belong
        # to the exact HEAD commit, even when the source tree has staged or
        # unstaged changes. git show also rejects an untracked review file.
        # Use argv, never a shell; the path list is static and traversal-free.
        reference = subprocess.run(
            ["git", "-C", str(root), "show", f"{commit}:{rel}"],
            capture_output=True, check=False,
        )
        if reference.returncode or reference.stdout != data:
            raise ValueError(f"review source differs from committed blob: {rel}")
        result[rel] = {"sha256": digest(data), "bytes": len(data)}
    return result


def inventory(root: Path, commit: str, paths: tuple[str, ...] = FILE_ALLOWLIST) -> dict:
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("review reference must be a full SHA-1 Git commit ID")
    sources = read_sources(root, commit, paths)
    manifest = {
        "schema": SCHEMA,
        "git_commit": commit,
        "scope": "inactive V02-B/C/D candidate, synthetic fixtures only",
        "source_files": sources,
        "release_gates": BLOCKED,
        "external_cryptographic_review": "NOT PERFORMED",
        "real_hardware_verification": "NOT PERFORMED",
        "approved_wire_format": False,
        "production_credential_activation": False,
    }
    # Not a signature: merely a deterministic content checksum for comparing
    # two copies of this manifest. The Git commit is the authoritative locator.
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest["manifest_sha256"] = digest(payload)
    return manifest


def git_commit(root: Path) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
        text=True, stderr=subprocess.DEVNULL,
    ).strip()


def canonical(manifest: dict) -> bytes:
    return (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()


def check_manifest(root: Path, commit: str, document: bytes,
                   paths: tuple[str, ...] = FILE_ALLOWLIST) -> None:
    if len(document) > MAX_FILE_BYTES:
        raise ValueError("oversized inventory")
    decoded = json.loads(document)
    expected = inventory(root, commit, paths)
    if decoded != expected:
        raise ValueError("inventory content/commit/status mismatch")
    if document != canonical(decoded):
        raise ValueError("non-canonical inventory encoding")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    option = p.add_mutually_exclusive_group(required=True)
    option.add_argument("--write", type=Path, metavar="PATH")
    option.add_argument("--check", type=Path, metavar="PATH")
    args = p.parse_args()
    root = Path(__file__).resolve().parents[2]
    commit = git_commit(root)
    if args.write:
        data = canonical(inventory(root, commit))
        args.write.write_bytes(data)
        print(f"V02-D review inventory created for {commit}: {len(FILE_ALLOWLIST)} source paths, sha256={digest(data)}")
    else:
        check_manifest(root, commit, args.check.read_bytes())
        print(f"V02-D review inventory verified for {commit}: {len(FILE_ALLOWLIST)} source paths")


if __name__ == "__main__":
    main()
