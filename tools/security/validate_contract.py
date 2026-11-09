#!/usr/bin/env python3
"""SEC-00: validate preparation contracts without third-party packages."""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HEX64 = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_MANIFESTS = {
    "Cargo.toml",
    "extenstion/host/Cargo.toml",
    "tools/lifecycle/v03c_rust/Cargo.toml",
    "tools/security_probes/rust/Cargo.toml",
    "tools/v02_verifier/Cargo.toml",
}
EXPECTED_IMAGES = {"static", "fuzz", "analysis", "release"}
EXPECTED_JOBS = {"pr", "nightly", "analysis", "release"}


def load_contract(root=ROOT):
    with (root / ".security/tools.lock.json").open(encoding="utf-8") as f:
        lock = json.load(f)
    with (root / ".security/policy.json").open(encoding="utf-8") as f:
        policy = json.load(f)
    return lock, policy


def validate(root, lock, policy, require_approved=False):
    errors = []
    if lock.get("schema_version") != 1 or policy.get("schema_version") != 1:
        errors.append("SEC00_SCHEMA: expected schema_version=1")
    if lock.get("package") != "SEC-00" or policy.get("package") != "SEC-00":
        errors.append("SEC00_ID: wrong package")
    if lock.get("state") != "PREPARATION_ONLY" or policy.get("state") != "PREPARATION_ONLY":
        errors.append("SEC00_STATE: SEC-00 must not claim implementation")
    if lock.get("release_authorized") is not False:
        errors.append("SEC00_RELEASE: release must be unauthorized")

    installation = lock.get("installation_policy", {})
    for key in (
        "unapproved_tools_may_not_be_installed_by_automation",
        "require_exact_versions_and_verified_sha256",
        "require_immutable_container_digest",
        "forbid_curl_pipe_shell",
        "registry_tls_required_for_trusted_images",
    ):
        if installation.get(key) is not True:
            errors.append(f"SEC00_INSTALL: required policy {key} is disabled")

    manifests = lock.get("rust_manifests")
    if not isinstance(manifests, list) or set(manifests) != EXPECTED_MANIFESTS or len(manifests) != len(EXPECTED_MANIFESTS):
        errors.append("SEC00_MANIFESTS: must list all five existing Rust manifests once")
    else:
        for manifest in manifests:
            manifest_path = root / manifest
            if not manifest_path.is_file():
                errors.append(f"SEC00_MANIFEST_MISSING: {manifest}")
            if not (manifest_path.parent / "Cargo.lock").is_file():
                errors.append(f"SEC00_LOCKFILE_MISSING: {manifest_path.parent / 'Cargo.lock'}")

    tools = lock.get("tools", {})
    if not isinstance(tools, dict) or not tools:
        errors.append("SEC00_TOOLS: tool inventory missing")
        tools = {}
    for name, record in tools.items():
        if not isinstance(record, dict):
            errors.append(f"SEC00_TOOL_RECORD: {name}")
            continue
        state = record.get("status")
        if state not in ("pending", "approved"):
            errors.append(f"SEC00_TOOL_STATE: {name}")
        if not re.fullmatch(r"SEC-01[ABCD]", str(record.get("owner_package", ""))):
            errors.append(f"SEC00_TOOL_OWNER: {name}")
        if state == "pending":
            if any(record.get(field) is not None for field in ("version", "sha256", "source")):
                errors.append(f"SEC00_TOOL_PENDING_PIN: {name} has unapproved pin data")
            if require_approved:
                errors.append(f"SEC00_TOOL_NOT_APPROVED: {name}")
        elif state == "approved":
            if not isinstance(record.get("version"), str) or not record["version"].strip():
                errors.append(f"SEC00_TOOL_VERSION: {name}")
            if not isinstance(record.get("sha256"), str) or not HEX64.fullmatch(record["sha256"]):
                errors.append(f"SEC00_TOOL_HASH: {name}")
            if not isinstance(record.get("source"), str) or not record["source"].startswith("https://"):
                errors.append(f"SEC00_TOOL_SOURCE: {name}")

    images = lock.get("images", {})
    if not isinstance(images, dict) or set(images) != EXPECTED_IMAGES:
        errors.append("SEC00_IMAGES: require four defined image roles")
        images = {}
    for name, record in images.items():
        state = record.get("status")
        if state == "unpublished":
            if record.get("reference") is not None or record.get("digest") is not None:
                errors.append(f"SEC00_IMAGE_UNPUBLISHED: {name}")
            if require_approved:
                errors.append(f"SEC00_IMAGE_NOT_PUBLISHED: {name}")
        elif state == "published":
            digest = record.get("digest")
            ref = record.get("reference")
            if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                errors.append(f"SEC00_IMAGE_DIGEST: {name}")
            if not isinstance(ref, str) or not re.fullmatch(r"[^/@\s]+(?:/[^/@\s]+)+@sha256:[0-9a-f]{64}", ref):
                errors.append(f"SEC00_IMAGE_REF: {name}")
            elif ref.split("@")[-1] != digest:
                errors.append(f"SEC00_IMAGE_MISMATCH: {name}")
        else:
            errors.append(f"SEC00_IMAGE_STATE: {name}")

    execution = policy.get("execution", {})
    if not isinstance(execution, dict) or set(execution) != EXPECTED_JOBS:
        errors.append("SEC00_EXECUTION: missing job class")
        execution = {}
    for name, record in execution.items():
        if record.get("enabled") is not False or record.get("blocking") is not False:
            errors.append(f"SEC00_PREMATURE_GATE: {name}")
    for key, expected in (
        ("manual_readiness_workflows_only", True),
        ("real_credentials_permitted", False),
        ("production_crypto_approved", False),
        ("physical_fido2_in_ci", False),
        ("release_signing_in_general_ci", False),
    ):
        if policy.get(key) is not expected:
            errors.append(f"SEC00_UNSAFE_POLICY: {key}")
    trust = policy.get("trust_boundaries", {})
    if not all(isinstance(trust.get(role), dict) and
               trust[role].get("host_container_socket") is False and
               trust[role].get("production_secrets") is False
               for role in ("pr", "heavy", "release")):
        errors.append("SEC00_BOUNDARY: host socket / prod secrets must be prohibited")
    for role in ("pr", "heavy"):
        if trust.get(role, {}).get("signing_keys") is not False:
            errors.append(f"SEC00_SIGNING_BOUNDARY: {role}")
    if not {"OPEN-01", "OPEN-15", "G1", "G2", "G3"}.issubset(set(policy.get("outstanding_review_gates", []))):
        errors.append("SEC00_GATE_REGISTER: external crypto blockers missing")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-approved", action="store_true", help="fail until all tool and image pins are approved")
    args = parser.parse_args()
    try:
        lock, policy = load_contract()
        errors = validate(ROOT, lock, policy, args.require_approved)
    except (OSError, ValueError, TypeError) as exc:
        print(f"SEC00_CONTRACT_ERROR: {exc}", file=sys.stderr)
        return 2
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("SEC00_CONTRACT_VALID: preparation only; scanners and protected gates NOT enabled")
    return 0


if __name__ == "__main__":
    sys.exit(main())
