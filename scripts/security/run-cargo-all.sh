#!/usr/bin/env bash
# Existing Rust baseline checks, not a substitute for the SEC-01A scanner gate.
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repo_root"
command -v cargo >/dev/null || { echo "cargo not installed" >&2; exit 69; }
# Do not put the manifest loader in process substitution: mapfile would then
# silently succeed on a failed/missing Python interpreter and check zero crates.
manifest_lines="$(python3 - <<'PY'
import json

with open(".security/tools.lock.json", encoding="utf-8") as f:
    manifests = json.load(f)["rust_manifests"]
if (
    not isinstance(manifests, list)
    or not manifests
    or any(
        not isinstance(manifest, str)
        or not manifest.strip()
        or "\n" in manifest
        or "\r" in manifest
        for manifest in manifests
    )
):
    raise ValueError("rust_manifests must be a nonempty list of nonempty paths")
for manifest in manifests:
    print(manifest)
PY
)" || {
  echo "SEC00_MANIFEST_LOAD_FAILED: cannot load required Rust manifests" >&2
  exit 78
}
[[ -n "$manifest_lines" ]] || {
  echo "SEC00_MANIFEST_EMPTY: refusing to report success with zero Rust manifests" >&2
  exit 78
}
mapfile -t manifests <<< "$manifest_lines"
(( ${#manifests[@]} > 0 )) || {
  echo "SEC00_MANIFEST_EMPTY: refusing to report success with zero Rust manifests" >&2
  exit 78
}
for manifest in "${manifests[@]}"; do
  lockfile="$(dirname "$manifest")/Cargo.lock"
  [[ -f "$lockfile" ]] || { echo "SEC00_LOCKFILE_MISSING: $lockfile" >&2; exit 78; }
  echo "SEC-00 existing Rust baseline: $manifest"
  cargo check --manifest-path "$manifest" --locked --all-targets
  cargo test --manifest-path "$manifest" --locked --all-targets
done
echo "Rust baseline complete. This is NOT a cryptographic approval or security-scanner gate."
