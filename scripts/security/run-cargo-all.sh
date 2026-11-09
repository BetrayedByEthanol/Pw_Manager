#!/usr/bin/env bash
# Existing Rust baseline checks, not a substitute for the SEC-01A scanner gate.
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repo_root"
command -v cargo >/dev/null || { echo "cargo not installed" >&2; exit 69; }
mapfile -t manifests < <(python3 - <<'PY'
import json
with open(".security/tools.lock.json", encoding="utf-8") as f:
    for manifest in json.load(f)["rust_manifests"]:
        print(manifest)
PY
)
for manifest in "${manifests[@]}"; do
  echo "SEC-00 existing Rust baseline: $manifest"
  cargo check --manifest-path "$manifest" --locked --all-targets
  cargo test --manifest-path "$manifest" --locked --all-targets
done
echo "Rust baseline complete. This is NOT a cryptographic approval or security-scanner gate."
