#!/usr/bin/env bash
# SEC-00: report prerequisites; presence does not mean security gates pass.
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repo_root"
python3 tools/security/validate_contract.py
echo "SEC-00 environment inventory (advisory):"
for binary in bash git python3 cargo rustc node npm podman docker semgrep gitleaks osv-scanner syft cosign trivy; do
  if command -v "$binary" >/dev/null 2>&1; then
    printf '  %-14s PRESENT (%s)\n' "$binary" "$(command -v "$binary")"
  else
    printf '  %-14s ABSENT / NOT APPROVED\n' "$binary"
  fi
done
echo "No scanner version or runner registration has been certified by this inventory."
