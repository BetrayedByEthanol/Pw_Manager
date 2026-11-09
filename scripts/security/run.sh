#!/usr/bin/env bash
# Single CLI dispatcher, fail-closed for every not-yet-implemented SEC-01 check.
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repo_root"
mode="${1:-help}"
[[ $# -le 1 ]] || { echo "Unexpected arguments" >&2; exit 64; }
case "$mode" in
  contract)
    python3 tools/security/validate_contract.py
    python3 -B -m unittest discover -s tools/security -p 'test_*.py' -v
    for file in scripts/security/*.sh; do bash -n "$file"; done
    echo "SEC00_CONTRACT_TESTS_PASSED — preparation checks only"
    ;;
  doctor)
    bash scripts/security/doctor.sh
    ;;
  plan)
    bash scripts/security/bootstrap-dev.sh --profile minimal --plan
    ;;
  rust-baseline)
    bash scripts/security/run-cargo-all.sh
    ;;
  check-versions)
    bash scripts/security/check-versions.sh
    ;;
  static-pr|static-quick|static-dependencies|static-browser|static-sast|static-secrets)
    bash scripts/security/run-static.sh "${mode#static-}"
    ;;
  pr|quick|dependencies|browser|sast|fuzz-smoke|full|release-verify)
    echo "SEC00_NOT_CONFIGURED: $mode belongs to a later SEC-01 package; refusing false PASS" >&2
    exit 78
    ;;
  help|-h|--help)
    echo "Usage: bash scripts/security/run.sh {contract|doctor|plan|rust-baseline|check-versions|static-pr|static-quick|static-dependencies|static-browser|static-sast|static-secrets|pr|quick|dependencies|browser|sast|fuzz-smoke|full|release-verify}"
    echo "SEC-01A candidate checks: static-*. Enforced PR/release gates remain disabled; original pr/full/release-verify commands exit 78."
    ;;
  *)
    echo "Unknown security mode: $mode" >&2
    exit 64
    ;;
esac
