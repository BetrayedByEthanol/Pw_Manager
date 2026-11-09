#!/usr/bin/env bash
# SEC-01A candidate local bootstrap; source-integrity-pinned binary tools.
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repo_root"
mode=plan
ack=false
candidate_ack=false
while (( $# )); do
  case "$1" in
    --plan) mode=plan; shift;;
    --apply) mode=apply; shift;;
    --confirm) ack=true; shift;;
    --candidate) candidate_ack=true; shift;;
    -h|--help)
      echo "Usage: bash scripts/security/install-static-tools.sh [--plan | --apply --confirm --candidate]"
      echo "Installs approved Gitleaks/cargo-deny archives, top-level-version-pinned Semgrep and npm dev tools."
      echo "Rust 1.99.1 + Clippy and a Python3 venv-capable runtime must already exist."
      echo "Semgrep transitive PyPI packages are NOT hash-locked; not release-approved."
      exit 0;;
    *) echo "unknown argument: $1" >&2; exit 64;;
  esac
done
if [[ "$mode" == plan ]]; then
  echo "Plan: verify Rust 1.99.1 + Clippy; download and SHA-256 verify cargo-deny 0.20.2, Gitleaks 8.30.1."
  echo "Plan: install semgrep==1.184.0 in a private venv and npm ci --ignore-scripts using package-lock.json."
  echo "Candidate only: Semgrep transitive wheel integrity review and OCI image publication are outstanding."
  exit 0
fi
[[ "$ack" == true ]] || { echo "SEC01A_CONFIRM_REQUIRED: --apply requires --confirm" >&2; exit 64; }
[[ "$candidate_ack" == true ]] || {
  echo "SEC01A_CANDIDATE_CONSENT_REQUIRED: Semgrep transitive PyPI wheels have no approved hash lock; supply --candidate for explicit dev-only installation" >&2
  exit 78
}
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || {
  echo "SEC01A_PLATFORM_UNSUPPORTED: this installer supports Linux x86_64 only" >&2; exit 69;
}
for required in python3 curl tar sha256sum cargo rustc npm node; do
  command -v "$required" >/dev/null || { echo "SEC01A_PREREQUISITE_MISSING: $required" >&2; exit 69; }
done
python3 - <<'PY'
import json
from pathlib import Path
m = json.loads(Path(".security/sec01a-static.json").read_text())
for key in ("gitleaks", "cargo-deny"):
    info = m[key]
    if not info["url"].startswith("https://") or len(info["sha256"]) != 64:
        raise SystemExit(f"SEC01A_UNVERIFIED_SOURCE: {key}")
PY
install_dir="$HOME/.local/bin"
mkdir -p "$install_dir"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
for tool in cargo-deny gitleaks; do
  info_lines="$(python3 - "$tool" <<'PY'
import json,sys
with open(".security/sec01a-static.json", encoding="utf-8") as f:
    o=json.load(f)[sys.argv[1]]
print(o["url"]);print(o["sha256"])
PY
)" || { echo "SEC01A_TOOL_METADATA_LOAD_FAILED: $tool" >&2; exit 78; }
  [[ -n "$info_lines" ]] || { echo "SEC01A_TOOL_METADATA_EMPTY: $tool" >&2; exit 78; }
  mapfile -t info <<< "$info_lines"
  [[ "${#info[@]}" == 2 ]] || { echo "SEC01A_INVALID_TOOL_RECORD: $tool" >&2; exit 78; }
  curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error     --retry 3 --output "$tmp/$tool.tar.gz" "${info[0]}"
  printf '%s  %s\n' "${info[1]}" "$tmp/$tool.tar.gz" | sha256sum --check --status || {
    echo "SEC01A_HASH_MISMATCH: $tool" >&2; exit 78;
  }
  # Shared extraction logic matches cargo-deny's nested release member and
  # Gitleaks' top-level member. Archives are SHA-256 checked immediately above.
  bash scripts/security/extract-static-tool.sh "$tmp/$tool.tar.gz" "$tool" "$install_dir"
done
echo "SEC-01A verified binary tools installed to $install_dir"

# Candidate-only: the top-level Semgrep version is fixed, but transitive
# dependencies do not yet have reviewed PyPI hashes. No release promotion.
python3 -m venv "$HOME/.local/share/vaulty/sec01a-venv"
"$HOME/.local/share/vaulty/sec01a-venv/bin/python" -m pip install   --disable-pip-version-check --no-input 'semgrep==1.184.0'

# npm ci uses committed SHA-512-integrity-pinned package-lock.json.
npm ci --ignore-scripts --no-audit --no-fund
echo "SEC01A_LOCAL_SETUP_CANDIDATE: source your own installed Rust toolchain and run scripts/security/run.sh pr"
echo "PATH tip: export PATH=\"$install_dir:$HOME/.local/share/vaulty/sec01a-venv/bin:$repo_root/node_modules/.bin:\$PATH\""
