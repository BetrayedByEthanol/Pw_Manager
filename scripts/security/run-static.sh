#!/usr/bin/env bash
# SEC-01A: real static analysis checks; never treat missing tools as a pass.
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repo_root"
mode="${1:-pr}"
case "$mode" in pr|quick|sast|dependencies|browser|secrets) ;; *)
  echo "SEC01A_UNKNOWN_MODE: $mode" >&2; exit 64;;
esac
case "$mode" in
  pr) versions="rustc,clippy,cargo-deny,gitleaks,semgrep,node,eslint,web-ext" ;;
  quick) versions="rustc,clippy,semgrep,node,eslint,web-ext" ;;
  sast) versions="rustc,clippy,semgrep" ;;
  dependencies) versions="rustc,cargo-deny" ;;
  browser) versions="node,eslint,web-ext" ;;
  secrets) versions="gitleaks" ;;
esac
python3 scripts/security/check-static-versions.py --only "$versions"
manifests=(
  Cargo.toml
  extenstion/host/Cargo.toml
  tools/lifecycle/v03c_rust/Cargo.toml
  tools/security_probes/rust/Cargo.toml
  tools/v02_verifier/Cargo.toml
)
if [[ "$mode" == pr || "$mode" == quick || "$mode" == sast ]]; then
  for manifest in "${manifests[@]}"; do
    [[ -f "$(dirname "$manifest")/Cargo.lock" ]] || { echo "SEC01A_LOCK_MISSING: $manifest" >&2; exit 78; }
    echo "SEC01A_CLIPPY: $manifest"
    cargo clippy --manifest-path "$manifest" --locked --all-targets -- -D clippy::correctness
  done
  echo "SEC01A_SEMGREP"
  semgrep scan --config .security/semgrep --error --metrics off \
    --exclude 'target/**' --exclude 'node_modules/**' \
    src extenstion tools
fi
if [[ "$mode" == pr || "$mode" == dependencies ]]; then
  for manifest in "${manifests[@]}"; do
    echo "SEC01A_CARGO_DENY: $manifest"
    cargo deny --manifest-path "$manifest" --config "$repo_root/deny.toml" check
  done
fi
if [[ "$mode" == pr || "$mode" == secrets ]]; then
  [[ -d .git ]] || { echo "SEC01A_NO_GIT_HISTORY: Gitleaks needs a real checkout" >&2; exit 78; }
  [[ "$(git rev-parse --is-shallow-repository)" == false ]] || {
    echo "SEC01A_SHALLOW_GIT_HISTORY: fetch full history before secret scanning" >&2; exit 78;
  }
  echo "SEC01A_GITLEAKS"
  gitleaks git --config .gitleaks.toml --redact --no-banner .
fi
if [[ "$mode" == pr || "$mode" == quick || "$mode" == browser ]]; then
  [[ -x node_modules/.bin/eslint && -x node_modules/.bin/web-ext ]] || {
    echo "SEC01A_NODE_MODULES_MISSING: run npm ci --ignore-scripts" >&2; exit 78;
  }
  echo "SEC01A_ESLINT"
  npm run lint:js
  echo "SEC01A_WEB_EXT"
  npm run lint:firefox
  for js in extenstion/*.js; do node --check "$js"; done
fi
echo "SEC01A_SCANS_PASSED: $mode — tooling scan only; no independent crypto approval"
