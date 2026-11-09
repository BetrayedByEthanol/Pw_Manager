#!/usr/bin/env bash
# SEC-01A custom OCI build with two operator-verified immutable base digests.
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repo_root"
[[ $# == 3 ]] || {
  echo "Usage: bash scripts/security/build-static-image.sh RUST_BASE@sha256:... NODE_BASE@sha256:... local-image-tag" >&2
  echo "No floating image tags, no registry push and no signing in this script." >&2
  exit 64
}
rust_base="$1"; node_base="$2"; tag="$3"
for base in "$rust_base" "$node_base"; do
  [[ "$base" =~ ^[^/@[:space:]]+(/[^/@[:space:]]+)+@sha256:[0-9a-f]{64}$ ]] || {
    echo "SEC01A_BASE_NOT_DIGEST_PINNED: $base" >&2; exit 78;
  }
done
command -v podman >/dev/null || { echo "SEC01A_PODMAN_MISSING" >&2; exit 69; }
python3 tools/security/validate_contract.py
podman build --pull=never \
  --build-arg "RUST_BASE=$rust_base" \
  --build-arg "NODE_BASE=$node_base" \
  -f containers/security/Containerfile.static -t "$tag" .
echo "SEC01A_IMAGE_BUILT_LOCALLY: inspect digest, scan, SBOM, then separately approve TLS registry publication"
