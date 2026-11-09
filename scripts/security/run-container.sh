#!/usr/bin/env bash
# SEC-00 dry-safe image runner: digest pin, no network, no host engine socket.
set -euo pipefail
usage() {
  echo "Usage: bash scripts/security/run-container.sh --image REGISTRY/REPO@sha256:DIGEST [--mode contract]" >&2
}
image=''
mode=contract
while (( $# )); do
  case "$1" in
    --image) (( $# >= 2 )) || { usage; exit 64; }; image="$2"; shift 2 ;;
    --mode) (( $# >= 2 )) || { usage; exit 64; }; mode="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 64 ;;
  esac
done
[[ "$mode" == contract ]] || { echo "SEC00_NOT_CONFIGURED: only contract mode is implemented" >&2; exit 78; }
[[ "$image" =~ ^[^/@[:space:]]+(/[^/@[:space:]]+)+@sha256:[0-9a-f]{64}$ ]] || {
  echo "SEC00_IMAGE_UNPINNED: supply an immutable registry/repo@sha256:<64 hex> reference" >&2
  exit 78
}
# A digest-shaped string is not an approval. Require an approved match in the repo contract.
python3 - "$image" <<'PY'
import json
import sys
with open(".security/tools.lock.json", encoding="utf-8") as f:
    lock = json.load(f)
requested = sys.argv[1]
approved = [obj["reference"] for obj in lock.get("images", {}).values()
            if obj.get("status") == "published" and obj.get("reference")]
if requested not in approved:
    print("SEC00_IMAGE_NOT_APPROVED: image digest is not in an approved lockfile record", file=sys.stderr)
    sys.exit(78)
PY
command -v podman >/dev/null || { echo "podman not installed" >&2; exit 69; }
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
exec podman run --rm --network=none --read-only --userns=keep-id --cap-drop=all \
  --security-opt=no-new-privileges --pids-limit=256 \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m \
  --mount "type=bind,src=$repo_root,dst=/workspace,ro" \
  -e PYTHONDONTWRITEBYTECODE=1 \
  --workdir /workspace "$image" bash scripts/security/run.sh contract
