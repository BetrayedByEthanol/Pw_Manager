#!/usr/bin/env bash
# SEC-01A: opt-in candidate OCI static checks in rootless Podman.
# Never attach host engine sockets, real vault secrets or hardware tokens.
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repo_root"
image=''
mode=static-pr
candidate=false
network=none
while (( $# )); do
  case "$1" in
    --image) (( $# >= 2 )) || exit 64; image="$2"; shift 2;;
    --mode) (( $# >= 2 )) || exit 64; mode="$2"; shift 2;;
    --candidate) candidate=true; shift;;
    --allow-network) network=slirp4netns; shift;;
    -h|--help)
      echo "Usage: bash scripts/security/run-static-container.sh --image IMAGE --candidate [--mode static-pr|static-quick|static-sast|static-dependencies|static-browser|static-secrets] [--allow-network]"
      echo "Candidate-only; isolated OCI execution does not make the image trusted/approved."
      exit 0;;
    *) echo "SEC01A_BAD_ARGUMENT: $1" >&2; exit 64;;
  esac
done
case "$mode" in
  static-pr|static-quick|static-sast|static-dependencies|static-browser|static-secrets) ;;
  *) echo "SEC01A_BAD_MODE: $mode" >&2; exit 64;;
esac
[[ -n "$image" ]] || { echo "SEC01A_IMAGE_REQUIRED" >&2; exit 64; }
[[ "$candidate" == true ]] || {
  echo "SEC01A_CANDIDATE_CONSENT_REQUIRED: local unapproved OCI image must use --candidate" >&2
  exit 78
}
# No arbitrary image-option injection and no remote mutable OCI image by default.
[[ "$image" =~ ^localhost/[a-z0-9._/-]+:[a-z0-9._-]+$ ]] || {
  echo "SEC01A_LOCAL_IMAGE_ONLY: use a localhost tag created by the reviewed Containerfile" >&2
  exit 78
}
command -v podman >/dev/null || { echo "SEC01A_PODMAN_MISSING" >&2; exit 69; }
python3 tools/security/validate_contract.py
podman volume exists vaulty-sec01a-cargo || podman volume create vaulty-sec01a-cargo >/dev/null
podman volume exists vaulty-sec01a-target || podman volume create vaulty-sec01a-target >/dev/null
if [[ "$network" != none ]]; then
  echo "SEC01A_NETWORK_ENABLED: use only on a segregated developer/security VM with firewall rules" >&2
fi
exec podman run --rm --read-only --userns=keep-id \
  --cap-drop=all --security-opt=no-new-privileges --pids-limit=512 \
  --memory=12g --cpus=4 --network="$network" \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m \
  --mount "type=bind,src=$repo_root,dst=/workspace,ro" \
  --volume vaulty-sec01a-cargo:/cache/cargo:U \
  --volume vaulty-sec01a-target:/cache/target:U \
  -e CARGO_HOME=/cache/cargo \
  -e CARGO_TARGET_DIR=/cache/target \
  -e HOME=/tmp \
  -e PYTHONDONTWRITEBYTECODE=1 \
  --workdir /workspace "$image" bash scripts/security/run.sh "$mode"
