#!/usr/bin/env bash
# SEC-00: opt-in distro prerequisites only; no unreviewed scanner installs.
set -euo pipefail

usage() {
  cat <<'HELP'
Usage: bash scripts/security/bootstrap-dev.sh [--profile minimal|extended|release] [--plan | --apply --confirm]
Default: --profile minimal --plan.
--plan is read-only. --apply --confirm installs Debian/Ubuntu build prerequisites
using apt-get and may ask for sudo. It NEVER installs scanner binaries,
Rust via curl|sh, signing keys, or unpinned tools. SEC-01 owns tool installation.
HELP
}
profile=minimal
mode=plan
confirmed=false
while (( $# )); do
  case "$1" in
    --profile) (( $# >= 2 )) || { usage >&2; exit 64; }; profile="$2"; shift 2 ;;
    --plan) mode=plan; shift ;;
    --apply) mode=apply; shift ;;
    --confirm) confirmed=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 64 ;;
  esac
done
case "$profile" in minimal|extended|release) ;; *) echo "Invalid profile: $profile" >&2; exit 64;; esac
[[ -r /etc/os-release ]] || { echo "Unsupported OS: /etc/os-release unavailable" >&2; exit 69; }
# shellcheck source=/dev/null
. /etc/os-release
case "${ID:-}" in debian|ubuntu) ;; *) echo "Unsupported distro: ${ID:-unknown} (no automatic installation)" >&2; exit 69 ;; esac

packages=(ca-certificates build-essential clang curl git jq pkg-config python3 python3-venv
  libpcsclite-dev libfido2-dev libudev-dev libusb-1.0-0-dev
  libxkbcommon-dev libssl-dev libclang-dev)
if [[ "$profile" != minimal ]]; then packages+=(llvm lld cmake); fi
if [[ "$profile" == release ]]; then packages+=(gnupg); fi

echo "SEC-00 profile=$profile mode=$mode distribution=${PRETTY_NAME:-$ID}"
echo "Prerequisite packages: ${packages[*]}"
echo "Scanner versions and security OCI digests remain PENDING; no production gate is enabled."
if [[ "$mode" == plan ]]; then
  printf 'Would execute: sudo apt-get update && sudo apt-get install -y --no-install-recommends'
  printf ' %q' "${packages[@]}"
  printf '\n'
  exit 0
fi
[[ "$confirmed" == true ]] || { echo "Refusing install without --confirm" >&2; exit 64; }
if (( EUID == 0 )); then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
else
  command -v sudo >/dev/null || { echo "sudo is required for --apply" >&2; exit 69; }
  sudo apt-get update
  sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
fi
echo "SEC-00 distro prerequisites installed; run bash scripts/security/doctor.sh."
