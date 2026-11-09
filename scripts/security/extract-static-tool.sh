#!/usr/bin/env bash
# SEC-01A: exact member extraction from a previously SHA-256-verified release tarball.
# Used by workstation bootstrap and the OCI Containerfile.
set -euo pipefail
[[ $# == 3 ]] || {
  echo "Usage: bash scripts/security/extract-static-tool.sh ARCHIVE {cargo-deny|gitleaks} DESTINATION_DIR" >&2
  exit 64
}
archive="$1"
tool="$2"
install_dir="$3"
[[ -f "$archive" ]] || { echo "SEC01A_ARCHIVE_MISSING: $archive" >&2; exit 78; }
case "$tool" in
  cargo-deny)
    # cargo-deny 0.20.2 release archives contain a versioned parent directory.
    member="cargo-deny-0.20.2-x86_64-unknown-linux-musl/cargo-deny"
    strip=1
    ;;
  gitleaks)
    # Gitleaks v8.30.1 Linux x64 release has a top-level executable.
    member="gitleaks"
    strip=0
    ;;
  *)
    echo "SEC01A_UNSUPPORTED_TOOL: $tool" >&2
    exit 64
    ;;
esac
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
# Only the exact binary member is extracted; never unpack arbitrary archive content.
tar -xzf "$archive" -C "$tmp" --strip-components="$strip" -- "$member" || {
  echo "SEC01A_ARCHIVE_MEMBER_MISSING: $member" >&2
  exit 78
}
[[ -f "$tmp/$tool" && ! -L "$tmp/$tool" ]] || {
  echo "SEC01A_ARCHIVE_INVALID_BINARY: $member" >&2
  exit 78
}
mkdir -p "$install_dir"
install -m 0755 -- "$tmp/$tool" "$install_dir/$tool"
