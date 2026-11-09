#!/usr/bin/env bash
# SEC-00 must not declare scanner versions approved before SEC-01 evidence.
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$repo_root"
python3 tools/security/validate_contract.py --require-approved
echo "All tool and OCI pins approved in manifest (still requires binary verification)." 
