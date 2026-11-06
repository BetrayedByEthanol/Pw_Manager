# Vaulty — development prototype (not suitable for real credentials)

**V01 status:** The original CLI and vault format are security prototypes. The default binary deliberately exits unsuccessfully. Do not use it to store real credentials.

The review baseline and limitations are recorded in [V01 Prototype Safety & Build Foundation](docs/roadmap/V01-prototype-safety.md). This repository's architecture and security reference is Vaulty v0.4.5; the legacy binary is not compliant with it. The Python/Rust policy probes in `tools/security_probes` are *reference checkers*, not production authorization or approved cryptography.


## Canonical project documentation (v0.4.5 target)

- [Documentation index](docs/README.md) — start here for the current design and source-of-truth rules.
- [v0.4.5 specification](docs/specification/v0.4.5.md) and [architecture](docs/architecture/v0.4.5.md).
- [Implementation roadmap](docs/roadmap/implementation.md), [feature roadmap (38 FRs)](docs/roadmap/features.md), [acceptance register](docs/roadmap/acceptance-register.md) and [decision register](docs/decisions/register.md).
- [Historical 67-item source-feature mapping](docs/specification/history/v0.3-design-reference.md#21-original-feature-list-traceability-source-baseline).

**Repository status:** The V01 prototype foundation builds on GitHub, but the product is intentionally disabled and **must not store real secrets**. v0.4.5 is an approved *target design*, not implemented or security-reviewed runtime code. Next: **V01-A security closure**. Forgejo workflows are present but have not run on a configured Forgejo runner.

## Historical development checklist

create vault
open vault
add entry
update entry
update password
add fido
perform passkey
generate random new password
type on hotkey
send entry to relay
register from relay
show partial entry
list entries
register relay device




Start
on Open
on Close
init Vault
load Vault

CLI
prompt PW
confirm password
prompt Y/N
request entry load for hotkey
update master
update entry
list entries
list devices
get entry
remove device
remove entry
add new entry
start server
stop server


Vault
list entries
list devices
update master
update entry
add entry
add device
remove device
remove entry
show entry
load hotkey function
verify_pw , three tries
verify_default_entry



Crypto
generate_key
generate_pw (char set, length)
generate_salt
generate_nonce
argon2_hash
chacha encrypt
verify_pw , three tries
verify_default_entry
zero memory
generate passkey

Fido
setup fido2
request fido2


Socket
launch unix socket server
socket send response
socket receive request
socket receive new entry password
socket receive new entry passkey
socket allow device

Hotkey
register hotkey

IO - File
atomic vault update


Recovery Code for Password
Recovery Code for Fido2 into Virtual Device HMAC2
Fido2 Fallback device