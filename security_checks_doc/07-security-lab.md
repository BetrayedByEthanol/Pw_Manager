# Dedicated security environments

SEC-01A static scans use an isolated Forgejo PR runner and a local developer workstation; they do not require a physical test lab.

| Environment | Role | Owner |
| --- | --- | --- |
| Disposable PR runner | Source/security static scans; no secrets | SEC-01A |
| `vaulty-sec-lab` planned VM | Fuzz, Miri, sanitizers, timing tests; crash corpus | SEC-01B |
| `vaulty-hardware-lab` operator machine | Physical FIDO2/UV and negative observations with synthetic credentials only | Existing V02-J/K/L and future physical testing |
| Protected release-builder planned VM | SBOM/provenance/signature generation with approved identities | SEC-01D |

Never attach physical USB tokens or pass PRF outputs into ordinary static CI. Run long fuzz/sanitizer jobs with resource limits and disposable source copies. Crash corpus contents must be reviewed and purged if they unexpectedly contain secrets. Document hardware model, firmware, test scenario and redacted output without storing PINs or PRF secrets.

Ansible hosts and runner provisioning belong to the homelab infrastructure repository; Vaulty's repo documents the requirements but does not assert that those external VMs exist or have been configured.
