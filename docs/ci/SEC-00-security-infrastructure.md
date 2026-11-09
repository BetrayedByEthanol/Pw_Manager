# SEC-00 — Security Infrastructure Preparation

**Status: PR CANDIDATE / PREPARATION ONLY.** This package prepares contracts and reproducible entrypoints; it neither installs security scanners nor provisions protected runners or signs releases. Mainline workflows and crypto acceptance remain unchanged until this PR is reviewed and merged.

## 1. Purpose / non-goals

SEC-00 creates a single source-controlled contract for local development, OCI execution, the Forgejo runner fleet, manual GitHub fallback, security laboratories and future release builders. Do not convert this into a claim that any tools, runners, scans, signing, or independent cryptographic approvals are operational. Separate deliverables: SEC-01A static/PR, SEC-01B adversarial, SEC-01C intelligence/threat-model, SEC-01D release supply chain.

The actual source tree has five separate Rust manifests and an existing **misspelled** `extenstion/` directory. Preserve those paths here; rename only in a dedicated migration.

## 2. Location-to-artifact map

| Location | SEC-00 artifact / operation | Not enabled in SEC-00 |
| --- | --- | --- |
| Linux developer machine | `scripts/security/bootstrap-dev.sh` (plan/default, optional explicit apt prerequisites), `doctor.sh`, `run.sh`, `run-cargo-all.sh` | Scanner installation, PR security certification |
| Git repository | `.security/tools.lock.json`, `.security/policy.json`, tests and docs | Approved pin data and scanner rules |
| Container tool (rootless Podman) | `scripts/security/run-container.sh`, `containers/security/README.md` | Built OCI images, trusted Zot release images |
| Forgejo runner | Four planned trust classes; `.forgejo/workflows/sec00-readiness.yml` manual smoke only | Required checks, dedicated PR/heavy/signing runner provisioning |
| GitHub | `.github/workflows/sec00-readiness.yml`, `workflow_dispatch` only; hosted runner | Automatic security gate, homelab access |
| Security lab | Documented dedicated VMs, offsite reproducible evidence | Host allocation, hardware execution, fuzz campaigns |
| Evidence / decisions | This runbook and `docs/security/assurance/SEC-00-acceptance.md` | Any OPEN-01/OPEN-15/G1-G3 closure |

## 3. Development machine runbook

```sh
git clone https://github.com/BetrayedByEthanol/Pw_Manager.git
cd Pw_Manager
git checkout sec/sec00-security-infrastructure-preparation
bash scripts/security/bootstrap-dev.sh --profile minimal --plan
# Optional, explicitly mutates Debian/Ubuntu OS prerequisites only:
bash scripts/security/bootstrap-dev.sh --profile minimal --apply --confirm
bash scripts/security/doctor.sh
bash scripts/security/run.sh contract
# Existing Rust baseline, if Rust/build requirements are already installed:
bash scripts/security/run.sh rust-baseline
```

`extended` adds LLVM/LLD/CMake OS prerequisites; `release` adds GnuPG prerequisites. These **do not install** cargo-fuzz, CodeQL, Syft, cosign, or any security scanner. Do not install unknown binaries with `curl | sh`. Tool install steps must first be reviewed and pinned in SEC-01A–D. `check-versions.sh` intentionally fails until each tool+image is approved; `run.sh pr` intentionally exits 78.

## 4. Container and registry contract

Use digest-pinned, reviewed base and final images. Supply chain path:
reviewed builder -> synthetic/no-real-secret scan -> SBOM -> approved digest -> authenticated TLS Zot -> isolated runner pull by digest.
Never rely on mutable tags for security evaluation. Keep current LAN HTTP Zot configuration **non-trusted**. Rootless Podman is preferred for local test commands; do not expose host Docker/Podman sockets inside untrusted jobs. The container helper runs `contract` only, with read-only source mount, no network, dropped capabilities, no-new-privileges and a temporary scratch area. No eligible image digest exists at SEC-00.

## 5. Runner trust classes / Ansible handoff

| Class | Proposed Forgejo label | Boundary / network | Future owner |
| --- | --- | --- | --- |
| PR | `vaulty-pr` | Disposable PR checkout, no secrets, no host engine socket, minimal egress to approved package/scanner sources | SEC-01A |
| Heavy | `vaulty-heavy` | Separate VM or comparable isolation, time/memory caps, offline corpus, no secrets, crash artifact sanitization | SEC-01B/C |
| Image builder | `vaulty-image-build` | Protected build-from-reviewed-source; authenticated Zot write scoped only to security images; no signing secret | SEC-01A/D |
| Release | `vaulty-release` | Protected approved commits/tags only, release identity isolation, no PR code, no general-purpose login | SEC-01D |

Provision with separate Ansible roles or equivalent idempotent tasks in the homelab configuration repository (not present here). Configure runtime labels at the Forgejo runner host; declaring `runs-on` does not register any runner. Require restricted ephemeral workspaces, separate identities, scoped registry credentials, logs/metrics, backup policy for needed evidence, and verified workspace wipe. In staging, do not make a workflow a protected/required status until it executes successfully and its trust boundary is reviewed.

## 6. GitHub and Forgejo workflows

Two **manual-dispatch-only** SEC-00 readiness checks validate the JSON contract, negative tests and Bash syntax. They do not access hardware, Zot, local filesystem outside the checkout, or protected secrets; they do not run Clippy/deny/Gitleaks/Semgrep. They must never be represented as security acceptance or added to required scanner checks.

The Forgejo smoke uses the pre-existing `docker` label and an existing workflow-compatible base image, with installation of Python for the check. This is a transitional **non-trusted** smoke, not a final pin-compliant security image. Reconfigure to reviewed digest and immutable checkout action during SEC-01A before using it as a security gate. Runner availability remains unverified until observed on the real instance.

GitHub dispatch uses a GitHub-hosted runner and pinned checkout action; its run is independent of homelab infrastructure. Manual workflows on GitHub become dispatchable from the default branch only after merge.

## 7. Dedicated security environments

- `vaulty-sec-lab`: planned disposable VM for libFuzzer campaigns, Miri and sanitizer tests, no sensitive user data. Collect bounded crash corpus with source/tree commit and tool versions; scrub logs and retain only reproducing inputs.
- `vaulty-hardware-lab`: separate operator-controlled USB/hidraw test environment; use only synthetic dedicated test credentials. No automated production-token access or CI hardware operation.
- `vaulty-release-builder`: separate protected VM, disjoint identity and network policy. Signing belongs only after reviewed SEC-01D release gate.

SEC-00 does not provision these resources. Release signing identity and code-signing authority remain undefined.

## 8. Tool approval / change control

Every executable tool requires an explicit exact version, authenticated supplier source and verified SHA-256 (or reviewed equivalent with recorded artifact integrity), plus coverage/compatibility acceptance. Keep package-manager lockfiles alongside the inventory. Each image needs matching digest + artifact verification and authenticated registry access. Nightly vulnerability database updates are separate from scanner binary updates. Moved pin values must be reviewed in the owning SEC-01 PR; never fill with invented values.

CodeQL usage/licensing must be checked for this repository before automatic scanning. Do not claim CodeQL runs because the CLI is listed. Signed releases require separately verified trust policy, OIDC/issuer if used, and verifier policy.

## 9. Security evidence and acceptance

Record source SHA, clean/dirty state, tool versions, command, timestamp, exit code, environment and sanitised artifact hashes. Keep raw secrets, recovery codes, PINs, PRF outputs and privileged runner configuration out of CI artifacts. Distinguish `CONTRACT_VALID` from `SCANNER_PASS`, `CI_PASSED`, `VERIFIED` and `PRODUCTION_APPROVED`.

Acceptance register: [SEC-00 acceptance](../security/assurance/SEC-00-acceptance.md). Open blockers remain unchanged: OPEN-01, OPEN-15, G1–G3, owner UV/PRF hardware assurance decisions. Physical FIDO2 evidence remains operator-reported unless independently verified.

## 10. Deferred SEC-01 stages

- SEC-01A: install and pin static/security tools; introduce actual PR workflow, approved static OCI image and protected CI gate.
- SEC-01B: instrument real V02 codec/slot/parser/IPC fuzz targets; reproducible crash corpus and heavy runner.
- SEC-01C: threat model, OSV/CodeQL subject to eligibility, findings register and external-review handoff.
- SEC-01D: trusted release builders, SBOM, provenance, signature verification and signing policy.

**SEC-00 completion means only that reviewed preparation assets are merged and their local contract tests passed.** External runner provisioning, CI green status, hardened registry, scanners and actual release assurance require independent evidence.
