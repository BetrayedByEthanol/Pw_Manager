# Vaulty security checks — locations and execution runbooks

SEC-01A introduces runnable static checks, but **infrastructure acceptance is separate from a green scanner**. Check the PR evidence before treating any Forgejo runner, image, signing environment or branch gate as operational.

| Location / task | Setup / runbook |
| --- | --- |
| Development machine setup and test commands | [01-development-machine.md](01-development-machine.md) |
| Git repository and policy/lock files | [02-repository.md](02-repository.md) |
| Rootless Podman, building the security image, Zot publishing | [03-container-and-zot.md](03-container-and-zot.md) |
| Forgejo/Gitea Actions runner registration and isolation | [04-forgejo-runner.md](04-forgejo-runner.md) |
| Forgejo Actions workflow, review evidence and enforcement | [05-forgejo-workflows.md](05-forgejo-workflows.md) |
| Lightweight, **manual-only** GitHub Actions | [06-github-actions.md](06-github-actions.md) |
| Independent lab, physical FIDO2 and scheduled security tests | [07-security-lab.md](07-security-lab.md) |
| Renovate setup, bot permissions and update PR review | [08-renovate.md](08-renovate.md) |
| Acceptance gates, finding review, rollback and evidence | [09-acceptance-and-evidence.md](09-acceptance-and-evidence.md) |
| Exact command reference by check | [10-check-command-reference.md](10-check-command-reference.md) |

## Scope and status

- SEC-00's machine-readable lockfile, approval, and fail-closed controls remain authoritative for release/production.
- SEC-01A adds a candidate static scanner runner and scripts for Clippy, cargo-deny, Gitleaks, Semgrep, ESLint and web-ext.
- Lockfile and artifact SHA-256 verification are mandatory for publishing an approved OCI image. The first image and Forgejo runner are **not published or provisioned by source changes**.
- Existing `extenstion/` spelling and five standalone Cargo manifests are preserved.
- No real credentials, PRF outputs, recovery codes, hardware tokens or signing keys may enter ordinary CI. OPEN-01/OPEN-15/G1–G3 remain blocked.
- Gitea's compatible workflow mechanism may be used after testing; these paths and runbooks target Forgejo, the source-of-truth CI.
