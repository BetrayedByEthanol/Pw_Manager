# CI: GitHub Actions and Forgejo Actions

Vaulty has two equivalent verification workflows on each platform:

| Verification | GitHub | Forgejo |
| --- | --- | --- |
| V01 Rust binary, native host, browser configuration | `.github/workflows/v01-product-safety.yml` | `.forgejo/workflows/v01-product-safety.yml` |
| Security-probe reference tests and vectors | `.github/workflows/vaulty-security-probes.yml` | `.forgejo/workflows/vaulty-security-probes.yml` |

The V01 pipeline checks the root crate and native host with locked Rust dependencies, and validates browser JSON/JavaScript syntax. Linux native build dependencies include PC/SC development headers required by `pcsc-sys`. These checks do **not** certify Vaulty for storing real secrets or exercise hardware-bound YubiKey operations.

## Forgejo cutover

1. Mirror the repository to Forgejo and enable Actions for that repository.
2. Register a **container-capable** Forgejo runner that advertises the `docker` label. The workflow uses `node:22-bookworm` job containers so the checkout action has Node; Rust is installed inside the Rust jobs. Allow access to Debian package mirrors, rustup, crates.io, and the Forgejo action source.
3. Run **both** Forgejo workflows manually first, then verify push and pull-request triggers, job results, and branch-protection required checks before switching any required status checks away from GitHub.
4. Retire GitHub Actions only after equivalent Forgejo checks are passing and are enforced on the source-of-truth repository. Do not configure deploy credentials in these verification jobs.

Forgejo prioritizes `.forgejo/workflows` over `.github/workflows`; keeping both mirrors ensures both verification suites are discoverable. The `runs-on: docker` label is a runner configuration requirement, **not** a promise that a runner is already installed.

The Forgejo reference probe job uses Debian's Python 3 provided in the job image, whereas GitHub pins Python 3.13. If exact Python-version equivalence becomes a release gate, pin a Forgejo Python 3.13 environment before cutover.

CI configuration has been added for later use; a successful Forgejo execution remains unverified until a runner is connected.

## SEC-00 security infrastructure preparation (proposal)

See [SEC-00 runbook](SEC-00-security-infrastructure.md) and [acceptance](../security/assurance/SEC-00-acceptance.md). SEC-00 adds separate **manual-only** contract smoke checks at `.forgejo/workflows/sec00-readiness.yml` and `.github/workflows/sec00-readiness.yml`; these do **not** scan dependencies, inspect secrets, validate signing, use physical FIDO2, or establish trusted runner readiness. The existing build and security-probe workflows remain separate. Forgejo `docker` runner availability and the provisional smoke container must still be verified; SEC-01A will add digest-pinned scanner images and genuinely blocking PR checks.
