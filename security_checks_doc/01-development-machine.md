# Development machine — Ubuntu/Debian x86_64

## Preparation

Requirements: Git, Python 3 with venv, `curl`, `tar`, `sha256sum`, `rustup`, Rust/Cargo, Node.js 22 and npm. The existing SEC-00 script installs OS build prerequisites, not Rust or security tools. Keep local security tooling separate from vault secrets and real FIDO2 credentials.

```bash
git clone https://github.com/BetrayedByEthanol/Pw_Manager.git
cd Pw_Manager
git checkout sec/sec01a-static-security-foundation
bash scripts/security/bootstrap-dev.sh --profile minimal --plan
bash scripts/security/bootstrap-dev.sh --profile minimal --apply --confirm
# Install rustup through its verified official distribution if not already installed.
rustup toolchain install 1.99.1 --profile minimal --component clippy
rustup default 1.99.1
# Node.js 22 needs a separate trusted package source if not installed.
node --version
npm --version
```

## Candidate tool installation

```bash
bash scripts/security/install-static-tools.sh --plan
bash scripts/security/install-static-tools.sh --apply --confirm --candidate
export PATH="$HOME/.local/bin:$HOME/.local/share/vaulty/sec01a-venv/bin:$PWD/node_modules/.bin:$PATH"
python3 scripts/security/check-static-versions.py
bash scripts/security/run.sh contract
```

The explicit `--candidate` flag acknowledges that the temporary development environment contains dependencies without complete upstream transitive hash approval. This is **not** permitted for protected release or privileged CI.

The script SHA-256 verifies upstream **cargo-deny** and **Gitleaks** archives against committed GitHub release digests; uses a dedicated venv for **Semgrep==1.184.0**; and `npm ci --ignore-scripts` for **ESLint** and **web-ext** using the committed npm lockfile. The entire transitive Semgrep PyPI dependency tree is **not yet hash locked**; consider this a candidate installation, not release assurance. Never run an unsigned bootstrap via `curl | bash`.

## Commands

```bash
bash scripts/security/run.sh static-pr             # all six real checks
bash scripts/security/run.sh static-quick          # Clippy, Semgrep, browser
bash scripts/security/run.sh static-dependencies   # cargo-deny x five manifests
bash scripts/security/run.sh static-sast           # Clippy + Semgrep
bash scripts/security/run.sh static-secrets        # full-history Gitleaks
bash scripts/security/run.sh static-browser        # ESLint + web-ext
bash scripts/security/run.sh rust-baseline         # all five locked checks/tests
```

`run.sh pr` and `run.sh release-verify` from SEC-00 intentionally fail closed until their separate deployment gates are approved; use `static-pr` to perform actual candidate scans. A nonzero scanner exit must not be hidden or replaced with `|| true`.

## Troubleshooting

- `SEC01A_TOOL_NOT_READY`: install/add the missing program to PATH or correct its exact version; do not bypass the check.
- `SEC01A_NO_GIT_HISTORY` / `SEC01A_SHALLOW_GIT_HISTORY`: clone/fetch the full Git history, then rerun secrets.
- `SEC01A_NODE_MODULES_MISSING`: use `npm ci --ignore-scripts`, not `npm install`, to preserve the committed lockfile.
- `SEC01A_LOCK_MISSING`: all five independent Cargo manifests need their own committed `Cargo.lock`.
- Semgrep/Firefox lint findings should be triaged by location and evidence; never apply blanket rule exclusions to obtain a green badge.
- CI needs outbound access to crates/advisory sources for cargo-deny's vulnerability database. A network failure is **INCOMPLETE**, not PASS.

Local tool installation is user-owned; a development-machine setup plan does not assert a privileged package installation occurred on any host.

### cargo-deny 0.20.2 archive and policy verification

The pinned `cargo-deny-0.20.2-x86_64-unknown-linux-musl.tar.gz` contains the **nested** member `cargo-deny-0.20.2-x86_64-unknown-linux-musl/cargo-deny`. The installer and OCI build both call `scripts/security/extract-static-tool.sh`, which extracts **only** this member after verifying the release archive digest; Gitleaks retains its top-level member. Avoid extracting every member or assuming a flat cargo-deny archive.

```bash
cargo deny --version                    # must report 0.20.2
cargo deny --config deny.toml --manifest-path tools/security_probes/rust/Cargo.toml --locked check bans
cargo deny --config deny.toml --manifest-path tools/security_probes/rust/Cargo.toml --locked check sources
```

The `[advisories] unmaintained = "workspace"` setting is a **scope** supported by cargo-deny 0.20.2: unmaintained direct dependencies fail; transitive-only unmaintained advisories are not included in that gate. Do not use `"warn"`, which is not a supported value. TOML parsing alone is insufficient: the real pinned cargo-deny CLI must parse this configuration.
