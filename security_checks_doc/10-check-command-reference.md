# SEC-01A — command reference

Run from repository root after [development-machine setup](01-development-machine.md), or from an independently provisioned `vaulty-pr` OCI job.

| Tool | Command | Notes |
| --- | --- | --- |
| SEC-00 and SEC-01A contracts | `bash scripts/security/run.sh contract` | Regression tests; **not** a security scan |
| Versions | `python3 scripts/security/check-static-versions.py` | Exact runtime versions; not proof of software provenance |
| Clippy | `cargo clippy --manifest-path Cargo.toml --locked --all-targets -- -D clippy::correctness` | Repeat for all five manifests via `run-static.sh` |
| cargo-deny | `cargo deny --manifest-path Cargo.toml --locked --config deny.toml check` | Repeated for all five lockfiles |
| Gitleaks | `gitleaks git --config .gitleaks.toml --redact --no-banner .` | Requires complete Git history |
| Semgrep | `semgrep scan --config .security/semgrep --error --metrics off src extenstion tools` | Local custom rules; security findings fail |
| ESLint | `npm run lint:js` | Exact dev dependency, npm ci first |
| web-ext | `npm run lint:firefox` | Mozilla extension compatibility and manifest checks |
| All candidate checks | `bash scripts/security/run.sh static-pr` | Exit nonzero if any check/tool fails |
| Local OCI build | `bash scripts/security/build-static-image.sh "$RUST_BASE" "$NODE_BASE" localhost/vaulty/security-static:sec01a` | Base images must use audited `@sha256` references |

Exit codes: 0 means the tool executed and passed in the tested environment; 78 means incomplete/not configured, never PASS. Scanner-specific nonzero codes must propagate. `run.sh pr` (without `static-` prefix) is still intentionally unconfigured pending protected Forgejo enforcement.

SEC-01B/C/D own fuzzing, Miri, deep threat modeling, SBOM signing and release workflows.
