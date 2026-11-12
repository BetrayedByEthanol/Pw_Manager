# SEC-01A — Static Security Foundation acceptance (candidate)

**SEC-01A source merged; first manual full static scan verified.** [GitHub Actions run #43095040536](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/43095040536) passed on `main` at SHA `979f7d5f5c188a6d7d46353a5b66dcf7d24cc2cb`. No Forgejo runner, trusted OCI image, TLS Zot registry, protected branch check or Renovate bot is assumed operational.

See the complete per-location runbooks in [security_checks_doc](../../../security_checks_doc/README.md).

- SOURCE: tool versions, binaries' verified upstream digests, lint configs, 5-crate scripts, npm locked graph, OCI build contract, Forgejo/GitHub workflow source and Renovate bot configuration.
- VERIFIED IN HOSTED GITHUB CI: first manual six-tool static scan at the source SHA above; 41/41 contract tests, five Rust manifests each for Clippy and cargo-deny, Semgrep (5 rules, 102 tracked targets, 0 findings), Gitleaks (626 commits, 0 leaks), ESLint success and web-ext (0 errors, 3 warnings). See [OPS-01 triage](../../../security_checks_doc/11-first-scan-firefox-compatibility.md).
- NOT VERIFIED OPERATIONALLY: clean development-machine installation, custom OCI image build/publication, Forgejo runner, branch protection, local Firefox/Chromium runtime tests, and completed browser privacy declaration.
- NOT APPROVED: cryptographic protocol OPEN-01/OPEN-15, G1–G3 release gates, protected PR enforcement or signed production releases.
- FOLLOW-UP: review Semgrep transitive PyPI wheel hashes; pin OCI base digests with independent provenance; validate the runner and branch protection; record full first-run results in this ledger.

## CI / PR acceptance

Contract/negative-path tests should run on the GitHub mirror's existing security-probes CI; they do not replace Forgejo scanner execution. The SEC-01A Forgejo job uses the dedicated `vaulty-pr` label, not the generic `docker` runner. A queued job is incomplete. The GitHub security scan is `workflow_dispatch` only and cannot be counted as a default pull-request gate.

For acceptance, capture the source SHA, script/tool/image digest, redacted logs, exit code, Forgejo job reference, exact branch protection rule and reviewer disposition. Do not close SEC-01A or promote scanner results to crypto security certification until the required evidence exists.

## Source-verification references (not first six-tool scan)

- The temporary [npm lockfile/lint verification workflow](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42605944418) completed successfully: resolved `package-lock.json`, ran `npm ci --ignore-scripts`, ESLint and web-ext. Its temporary PR-trigger workflow source has since been removed; the final GitHub SEC-01A workflow is manual-only.
- GitHub's existing security-probes CI has executed `bash scripts/security/run.sh contract` on the SEC-01A branch, covering the source-level negative/contract tests. Preserve the exact latest SHA and run URL when deciding merge.
- V01/V02 workflows still run on PR updates; these check previous product/candidate foundations and **do not** establish SEC-01A six-tool run acceptance.

### Remaining operator configuration before mandatory enforcement

1. On a clean workstation, run the candidate installation plan, explicit opt-in install, version checker and `static-pr` checks; triage all findings.
2. Build `Containerfile.static` with independently reviewed, immutable Rust and Node base-image digests; prove container tools and dependency/advisory freshness. Review/pin Semgrep transitive wheel hashes before classifying the image as trusted.
3. Harden Zot to authenticated TLS, build and publish the reviewed OCI image; independently verify the image digest and vulnerability/SBOM evidence.
4. Provision the isolated Forgejo `vaulty-pr` runner; run the SEC-01A workflow on the exact approved SHA and record the outcome.
5. Turn on Forgejo's required status-check protection **only after** it passes on the intended runner. Manually run GitHub's independent fallback after merge; optionally deploy the Renovate bot with least-privilege permissions and reviewed version/image.

## Codex P1/P2 corrections to the candidate setup

The development installer and OCI source share the exact-member archive extraction helper so cargo-deny's versioned parent directory is handled safely. `deny.toml` now uses cargo-deny 0.20.2's supported `unmaintained = "workspace"` scope. Behavioral archive-layout tests and configuration assertions were added. **The real pinned scanner must still execute successfully on a reviewed commit**; a Python TOML parser is not enough. Archive and config acceptance is separate from OCI publication, Forgejo runner provisioning or production approval.

### Codex P1/P2 real-binary evidence

[GitHub review run #42610908904](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42610908904) passed at SHA `56ab84eda38d37fd00187563637b7c5730fa9df5`: SHA-256-verified cargo-deny 0.20.2 archive download, nested binary extraction, `--version` and actual `--locked check bans`/`check sources` parsing of `deny.toml`, plus 41 Python contract/negative-path tests. In the initial probe, cargo-deny also rejected the removed `licenses.unlicensed` key; this key was removed before the green run. Source checks and packaging smoke **do not** certify the full PR static scanner suite or external Forgejo/OCI infrastructure.

## SEC-01A-OPS-01 — First full static scan evidence intake (2026-11-12)

| Evidence | Verified result |
| --- | --- |
| Source | `main`, SHA `979f7d5f5c188a6d7d46353a5b66dcf7d24cc2cb` |
| [GitHub manual workflow](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/43095040536) | Run `43095040536`, job `130781583138`, successfully completed (2026-11-11 UTC) |
| SEC-00 / SEC-01A contracts | 41 tests passed; fail-closed inventory remains `PREPARATION_ONLY` |
| Rust | Clippy + cargo-deny ran across five standalone Cargo manifests and succeeded |
| Semgrep | 5 rules; 102 tracked files; 0 findings; path-anchor compatibility warnings |
| Gitleaks | 626 Git commits scanned; 0 leaks detected |
| Browser tooling | ESLint passed; Mozilla web-ext: 0 errors, 3 warnings |
| cargo-deny warnings | Multiple package-version duplicates and unused license allowances; dependency hygiene review remains open |
| Product security approval | **Not granted.** OPEN-01/OPEN-15, G1–G3 and protected Forgejo deployment still outstanding |

Firefox warnings were **not** globally suppressed. This follow-up PR corrects the 48×48 icon and Semgrep path anchors, preserves the dual-engine background manifest, and leaves `MISSING_DATA_COLLECTION_PERMISSIONS` explicitly open pending privacy audit of native messaging. See the [first-scan and Firefox triage runbook](../../../security_checks_doc/11-first-scan-firefox-compatibility.md) and [findings register](SEC-01A-findings.md). New source changes require a separate post-change run before their fixes can be marked validated.
