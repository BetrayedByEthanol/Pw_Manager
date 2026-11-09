# SEC-01A — Static Security Foundation acceptance (candidate)

**PR #31, not merged; source and documentation candidate.** No Forgejo runner, image, TLS registry, protected branch check or Renovate bot is assumed operational. Tools must be executed and their findings reviewed before changing this disposition.

See the complete per-location runbooks in [security_checks_doc](../../../security_checks_doc/README.md).

- SOURCE: tool versions, binaries' verified upstream digests, lint configs, 5-crate scripts, npm locked graph, OCI build contract, Forgejo/GitHub workflow source and Renovate bot configuration.
- NOT EXECUTED: workstation installation, custom image creation/publication, Forgejo runner, manual GitHub workflow (requires default-branch merge), actual static security scans and reviewed findings.
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
