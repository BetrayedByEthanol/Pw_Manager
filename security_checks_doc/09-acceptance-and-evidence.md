# SEC-01A — acceptance and evidence

Do not equate **CODE PRESENT**, **CI EXECUTED**, **REVIEWED**, and **ENFORCED**.

| Gate | Acceptance condition | Initial SEC-01A source status |
| --- | --- | --- |
| A01 | All six static command paths execute real checks | VERIFIED on GitHub manual run 43095040536; Forgejo pending |
| A02 | Five Rust manifests checked by Clippy and cargo-deny | VERIFIED on GitHub manual run 43095040536 |
| A03 | npm lockfile committed and `npm ci` enforced | SOURCE IMPLEMENTED |
| A04 | cargo-deny/Gitleaks upstream release digests verified | VERIFIED hosted installation / version check; developer-host installation pending |
| A05 | Developer machine bootstrap and exact version check | SOURCE IMPLEMENTED; clean-host evidence pending |
| A06 | OCI image built against reviewed base digests, tested and scanned | NOT EXECUTED; publication blocked |
| A07 | Isolated Forgejo `vaulty-pr` runner registered, workflow green | NOT PROVISIONED |
| A08 | Actual Forgejo required check enforced by branch protection | NOT CONFIGURED |
| A09 | GitHub manual-only workflow executed independently | VERIFIED run 43095040536 on main SHA 979f7d5; not a protected PR check |
| A10 | Renovate bot connected using restricted account | NOT CONNECTED; optional operational follow-up |
| A11 | Open findings dispositioned with no blanket suppressions | FIRST INTAKE COMPLETE; Firefox privacy and dependency-hygiene warnings open |
| A12 | Semgrep transitive wheel hashes and approved image/supply-chain evidence | STILL OPEN |

Record every CI/lab run's source SHA, environment, tool versions, command, exit code, timestamp, redacted findings, image digest (where relevant), and limitations. A missing dependency or stale external advisory feed is a failed/incomplete run, never an accepted PASS.

Use `docs/security/assurance/SEC-01A-acceptance.md` for the authoritative ledger. Add future findings to the central security register with issue ID, severity, affected file and accepted disposition; no user credentials or raw scanner secrets in the repository.

Rollback: disable the new required Forgejo status check (only if outage necessitates and under change control), revert the reviewed PR, switch runner to previous approved OCI digest, and document the temporary assurance reduction. Never silently continue releasing without checks.

## First verified execution

See [first scan evidence and browser lint triage](11-first-scan-firefox-compatibility.md). GitHub's manual hosted scan on 2026-11-11 ran all six tools successfully; this changes the **CI EXECUTED** status only. A reviewed no-data declaration and Forgejo enforcement remain separately gated.
