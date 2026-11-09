# SEC-01A — Static security findings register

**Initial state: BASELINE NOT COLLECTED.** No scan result, finding count or severity is asserted until all six real checkers have executed against a pinned commit in an identified environment.

| Finding ID | Scanner | File/component | Severity | Evidence commit/job | Disposition | Owner | Due |
| --- | --- | --- | --- | --- | --- | --- | --- |
| (none recorded yet) | — | — | — | — | NOT_EXECUTED | — | — |

## Intake requirements

After the first full `static-pr` run, record each finding individually (or as a justified, bounded cluster), assign severity and owner, link to a redacted report/commit and choose `OPEN`, `FALSE_POSITIVE_WITH_EVIDENCE`, `ACCEPTED_RISK_WITH_EXPIRY`, or `FIXED_AND_REGRESSION_TESTED`. A failed tool download, offline advisory database, or missing runner is **INCOMPLETE**, not an empty findings list.

Do not add blanket Semgrep, cargo-deny, ESLint or Gitleaks suppression rules to force a green build. Approved exemptions must be narrow, documented and reviewed before enforcement. Do not store leaked secret contents or unredacted Gitleaks output in Git or CI artifacts.

## SEC-01A initial evidence

- Upstream cargo-deny 0.20.2 and Gitleaks 8.30.1 release asset digest metadata recorded; **local installation verification pending**.
- npm `package-lock.json` committed after GitHub CI-generated dependency resolution; temporary npm CI lint result passed (link to specific run in PR if required).
- Existing security-probes regression job and V02 checks may pass; neither represents a completed six-tool static security scan.
- Forgejo `vaulty-pr` runner, TLS Zot security image and branch protection have **not** been verified.

## Codex review corrections — P1/P2 (2026-11-09)

- **P1 archive layout — fixed in candidate source:** Shared `scripts/security/extract-static-tool.sh` extracts the exact nested cargo-deny 0.20.2 member with one directory component stripped. Both native installer and OCI Containerfile call the helper. Python regression tests simulate cargo-deny's nested archive, Gitleaks' flat archive, and the malformed flat cargo-deny case.
- **P2 unmaintained setting — fixed in candidate source:** `deny.toml` specifies `unmaintained = "workspace"` (valid cargo-deny 0.20.2 enum), so unmaintained direct dependencies fail. The former `"warn"` value was invalid. Regression tests require the exact scope.
- **Pinned binary validation:** A review-only GitHub CI probe is used to download the *SHA-256-verified* cargo-deny 0.20.2 release and execute the dependency configuration. Until a successful run is recorded at the final commit, treat real binary validation as **PENDING**, not PASS. This review-only workflow is to be removed before merge to preserve the manual-only GitHub static scan policy.
