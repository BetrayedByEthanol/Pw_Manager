# SEC-01A — Static security findings register

**First baseline collected:** Manual GitHub full scan [run #43095040536](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/43095040536) passed for `main` SHA `979f7d5f5c188a6d7d46353a5b66dcf7d24cc2cb`. This confirms scanner execution, **not** warning-free review, protected Forgejo enforcement, or product/crypto approval.

| Finding ID | Scanner | File/component | Severity | Evidence commit/job | Disposition | Owner | Due |
| --- | --- | --- | --- | --- | --- | --- | --- |
| OPS01-BROWSER-ICON | web-ext `ICON_SIZE_INVALID` | `extenstion/icons/icon48.png` | Low / compatibility | Run 43095040536 | FIXED_IN_PR — needs post-change lint | Browser | Before Firefox package release |
| OPS01-BROWSER-CONSENT | web-ext `MISSING_DATA_COLLECTION_PERMISSIONS` | `extenstion/manifest.json`, native-message flow | Medium / release compliance | Run 43095040536 | OPEN_PRIVACY_REVIEW — no `none` assertion | Security/privacy | Before Firefox distribution |
| OPS01-BROWSER-BG | web-ext `BACKGROUND_SERVICE_WORKER_IGNORED` | `extenstion/manifest.json` | Info / cross-browser | Run 43095040536 | DOCUMENTED_EXPECTED — Firefox uses scripts, Chromium uses worker | Browser | Smoke-test both engines |
| OPS01-SEMGREP-PATH | Semgrep anchored path warning | `.security/semgrep/vaulty-browser.yml` | Low / future compatibility | Run 43095040536 | FIXED_IN_PR — needs post-change scan | Security tooling | Before next scanner pin |
| OPS01-CARGO-DUPLICATES | cargo-deny `warning[duplicate]` | 5 independent Rust lockfiles | Low / dependency maintenance | Run 43095040536 | OPEN_TRIAGE — no blanket suppression | Dependencies | Scheduled review |
| OPS01-LICENSE-ALLOW | cargo-deny `warning[license-not-encountered]` | `deny.toml` / Rust manifests | Info / policy hygiene | Run 43095040536 | OPEN_TRIAGE — approved license list retained | Security policy | Scheduled review |

## Intake requirements

After the first full `static-pr` run, record each finding individually (or as a justified, bounded cluster), assign severity and owner, link to a redacted report/commit and choose `OPEN`, `FALSE_POSITIVE_WITH_EVIDENCE`, `ACCEPTED_RISK_WITH_EXPIRY`, or `FIXED_AND_REGRESSION_TESTED`. A failed tool download, offline advisory database, or missing runner is **INCOMPLETE**, not an empty findings list.

Do not add blanket Semgrep, cargo-deny, ESLint or Gitleaks suppression rules to force a green build. Approved exemptions must be narrow, documented and reviewed before enforcement. Do not store leaked secret contents or unredacted Gitleaks output in Git or CI artifacts.

## SEC-01A initial evidence

- Pinned cargo-deny 0.20.2 and Gitleaks 8.30.1 executed in GitHub hosted workflow #43095040536; developer machine installation remains independently unverified.
- npm `package-lock.json` committed after GitHub CI-generated dependency resolution; temporary npm CI lint result passed (link to specific run in PR if required).
- The actual `static-pr` suite passed on the manual GitHub run: Clippy and cargo-deny each checked all 5 Rust manifests; Semgrep scanned 102 tracked files with 0 findings; Gitleaks scanned 626 commits with 0 leaks; ESLint passed; web-ext returned 3 warnings.
- Forgejo `vaulty-pr` runner, TLS Zot security image and branch protection have **not** been verified.

## Codex review corrections — P1/P2 (2026-11-09)

- **P1 archive layout — fixed in candidate source:** Shared `scripts/security/extract-static-tool.sh` extracts the exact nested cargo-deny 0.20.2 member with one directory component stripped. Both native installer and OCI Containerfile call the helper. Python regression tests simulate cargo-deny's nested archive, Gitleaks' flat archive, and the malformed flat cargo-deny case.
- **P2 unmaintained setting — fixed in candidate source:** `deny.toml` specifies `unmaintained = "workspace"` (valid cargo-deny 0.20.2 enum), so unmaintained direct dependencies fail. The former `"warn"` value was invalid. Regression tests require the exact scope.
- **Pinned binary validation — VERIFIED on review commit `56ab84eda38d37fd00187563637b7c5730fa9df5`:** GitHub [review workflow run 42610908904](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42610908904) verified the cargo-deny 0.20.2 release SHA-256, extracted its exact nested archive member, ran `cargo-deny --version`, and executed real `cargo deny --locked check bans` and `check sources` against the security-probes manifest with the corrected policy. It also passed the SEC-01A archive/policy regression tests. The first real CLI run exposed a second 0.20.2 removed key, `licenses.unlicensed`, which was then deleted; the cited green run includes that correction. **This is configuration/package-smoke evidence only**: it is not a full six-tool scan, advisory database review, Forgejo run or production approval. The temporary PR-trigger review workflow is removed before merge to preserve the manual-only GitHub static check policy.

## Evidence scope and disposition

The first full scanner run is complete, but **zero blocking findings does not mean zero warnings**. All Firefox warnings and representative cargo-deny / Semgrep warnings are tracked above rather than suppressed. The same scan's success cannot prove browser runtime behavior, the correctness of future credentials handling or physical FIDO2 guarantees.

See [SEC-01A-OPS-01 Firefox triage](../../../security_checks_doc/11-first-scan-firefox-compatibility.md) for Mozilla policy links, actual native-message flows, and required post-change rechecks. No `browser_specific_settings.gecko.data_collection_permissions` declaration is added until a product/security reviewer approves the categories and whether disclosure is required. Treat this privacy decision as a **Firefox distribution blocker**, not as a scanner failure.
