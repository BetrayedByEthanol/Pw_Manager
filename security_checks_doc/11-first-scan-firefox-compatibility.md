# SEC-01A-OPS-01 — First scan and Firefox compatibility triage

## Verified baseline (not a protected Forgejo gate)

- Evidence: [GitHub manual static security run #43095040536](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/43095040536), job `130781583138`, completed successfully on 2026-11-11.
- Source: `main`, commit `979f7d5f5c188a6d7d46353a5b66dcf7d24cc2cb`.
- Command: `bash scripts/security/run.sh contract` and `bash scripts/security/run.sh static-pr` on GitHub-hosted Ubuntu 24.04. This is real scanner execution, not a mock or a production security approval.
- Toolchain: rustc 1.99.1, Clippy 0.1.99, cargo-deny 0.20.2, Gitleaks 8.30.1, Semgrep 1.184.0, Node 22, ESLint 10.14.0, web-ext 10.8.0.
- Results: 41/41 source contract tests; Clippy and cargo-deny each ran for **five** standalone Rust manifests; Semgrep **five rules over 102 tracked files, zero findings**; Gitleaks **626 commits, zero leaks**; ESLint passed; web-ext **zero errors, three warnings**.
- cargo-deny advisories, bans, licenses and sources all returned OK for each manifest, with nonfatal duplicate-crate and license-not-encountered warnings. These are recorded for dependency hygiene; they are not evidence of confirmed vulnerabilities.

## Browser and scanner warning disposition

| Check | Finding | Disposition |
| --- | --- | --- |
| Firefox web-ext | `ICON_SIZE_INVALID`: image advertised as 48×48 was actually 512×512 | Corrected and verified: resampled the existing asset to 48×48; IHDR/CRC regression passed and pinned web-ext 10.8.0 no longer reports `ICON_SIZE_INVALID` in run 43169921377. |
| Semgrep | Path `extenstion/*.js` will change interpretation under Semgrepignore v2 | Corrected and verified: each affected rule uses root anchor `/extenstion/*.js`; pinned Semgrep 1.184.0 ran 5 rules on 102 files with no path-compatibility warnings or findings in run 43169921377. No rule was disabled. |
| Firefox web-ext | `BACKGROUND_SERVICE_WORKER_IGNORED` | **Expected cross-browser difference, retained.** Manifest V3 declares both `background.scripts` (Firefox event page) and `background.service_worker` (Chromium worker). Removing either would break one engine. Document warning and test both browsers rather than suppressing it globally. |
| Firefox web-ext | `MISSING_DATA_COLLECTION_PERMISSIONS` | **Open: browser privacy disclosure decision required before Firefox distribution.** No unreviewed `required: ["none"]` declaration is added to the manifest. |

## Privacy disclosure review — required before Mozilla Add-ons publication

Mozilla's [built-in data consent documentation](https://extensionworkshop.com/documentation/develop/firefox-builtin-data-consent/) requires new Firefox extensions to declare data categories in `browser_specific_settings.gecko.data_collection_permissions`. Data use/transmission outside the extension or local browser is in scope, **including native app transfers**. An extension that really transmits no personal data may use `required: ["none"]`, but that cannot be presumed for Vaulty.

Relevant source paths for the audit:

| Source | Data flow to review |
| --- | --- |
| `extenstion/nativeBridge.js` | `sendNativeMessage` to `com.vaulty.native_host`; includes active-tab origin; `SAVE_CREDENTIAL` request may include authentication fields; `RETRIEVE_CREDENTIAL` and `GENERATE_PASSWORD` relay requests |
| `extenstion/host/src/main.rs` | Native request validation; currently responds `UNAVAILABLE` after validation, but the browser can still send origin/credential fields to this executable |
| `extenstion/content.js` and `extenstion/background.js` | Website selectors, field metadata and origin-local site mappings; distinguish browser-local storage from actual native transmission |
| `extenstion/manifest.json` | `nativeMessaging`, `<all_urls>`, and both browser background modes |

Review exact native message payloads and whether each field is required versus optional. Candidate categories requiring assessment include `authenticationInfo`, `browsingActivity`, `websiteContent`, and `websiteActivity`; **none is approved by this runbook**. Decide categories and consent behavior, including supported older Firefox versions, in a separate privacy-reviewed change. Record reviewer and supporting data-flow evidence, then rerun `web-ext lint`.

## Recheck after PR

```bash
bash scripts/security/run.sh contract
bash scripts/security/run.sh static-browser
bash scripts/security/run.sh static-sast
# Additional Firefox smoke in an isolated browser profile:
npx web-ext run --source-dir extenstion --ignore-files 'host/**'
```

Smoke-test Firefox's event-page behavior and Chromium's extension service-worker behavior with synthetic requests; do not store real passwords, recovery codes or PRF outputs. The initial first-scan results **do not prove both browsers worked at runtime**.

## Deployment boundary

The manual hosted GitHub scan does **not** register a Forgejo `vaulty-pr` runner, build/publish the verified OCI security image, enable a required status check, approve Semgrep transitive wheel provenance, or establish cryptographic release assurance. See [SEC-01A acceptance](../docs/security/assurance/SEC-01A-acceptance.md) for the remaining operator steps.

## Post-change verification evidence

[Temporary GitHub PR verification run #43169921377](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/43169921377) at branch SHA `91a128eeb8db6cc7475b25df3901fe21b6bffb2e` succeeded:

- **45/45** SEC-00/SEC-01A regression tests, including binary PNG IHDR and CRC.
- `npm ci` and pinned `web-ext 10.8.0`: **0 errors, 2 warnings**, down from 3.
- Pinned `Semgrep 1.184.0`: valid config; five rules on 102 tracked files; **0 findings**; the old path warning is absent.
- Only the privacy-consent decision and the documented Firefox service-worker difference remain. Neither is bypassed by disabling lint checks.

The temporary PR-trigger workflow was deleted after successful verification to preserve SEC-01A's manual-only permanent GitHub static scanner policy.
