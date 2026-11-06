# V01 — Prototype Safety & Build Foundation
**Status:** Implemented safety patches pending CI and code review. **Not** a v0.4.5 production key hierarchy or secure release.

## Intent
- Establish a compiling binary and deterministic regression tests, including native-host validation.
- Eliminate secret-bearing debug output and environment-variable master password/PIN fallback.
- Eliminate outer AEAD nonce reuse on repeated seals (both historical binary and JSON proof-of-concept).
- Verify FIDO2 attestation/assertion results before using hardware PRF values.
- Make binary body count and length validation strict; fail closed for unsupported client records.
- Preserve the previous vault generation and fsync temporary/backup/parent directory on writes. A stale single-writer lock requires deliberate intervention.
- Keep the default executable explicitly non-operational; it must not quietly initialize or reveal credentials.

## Deliberate V01 limitations
- Legacy password-only creation **fails closed** because the virtual FIDO2 provider does not exist. Support belongs to V03.
- Entry updates and master-password rotation **fail closed** until policy-bound, independently reviewed rewrapping exists.
- Legacy header/body parsing still needs full authenticated-format replacement and fuzzing in V02.
- No entry-specific hardware PRF per read, recovery slot provisioning, VERS masking, trusted daemon, end-to-end extension channel, or S4 ancestry has been implemented.
- A successful legacy regression test does **not** certify recovery, migration, or safety for real credentials. Existing vault files require a dedicated safe migration; never silently rewrite unknown formats.
- The native host is still a mock. Its demo credential replies are not production authentication.
- V01 intentionally does **not** merge open security-probe PR #1 or declare OPEN-01/15 cryptographically approved.

## Evidence and remaining gates
- GitHub CI should check the root crate, the native host, and browser script/manifest syntax.
- Introduce executable integration tests for canonical VMK/DEK, virtual provider, 4 entry modes, transaction atomicity, crash injection, and recovery under V02–V04.
- Rust application is **not fit for storing real secrets** even when this V01 PR builds.
