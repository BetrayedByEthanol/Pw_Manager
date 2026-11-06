# V01 — Prototype Safety & Build Foundation
**Status:** **Source merged and GitHub CI passing** (PR #4 + PR #5 on `main` at `7c3ba719`); **security acceptance still open** pending V01-A and review evidence. **Not** a v0.4.5 production key hierarchy or secure release.

> V01 evidence: [merged main V01 workflow](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42217284380), [security reference probes](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42217284398). The first includes 11 root Rust tests; the native-host crate currently has no behavioral tests. See [acceptance register](acceptance-register.md) and [next-stage roadmap](implementation.md).

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
- Security-probe PR #1 has now been merged as a **reference checker**; OPEN-01 and OPEN-15 remain **unapproved** cryptographic/device protocol reviews.

## Evidence and remaining gates
- GitHub CI now checks root crate, native-host compilation and browser syntax on merged main. Native-host behavioral tests and failure-path security acceptance remain outstanding.
- Introduce executable integration tests for canonical VMK/DEK, virtual provider, 4 entry modes, transaction atomicity, crash injection, and recovery under V02–V04.
- Rust application is **not fit for storing real secrets** even when this V01 PR builds.

## Post-merge acceptance follow-up (V01-A)

- Remove/isolate remaining experimental master-key-dump and destructive helpers in `src/util/gocrypt.rs` from compiled code paths.
- Default native host must stop reporting mock unlock/retrieve/save success; add native-host behavioral/negative tests.
- Add fail-closed executable smoke test, filesystem fault-injection and documented stale-lock recovery; keep legacy header/payload rewrite in V02.
- Preserve the disabled default application and never use it for real credentials.

See [V01-A in the implementation roadmap](implementation.md#d-proposed-next-pr-v01-a--security-closure--verification-hardening) and [current evidence](acceptance-register.md).
