# Vaulty native messaging host — fail-closed V01-A stub

The installed host is **not an operational password manager and not an encrypted daemon relay**. It accepts one native-messaging frame, validates the request shape and returns a framed `RELAY_ERROR` with `error.code=UNAVAILABLE` for every currently recognized operation:

- `GENERATE_PASSWORD`, `RETRIEVE_CREDENTIAL`, `SAVE_CREDENTIAL`
- `CHECK_LOCK_STATE`, `CHECK_DUPLICATE_CREDENTIAL`

The default binary **never** returns mock passwords, synthetic success receipts, `locked: false` or successful credential storage. A malformed/oversized/truncated input frame returns a generic error with a nonzero process exit. Validation is only syntactic; browser-supplied origin is **not** proof of authorization.

Run `cargo test --manifest-path extenstion/host/Cargo.toml --locked --all-targets` for unit-level and child-process native stdio tests. Tests use only synthetic credentials, with no production-accessible mock toggle.

A real host must forward opaque E2E ciphertext to a trusted Vaulty daemon after separately reviewed pairing, replay, identity and origin/gesture binding (V07). Do not wire this stub into any workflow that expects real passwords or durable writes.

See [V01-A failure recovery and trust boundary](../../docs/security/V01A-failure-recovery.md). The original mock has been removed from default dispatch; developer-specific native-host installation paths remain a future portability task.
