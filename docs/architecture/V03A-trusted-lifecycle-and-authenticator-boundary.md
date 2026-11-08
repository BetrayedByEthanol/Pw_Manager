# V03-A — Trusted Session Lifecycle & Authenticator Boundary v0

**Status: review-gated foundation only. NOT a completed trusted OS listener or authenticator.**

The merged V03 model establishes state and unauthenticated read/write *intents*. This V03-A change provides a deliberately **non-activating** trust boundary and synthetic failure tests. It does **not** introduce a real LOADED constructor, Linux D-Bus subscription, permissioned daemon, trusted owner prompt, physical FIDO2 runtime provider, master-key handling or credential access. The compiled default Vaulty executable and native host remain fail closed.

## A. Lifecycle guard and Linux event normalization

`src/v03a.rs` introduces `LifecycleGuard` with finite monotonic health deadline (1–60 seconds) and normalized `LogindSafetyEvent` values:

| Signal | Conservative state effect |
| --- | --- |
| SessionLocked | Lock, reason ScreenLock |
| PrepareForSleep(true) | Lock, reason Suspend |
| PrepareForSleep(false) | **Still lock**; wake never silently restores LOADED |
| PrepareForShutdown(true) | Lock, reason Hibernate/termination |
| SessionUnlocked | Treat as possible missed earlier lock, fail closed |
| SessionRemoved, SubscriptionLost | Fail closed and invalidate health |
| MalformedOrUnknown, unexpected shutdown state | Fail closed and invalidate health |

The guard starts **not trusted**. Its public API can check health, lock on events and invalidate the guard, but **cannot mark a listener healthy**. Only `#[cfg(test)]` synthetic hooks simulate verified monitor acquisition and periodic trusted health checks. After losing monitor health, `enforce` locks the session and refuses to resume it. A future trustworthy daemon must supply independently verified OS event subscription and watchdog delivery; this milestone must not be mistaken for that implementation.

**Unimplemented Linux requirements:** actually connect to the system bus, subscribe to logind Session.Lock/Unlock and Manager.PrepareForSleep without a subscription/check race, verify signal sender unique owner and correct local session/seat, handle owner changes, lock screen events and initial LockedHint, register delay inhibitor where appropriate, integrate independent periodic liveness/overflow/disconnect monitoring, cross-platform equivalents, and run OS integration failure tests. Simply parsing untrusted stdout, accepting arbitrary event objects from a native host, or trusting a caller's boolean cannot establish these prerequisites. Actual production LOADED remains impossible for this reason, among others.

## B. Authenticator boundary

The `AuthenticatorBoundary` uses **sealed** `ProviderAdapter` marker implementations: `VirtualNonFactorAdapter` and `PhysicalFido2Adapter`. It evaluates only a `ReadIntent` that still matches the *session-owned* active operation ID, entry ID and selected provider. Read pending records now retain entry+provider to prevent stale/cross-entry/policy-substituted requests. Selection of the wrong provider consumes the active intent without falling back to another provider.

- Virtual remains a non-factor. No virtual seed or synthetic PRF is exposed.
- Physical factors have no runtime `Active` registration path. Test-only states exercise missing/suspended/revoked/active denials. Even **test-only Active** always returns `TrustedBackendUnavailable`, not an authorization or valid hardware assertion.
- The boundary never marks `ReadIntent` authorized, unwraps a DEK, accesses a YubiKey, releases plaintext, or retains a successful prior touch. Every matching attempt cancels its pending intent and remasks VERS. Stale attempts cannot cancel unrelated valid pending intents.
- Sealed adapters do **not** prove factor provenance. They merely prevent injecting arbitrary third-party implementations *into this foundation*. V04/V06 must implement authenticated credential registry, exact RP/UV/UP/salt binding, revocation and fresh per-read PRF with actual device proof before activation. V07 must authenticate clients, owner intent and secure prompts.

The implementation is additive: no production user-facing vault path is enabled, no VLY2/V3RV crypto format changed and no recovery policy relaxed. Neither `read intent` nor synthetic monitoring is a trusted-capability token.

## C. Offline tests and review

`src/v03a_tests.rs` includes tests for:

- Untrusted startup monitor fail-closed and stale operation cancellation.
- Synthetic verified observer health deadline and inability to revive after loss.
- All supported Linux logind event classifications, including unexpected wake/unlock and malformed signals.
- Physical→virtual substitution and inverse substitution rejected; matching pending operation consumed without fallback.
- Missing/suspended/revoked/active *synthetic* credential states always denied.
- Tampered read intent entry/provider and replayed operation rejected against session-owned matching.
- Virtual adapter non-factor and cancellation/lock invalidating pending operations.

These tests do not contact a real session bus, physical key, network or private session.json. The module is compiled by both root and the isolated V02 verifier CI; the source inventory is extended to pin the V03-A module/tests.

Local developer commands:

~~~sh
cargo test --lib -- v03a
cargo test --manifest-path tools/v02_verifier/Cargo.toml --locked --lib -- v03a
cargo check --manifest-path tools/v02_verifier/Cargo.toml --locked --all-targets
python3 tools/v02_verifier/review_bundle.py --write /tmp/v03a-review.json
python3 tools/v02_verifier/review_bundle.py --check /tmp/v03a-review.json
~~~

## D. Exit criteria and blocked gates

**V03-A v0 acceptance is source and negative-test behavior only.** The trusted Linux listener implementation and real authenticator backends are future follow-ups, not implicitly completed.

- OPEN-01/OPEN-15 cryptographic/physical assurance reviews: BLOCKED.
- OPEN-PRF-SALT, OPEN-HW-ASSURANCE, owner recovery consent: OPEN.
- Production VMK/DEK unwrap, V04 recovery slots, V06 trusted authenticator enrollment and revocation, and V07 trusted daemon/approval: NOT IMPLEMENTED.
- G1/G2/G3, READY vault routes, production use: BLOCKED.
- EV-023/EV-025 local hardware tests: unchanged, operator self-reports, not these runtime tests.

Recommended follow-up: V03-B trusted Linux logind listener and operation watchdog with integration tests on a dedicated test desktop/session, then authenticated factor and registry implementation under V04/V06 and independent review. Any future enabling of LOADED must be an explicit separately reviewed change, not a side effect of these marker types.
