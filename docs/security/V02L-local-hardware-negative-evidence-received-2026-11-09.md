# V02-L-A/B — Local native negative-verification evidence received (2026-11-09)

**Disposition: EV-025 RECEIVED — operator-submitted self-report, successful local negative observations, NOT independent device assurance, NOT OPEN-15/01 approval.**

This intake records three redacted V02-L JSON receipts provided in conversation. The date is **intake date**, not an independently established time of physical execution. The receipts claim source commit `edd3256a90a2993d907525495e3eb01bdabe9a47`, the [merged V02-L troubleshooting PR #23](https://github.com/BetrayedByEthanol/Pw_Manager/pull/23). The harness code was merged through [PR #22](https://github.com/BetrayedByEthanol/Pw_Manager/pull/22) and corrected for CBOR framing, terminal-safe diagnostics and offline PRF context validation in #22/#23.

The operator previously provided `INCOMPLETE` receipts due to `FIDO_ERR_NO_CREDENTIALS` and reported new synthetic test registrations before these three later results. The current results supersede those *for local test success*, but do not erase the failure history or prove the underlying device identities. Raw assertion signatures, PRF outputs, PINs, credential identifiers, RP strings, device paths and private `session.json` are intentionally not collected. These redacted claims cannot independently reproduce or cryptographically verify the assertions.

## Source-pinned redacted receipts

| Receipt | Submitted status | Observations |
| --- | --- | --- |
| [Primary native verifier](evidence/v02l-primary-verifier-local-2026-11-09.json) | `LOCAL_NEGATIVE_OBSERVATIONS_CAPTURED` | `positive_signed_up_uv=OBSERVED`; five mutated verification inputs each `LOCAL_VERIFIER_REJECTED` |
| [Backup native verifier](evidence/v02l-backup-verifier-local-2026-11-09.json) | `LOCAL_NEGATIVE_OBSERVATIONS_CAPTURED` | `positive_signed_up_uv=OBSERVED`; five mutated verification inputs each `LOCAL_VERIFIER_REJECTED` |
| [Wrong-device local probe](evidence/v02l-wrong-device-local-2026-11-09.json) | `LOCAL_DEVICE_REJECTION_OBSERVED` | `control_before=OBSERVED`, `target_credential_on_other_key=LOCAL_DEVICE_REJECTION_UNCLASSIFIED`, `control_after=OBSERVED` |

The five mutation categories on **each** reported key are: `wrong_challenge`, `wrong_rp`, `tampered_authenticator_data`, `tampered_signature`, `wrong_public_key`. These establish that the local libfido2 verifier rejected modified transcripts after a positive signed assertion, **as reported by the operator**. They do not demonstrate a production daemon replay cache or browser origin authorization. The wrong-device rejection is **unclassified**, not independently attributable to absent credentials, token identity, UV or revocation. A passing control both before and after narrows—but does not eliminate—those ambiguities.

Prior [EV-023 V02-K observations](V02K-local-hardware-evidence-received-2026-11-08.md) remain separate: native PRF stability and synthetic entry-scope difference were reported on two YubiKey 5 NFC USB-A tokens with firmware 5.7.4. V02-L receipts contain no independent proof of hardware identity, token uniqueness or firmware and must not be merged into a fabricated device attestation.

## Updated OPEN-15 matrix

| Case | EV-025 contribution | Still required |
| --- | --- | --- |
| I-P01 | None beyond prior EV-023 | Attestation-chain and hardware identity verification; two physically independent authenticators |
| I-P02 | None beyond prior EV-023 | Authenticated test DEK envelopes that decrypt only under correct per-entry routes |
| I-P03 | Wrong credential locally rejected on other test device, positive backup controls before/after | Trusted per-entry/backup slot binding, unavailable/removed and revocation scenarios |
| I-P04 | **New partial evidence:** both local native verifiers rejected mutated RP, challenge, data, signature, public key | Application challenge tracking, stale-replay registry/revocation, spoofed-client/origin controls and independent review |
| I-P05 | Not executed | Browser WebAuthn/native PRF parity using same credential and UV (deferred); no passkey implementation claim |
| I-P06 | **New partial evidence:** positive locally requested UV/UP, earlier missing-path precheck | Real signed UV/UP-absent assertions, safe cancellation/timeout/removal, no-fallback runtime; no deliberate bad PIN/retry exhaustion tested |
| I-P07 | Not executed | Backup-slot rewrap, retirement, atomic reopen and Option A recovery lifecycle |
| I-P08 | Not executed | Native batching, fanout and operation-count behavior |
| I-P09 | Not executed | Lock/suspend/reconnect and per-operation PRF/key lifetime in actual V03/V06 runtime |

**Approval boundary:** Every included receipt still asserts `review_only=true`, `local_self_report_only=true`, `entry_route_ready=false`, `i_p04=PARTIAL`, `i_p06=PARTIAL`, `open_15=BLOCKED`, `open_01=BLOCKED`, `release_gates=G1-G3 BLOCKED`. No cryptographic expert sign-off, physical-key uniqueness, manufacturer provenance or production authorization is implied.

**Next recommended work:** independent reproduction/review of the existing local negatives with controlled device/CLI versions and explicit signed assertions (without publishing secrets), then application-layer replay/registry/fail-closed controls under V03/V06. I-P05 browser parity and I-P07–09 lifecycle tests remain separate future milestones. OPEN-PRF-SALT and OPEN-HW-ASSURANCE are not resolved by this evidence.
