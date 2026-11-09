# Vaulty — Implementation Roadmap

**As of:** 2026-11-09 | **Merged baseline:** [V02-L PR #22](https://github.com/BetrayedByEthanol/Pw_Manager/pull/22) and [follow-up #23](https://github.com/BetrayedByEthanol/Pw_Manager/pull/23), merge `edd3256a`. **Operator-reported evidence received:** [EV-023 V02-K PRF observations](../security/V02K-local-hardware-evidence-received-2026-11-08.md) and [EV-025 V02-L local verifier/wrong-key negatives](../security/V02L-local-hardware-negative-evidence-received-2026-11-09.md). No independent OPEN-15 approval or production token authentication; OPEN-HW-ASSURANCE/OPEN-PRF-SALT and OPEN-01/15/G1–G3 remain BLOCKED.  
**Target:** [v0.4.5 specification](../specification/v0.4.5.md) | [architecture](../architecture/v0.4.5.md) | [feature ledger](features.md) | [acceptance register](acceptance-register.md)

> **Status rules:** MERGED means source merged; CI-PASSED means its specified automated checks passed; VERIFIED means explicit acceptance tests and independent review evidence; DESIGN-APPROVED means intent only. Do not use “DONE” for unverified cryptographic behavior. A green workflow is not authorization to store real credentials.

## A. Immediate state

| Track | Current disposition | Evidence / outstanding |
| --- | --- | --- |
| V01 — Prototype Safety & Build Foundation | **Merged + CI-PASSED; security acceptance incomplete** | PR #4/#5; 11 root tests and browser/config checks; main GitHub CI green |
| V01-A — Security Closure & Verification Hardening | **MERGED + PR CI PASSED; production security not certified** | PR #7 (`ae6d387`), fail-closed host, removed key dump, executable/IPC/fault tests; see [evidence register](acceptance-register.md) |
| V02 — Canonical Format & Independent Keys | **MERGED PR #8; candidate library only, NOT final wire/production** | Typed VMK/VERS/DEKs, authenticated outer header/body, independent entry AEAD, pending slots, bounded codec and ancestry checks; all four Codex P2 findings resolved, final-head V02/product CI passed. **OPEN-01/15 and runtime pending**; see [candidate format](../architecture/v02-format-candidate.md) |
| V02-A — Cryptographic Protocol & Key-Slot Design Review | **MERGED PR #9; design packet only** | [Threat matrix, transcript, Option A/OPEN-02 and reviewer gates](../architecture/v02a-crypto-keyslot-review.md); not independent OPEN-01/15 approval |
| V02-B — Factor-Bound Key-Slot Cryptography Candidate | **MERGED PR #10, NOT production/approved** | [Private Argon2id/HKDF/AEAD/HMAC candidate](../architecture/v02b-keyslot-candidate.md); final-head GitHub CI and Codex review clean; 26/26 V02 tests on tested code; no active slots or OPEN-01/15 approval |
| V02-C — Cryptographic Conformance & Security Verification | **MERGED PR #11, synthetic evidence only** | [Six frozen cross-library KATs, inner/outer tamper tests and KDF bounds](../security/V02C-cryptographic-conformance.md); final-head V02, security probes, product CI passed and Codex final review clean; **no real FIDO2/external review** |
| V02-D — External Crypto Review Readiness & Gap Closure | **MERGED PR #12, not externally approved** | [Pinned review handoff and verified source inventory](../security/V02D-independent-review-handoff.md); final-head focused, product and security CI PASS; final Codex no major issues; external OPEN-01/15 still absent |
| V02-E — Cryptographic Review Findings & Pre-Approval Hardening | **MERGED PR #13; internal candidate only** | [F-1–F-9 triage](../security/V02E-review-findings-and-preapproval-hardening.md); 40 Rust tests, six frozen vectors, 27-file inventory and all three final-head CI checks PASS; final-head Codex no major issues; OPEN-01/15 remain blocked |
| V02-F — Recovery Assurance & Cryptographic Policy Decisions | **MERGED PR #14, proposals only** | [Approved recovery invariants and open owner/expert decisions](../security/V02F-recovery-assurance-and-cryptographic-policy.md); 40 focused Rust and four policy CI checks PASS at final head; Codex initial P1/P2 corrected, final-head review no major issues; **no KDF/password/consent policy newly approved** |
| V02-G — Cryptographic Protocol vNext Review Candidate | **MERGED PR #15, test-only proposal** | [Review-only V3RV descriptor/envelope and transcript](../architecture/v02g-vnext-cryptographic-protocol-review.md), 47 Rust tests and three final-head CI workflows PASS; Codex no major issues; merge `239f80c`. No authenticated slot or approved crypto. |
| V02-H — Adversarial Conformance & Review Submission | **MERGED PR #16; internal evidence only** | [Source-pinned 36-file reviewer handoff](../security/V02H-adversarial-conformance-and-review-submission.md); final head `3f36a442`: 49 Rust, 7 Python scenario tests, 5 wire vectors, seeded mutations, three final-head CI workflows PASS; Codex no major issues; merge `9d854a6`. **No authenticated vNext KEK/slot or external OPEN-01/15 verdict.** |
| V02-H round-two findings intake | **MERGED PR #17, issue intake only** | [F-1–F-9 and W1 review disposition](../security/V02H-round-two-review-disposition.md) accepted with explicit F-1 owner discretion and no P6/HMAC/V3RV cryptographic proof; merge `a3f1777`; hardware/Argon2/entry metadata and graph remain incomplete. |
| V02-I — FIDO2 PRF Isolation & Hardware Assurance Policy | **MERGED PR #18; test-only policy and input reference** | [Six frozen PRF public-input/salt vectors and two-key coverage policy](../security/V02I-fido2-prf-isolation-and-hardware-assurance.md); final 57 Rust, five Python, five policy checks, 44-file inventory and full GitHub CI PASS; merge `54a20268`; **no real device or approved UV/PRF policy.** |
| V02-J — FIDO2 Hardware Integration & Verification Foundation | **MERGED PR #19; lab foundation only** | [Opt-in Linux libfido2 test harness](../security/V02J-isolated-fido2-hardware-verification.md), final-head 57 Rust and 20 mocked Python hardware/policy cases, 48-file source inventory, three GitHub workflows PASS, all initial Codex P2 corrections resolved; merge `9e7edb83`. **No real device or OPEN-15 verdict.** |
| V02-K — Physical FIDO2 Verification & Evidence Intake | **MERGED PR #20; operator local observations RECEIVED, NOT independently verified** | [Rust runner](../security/V02K-physical-fido2-verification-and-evidence.md) merged `f65615e8`; [EV-023 redacted owner report](../security/V02K-local-hardware-evidence-received-2026-11-08.md) shows primary+backup `OBSERVED` native UV-requested PRF stability and synthetic entry separation on two *reported* YubiKey 5 NFC USB-A 5.7.4 devices. I-P01/02/03/04/06 remain PARTIAL, I-P05/07–09 NOT_EXECUTED. **OPEN-15/01 and READY remain blocked.** |
| V02-L-A/B — Native FIDO2 Negative & Physical Failure Verification | **MERGED PR #22/#23; EV-025 local observations RECEIVED, NOT independently reviewed** | [Review-only native test harness](../security/V02L-native-fido2-negative-and-failure-verification.md) + [operator-reported redacted evidence](../security/V02L-local-hardware-negative-evidence-received-2026-11-09.md): primary and backup positive UV/UP control, five verifier mutations rejected on each, wrong-device unclassified rejection with backup controls before/after. No bad PIN attempts, signed absent-UV/UP token output, browser passkeys, trusted daemon replay/revocation or production entry routes. I-P03/04/06 PARTIAL; OPEN-15/01 and G1–G3 BLOCKED. |
| V04M — Safe Migration Foundation | Not implemented | Separate format detection, non-destructive import and verify-before-commit |
| V03 — Operations, States & Authenticators | **MERGED PR #25** (`6411bcdc`), foundation model only | [V03 source/test design](../architecture/V03-session-and-authenticator-foundation.md): public-only OPEN; test-only synthetic LOADED; CLOSED/LOCKED cleanup, XOR-share remasking, finite inactivity/absolute clocks, OS event fail-close, per-entry virtual/physical read intent and bounded write intent. CI passed, but **no production LOADED transition, actual adapter, DEK unwrap, VMK/write commit, trusted listener or local prompt**; OPEN-01/15 and G1–G3 BLOCKED. |
| V03-A — Trusted Session Lifecycle & Authenticator Boundary | **PR CANDIDATE; NO production monitor or authenticator** | [V03-A design/evidence scope](../architecture/V03A-trusted-lifecycle-and-authenticator-boundary.md): fail-closed health watchdog and Linux logind safety event mapping, exact active read-intent binding, sealed virtual vs physical non-authorizing adapters, synthetic missing/suspended/revoked credential tests, lifecycle cancellation and no fallback. **No D-Bus connection, trusted sender/seat verification or live FIDO2**, no production LOADED path; review/CI required. |
| V04 — Recovery & Slot Provisioning | Not implemented | Option A semantics; code-only conditions; all dependent envelopes |
| V05 — Entry Policies & CRUD | Not implemented | 4 entry modes; independent DEKs; isolated path assurance |
| V06 — Trusted Authenticators | Not implemented | Enrollment, scoping, revocation, hardware PRF review |
| V07 — Trusted Daemon, IPC & Pairing | Prototype only | Unix socket/mock dispatcher exists; real E2E identity/authz missing |
| V07A — CLI, Service and Metadata UX | Prototype only | Existing CLI routines are disabled; safe policy-backed commands missing |
| V08A/B/C — Hotkeys / Browser / Passkeys | Prototype / deferred | Extension selector exists, mock fill exists; sensitive flows untrusted |
| V09 — Release Security Assurance | Not started | External review, fuzz, recovery and platform certification |
| Forgejo cutover | Workflow files committed; runner verification **pending** | See [Forgejo CI instructions](../ci/forgejo-actions.md) |
| OPEN-01 / OPEN-15 | **Open independent crypto-review blockers** | Candidate reference vectors are not approved |

## B. Execution order and deliverables

| ID | Package | Minimum deliverables / completion conditions | Depends on |
| --- | --- | --- | --- |
| **V01** | Build and prototype safety | Compiling CLI/root/host; fail-closed default executable; fresh outer nonces; strict body checks; atomic backup/lock; CI on main | — |
| **V01-A** | Security closure (merged; acceptance limited) | Remove reachable key-dump/debug helpers; make default native host fail closed rather than report fake success; test host IPC and executable; inject filesystem faults; classify remaining V01 security review items; update evidence | V01 |
| **V02** | Authenticated canonical format and separated roots | Bounded single-file codec, independent VMK/VERS/DEKs, policy-bound slots, full authenticity and version gates, generation index, tombstones, nonced AEAD, crash writer, negative/fuzz tests | V01-A + OPEN-01 approval before activating crypto |
| **V02-A** | Cryptographic protocol and key-slot design review | Threat/slot discrepancy analysis, proposed factor/PRF transcripts, Option A recovery and bootstrap matrices, review handoff; **OPEN-01/15 remain blocked until independent approval** | V02 candidate merged |
| **V02-B** | Key-slot protocol candidate and review-gated implementation | **Merged experimental PR #10:** isolated Argon2id/HKDF/slot AEAD and draft commitment; not final protocol. Production serializer, hardware proof and activation still require independent OPEN-01/15 review | V02-A merged; independent OPEN-01/15 approval for production |
| **V02-C** | Cryptographic conformance and security verification | **Merged PR #11:** synthetic cross-library vectors, mutation tests and hardware review plan; no independent crypto or device verification | V02-B merged |
| **V02-D** | Independent cryptographic review readiness and gap closure | **Merged PR #12:** source-pinned test/review package, 12 security gaps and unexecuted hardware/verdict templates; not an external audit | V02-C merged |
| **V02-E** | Review findings and pre-approval hardening | **Merged PR #13:** shared structural eligibility for model/candidate; route parity tests; fixed zeroizing combiner scratch; metadata transition guard and vNext test-only AAD; F-1–F-9 triage, no wire change | V02-D merged; OPEN-01/15 blocked |
| **V02-F** | Recovery assurance and cryptographic policy decisions | Pre-approval contract for VMK/VERS/seed/DEK normal vs recovery reports; proposed informed weaker-route opt-in, trusted owner receipts, Option A lifecycle, Argon2 profile benchmarking/resource budget, proposed NFC→UTF-8 byte encoding, code-scope ownership, OPEN-01/15-vetted PRF/UV and V02-G/H exit criteria. **No new approved owner decision or runtime activation.** | V02-E merged; explicit owner + external reviews remain |
| **V02-G** | Cryptographic protocol vNext review candidate | **MERGED PR #15 (inactive):** `V3RV` magic, strict bounded big-endian descriptor/envelope, review-only slot/commitment context, Isolated structural test and test-only DEK metadata AAD; no authenticated slot or production serialization | V02-F merged; OPEN-01/15 external review outstanding |
| **V02-H** | Adversarial conformance and submission | Separate Rust and Python V3RV wire/context implementations with five frozen synthetic fixtures; strict/truncated/mutated corpus, scoped recovery/ancestor graph reference model and *synthetic* KDF budget; reviewer attack matrix, pinned source inventory and blank OPEN-01/15 verdict template. **vNext crypto multi-key commitment remains UNTESTED until an authenticated slot is designed/reviewed** | V02-G merged; OPEN-01/15 still independent; V02-C KATs apply only to V02-B |
| **V02-I** | FIDO2 PRF isolation and hardware assurance policy | Distinct proposed per-entry/slot/credential/purpose PRF salt input; correctly separate browser PRF raw input from CTAP salted input; test-only Rust/Python reference, two-device offline-backup lifecycle and OPEN-15 device matrix; owner UV-required versus touch-only profile unresolved. **No verified hardware or production wire** | V02-H/round-two findings merged; OPEN-01/15 and owner hardware profile decisions remain |
| **V02-J** | Isolated FIDO2 hardware verification foundation | Safe local/interactive libfido2 test enrollment, signed challenge/UP/UV assertion verification, no-secret observations, Python mocked CI tests, mapped I-P01..09 hardware/operator runbook; **no physical test in CI and no ready entry route** | V02-I merged; operator-controlled tokens and qualified independent OPEN-15 reviewer still required |
| **V02-K** | Local physical verification and evidence intake | Rust CLI prompts primary/backup hardware stages and reduces native test observations to source-pinned redacted report; **EV-023 owner report received** (local self-report, not device provenance proof) | V02-J and V02-K merged; independent OPEN-15 review, browser PRF parity and owner hardware policy still required |
| **V02-L-A/B** | Native assertion verifier negatives + safe physical-key failure probes | Operator-only Python/libfido2 test harness, clean-Git redacted receipts, signed-positive/mutated-negative checks, secondary-token controls; offline CI; I-P04/I-P06 partial only | V02-J/K merged; local EV-023 evidence; independent OPEN-15, later V03/V06 runtime authorization tests |
| **V04M-1** | Migration foundation | Version detector, read-only legacy parser, backup manifest, separate destination output, reopen/verify and rollback instructions. Do not auto-import unknown files | V02 codec |
| **V03** | Session states and authenticator adapters | **MERGED foundation #25:** public-only OPEN, synthetic test-only LOADED, per-entry read/write intent constraints, two-share VERS masking, timeout and lifecycle fail closed. Production unlock remains disabled. | V02; OPEN-01/15 approval before production activation |
| **V03-A** | Trusted lifecycle and authenticator *boundary* v0 | **PR candidate:** Linux logind fail-closed event mapping, non-authorizing watchdog, session-owned read policy matching and sealed virtual/physical adapters; fake/test statuses always denied. Needs OS D-Bus subscription, trusted sender/session proof, watchdog delivery, trusted prompt and actual physical PRF in separately reviewed follow-ups | V03 merged; OPEN-15 and owner hardware policy before activation |
| **V04** | Recovery / rewrap provisioning | Distinct VMK/VERS/DEK slots; code-only VMK recovery **password-only vaults exclusively**, hardware vaults with separately provisioned code+existing-password replacement and code+registered-hardware reset routes; Option A explicit code prompts; owner-approved weaker-Standard-route consent **only after OPEN-REC-CONSENT decision**, ancestry-aware assurance graph and READY/PENDING/MISSING/DEGRADED/UNVERIFIED/STRICT_NONE; recovery test matrix | V02–V03 + V02-F owner decisions; OPEN-01/15 before activation |
| **V04M-2** | Vault-to-vault transfer (N-02) | Explicit copy/move; source+destination authorization, fresh destination keys, duplicate/policy checks, destination commit validation before source delete | V04 + V05 |
| **V04M-3** | Manual distinct-vault merge (N-03) | Conflict planning, explicit entry/policy selection, lineage tracking, partial failure atomicity, no silent trust transplant; preserve both inputs until verified | V04M-2 + V05 |
| **V05** | Entry access policies and lifecycle | Four normal entry modes; independent DEK CRUD and per-operation authorization; ISOLATED normal access always hardware-mandatory, with recovery hardware-mandatory or disabled via STRICT_NONE; inherited recovery assurance; no VMK read dependency | V03–V04 |
| **V06** | Trusted authenticator lifecycle | Enroll/authorize/scope/backup/suspend/revoke/rotate physical devices; repair affected wrapping slots, detect orphaned keys, interactive loss cases | V03–V05 |
| **V07** | Trusted daemon, client pairing and E2E IPC | Authenticated socket, owner approval and pinned identity, reviewed encrypted extension→daemon channel via opaque native host, least privilege, replay/failure tests | V03–V06; E2E protocol review |
| **V07A** | CLI/service controls and metadata UX | Secure prompts, lock/close, bounded retry UX, list/search/redacted preview, daemon lifecycle, recovery status and warnings | V03–V07 |
| **V08A** | Hotkey activation | Shortcut registration, conflict/missing-focus tests; no X11 credential typing by default | V07A |
| **V08B** | Browser CRUD and password generator | Explicit gesture, exact origin/frame binding, authenticated save/fill and durable receipts; generator reuse; no fake mock successes | V05–V07A |
| **V08C** | Passkeys (deferred) | Distinct software passkey provider/RP checks and hardware passkey interface; standalone external review | V07–V08B |
| **V09** | Independent verification and release | Crypto review receipts, fuzz/property tests, hardware integration, restore/corruption/rollback evidence, threat-model revision, signed release/SBOM and platform checks | All release scope |
| **P3 / N-04** | Automatic sync-conflict merge | Separate distributed conflict/ancestry threat model and protocol. **Deferred, not prerequisite for manual vault merge** | Post-V09 design approval |

The V04M identifiers name a **migration/transfer workstream**; they may be scheduled around V03–V05 as dependencies permit. N-01 format upgrade is P0, N-02 copy/move P1, N-03 manual merge P2; N-04 conflict merging is deferred P3.

## C. Gates (never infer from merge alone)

| Gate | Evidence required | Current |
| --- | --- | --- |
| **G0 — Build / safe prototype** | Green CI on merged main, default executable inert, no false native-host save/retrieve success, basic negative tests and accepted V01 security-closure review | **Partial:** CI green, V01-A outstanding |
| **G1 — Canonical cryptography** | Independent OPEN-01 combiner/commitment review, canonical codec tests, cross-implementation vectors, key isolation, no nonce reuse, fuzz and error-path evidence | **Blocked** |
| **G2 — Authenticator & session** | OPEN-15 review; hardware/virtual separation; fresh physical PRF; LOADED masking; key cleanup; failed-auth/unplug tests | **Blocked** |
| **G3 — Recovery + client access** | Option A provisioning and complete slot coverage, restore/migration; owner-approved pairing, E2E/IPC authorization, negative attack tests | **Blocked** |
| **G4 — Pilot/release assurance** | CRUD with four modes, real browser flows, backups/restore, threat-model review and independent release evidence | **Blocked** |
| **G5 — Optional postponed** | Passkeys/typing/automatic sync-specific separate gates | **Deferred** |

## D. Merged V01-A #7 and V02 v0 #8

**V01-A source was merged in PR #7. V02 candidate source was merged in PR #8 (`84f92be`); remaining cryptographic/release acceptance is tracked separately. The standalone codec library does NOT change the disabled main executable.**
1. Strip or isolate `src/util/gocrypt.rs` master-key-dump and destructive experiment helpers from the compiled runtime, plus any uncontrolled credential logging. Keep tests synthetic.
2. Default native host must report UNAVAILABLE/NOT_IMPLEMENTED for secret and persistence operations unless an explicitly test-only mock is enabled; no default successful fake “saved” receipt or unlocked status. Add host protocol behavior tests.
3. Test executable fails nonzero, does not create/modify a vault and does not print real secrets.
4. Add deterministic fault-injection tests to atomic backup/rename/fsync/lock/crash paths, including path/symlink attacks.
5. Add malformed header/payload rejection and negative FIDO2 verification test harness planning. Legacy format rewrite stays in V02.
6. Update V01 status and checklists with concrete merged main commit and CI evidence; no false claim of production readiness.

**Out-of-scope for V01-A:** enabling legacy CLI or mock native host; implementing the canonical format; marking OPEN-01/15 approved; marketing Vaulty as safe for real credentials.

### V02 v0 — staged acceptance (PR #8 merged, candidate only)

| Candidate deliverable | Implementation | Remaining approval |
| --- | --- | --- |
| Versioned public header and authenticated body | `src/v02/codec.rs`; bounded parsing, duplicate checks, UTF-8 and version rejection | Final byte schema, padding/leakage budget and key commitment **OPEN-01** |
| Independent random VMK/VERS/entry DEKs | `src/v02/model.rs` / `mod.rs` with drop-zeroizing key wrappers | Factor wrapping/derivation and independent cryptographic review **OPEN-01/15** |
| Entry ciphertext/AAD | DEK-separated XChaCha20-Poly1305 binding vault ID, entry ID, revision, tier, mode, recovery | Slot key commitments, inheritance/group path assurance **V04/V05** |
| Generation, tombstones and stale-write checks | Authenticated commit UUID, parent full-encrypted-file hash, revisioned tombstones; encrypted conflict copy | Local last-seen-head and race-free dirfd writer; approved S4 acceptance **V02 follow-up** |
| Negative evidence | Synthetic tamper/wrong-key/version/limit/fuzz-like tests + injected conflict/rename failures | Broad fuzz/property/cross-language conformance and reviewed hardware factors |
| Runtime and recovery | **Not enabled**; main CLI inert, native host UNAVAILABLE | R1/R5/R6, password/hardware bootstrap, secure daemon, migration/restore |

No G1 certification or full FR closure follows automatically from the candidate codec. V02-A #9, V02-B #10 and V02-C #11 are merged, **none constitutes independent cryptographic review**. V02-B stays disconnected from runtime; V02-C conformance and [V02-D reviewer handoff](../security/V02D-independent-review-handoff.md) do not lift OPEN-01/15.

## E. Tracking and PR acceptance protocol

Every PR description should include: package ID; feature/FR and decision IDs; explicit source/changes; negative-path tests; linked test run/commit; migration/rollback implications; threat-model effects; reviewer findings and disposition; remaining blockers; and whether release gates changed.

Only move an item to DONE when merged implementation plus applicable acceptance evidence exist. Record proposed/provisional decisions separately from implementation status. Update [acceptance register](acceptance-register.md), [feature roadmap](features.md), and [decision register](../decisions/register.md) in the **same PR** as a material change. Never retroactively mark old work completed from a roadmap refresh.

## F. Current blockers and ownership

| Blocker | Needs new user decision? | Owner / next action |
| --- | --- | --- |
| V01-A cleanup and tests | No | PR #7 merged; security acceptance remains separately gated |
| OPEN-01 combined-factor KEK/key commitment | **Independent reviewer approval**; may require design decision if rejected | Secure review before V02 crypto enablement |
| OPEN-15 PRF scope/batching/UV | **Independent reviewer approval**; may require capability trade-off choice | Review before V03/V06 hardware policy |
| Canonical codec and authenticated ancestry | No for approved principles; cryptographic details require review | V02 candidate merged; finish S4/dirfd/fuzz and independent cryptographic acceptance |
| Option A code-dependent recovery envelopes | **Approved**, no repeat decision | Implement V04 |
| ISOLATED hardware normal access; hardware-only recovery or STRICT_NONE | **Approved**, no repeat decision | Test that STRICT_NONE never permits a virtual normal route; implement and test V04/V05 |
| INDEPENDENT UI setup | **Deferred**, not blocked by schema | Later product milestone |
| N-01/02/03 transfer and merge | **Accepted feature scope**, detailed conflict UI design later | V04M |
| N-04 automatic sync-conflict merge | **Deferred** | Do not begin in MVP |
| Forgejo switch | Runner/environment setup, not product decision | Verify before cutover |

### Approved contract gates carried forward

- **R1:** Password-only code recovery; hardware-backed vaults require separately provisioned code+existing-master (replacement token) and code+already-registered hardware (master reset) routes. **No hardware code-only VMK/metadata recovery or emergency override.** Show metadata and entry-DEK access paths independently.
- **R5/R6:** Before enabling runtime, enforce idle plus absolute LOADED timeout, OS lock/suspend/hibernate fail-closed cleanup, and bounded `WRITE_TRANSACTION` (ID, base, TTL, cap) without VMK; require trusted daemon change summary and fresh VMK for one atomic commit.
- **S4:** Authentic ancestry, stable entry revisions/tombstones, local best-effort head outside vault directory checked after decrypt and before LOADED; refuse stale/divergent writes and retain both encrypted copies for owner reconciliation.
- **OPEN-02 / OPEN-15:** Random virtual-provider seed with password/recovery bootstrap and pinned physical PRF UV/salt/credential enrollment checks; independent cryptographic/device reviews still block release.
- **R8:** Encrypted pre-operation backups, historical factor inventory, purge-on-rotate and old-code-only warning when converting password-only to hardware-backed vaults.
- **Traceability:** Keep approved D-01…D-32 IDs (D-19/D-20 RESERVED); DEC aliases and the 67 historic source features must remain mapped. These entries are **design requirements, not implemented or tested** by this documentation update.

## G. Verification commands (current baseline)

- Root: `cargo check --locked --all-targets`, `cargo test --locked --all-targets`
- Native host: `cargo check --manifest-path extenstion/host/Cargo.toml --locked --all-targets`, `cargo test --manifest-path extenstion/host/Cargo.toml --locked --all-targets`
- Security probes: `python -m unittest -v test_probes` in `tools/security_probes/`, `cargo test --manifest-path tools/security_probes/rust/Cargo.toml --all-targets`
- Extension: manifest JSON parse and `node --check` of extension JS files
- Forgejo: `.forgejo/workflows/` mirror is committed but unverified on a real Forgejo runner.

The source of truth for changes is the repository; this roadmap is a plan and evidence ledger, not an automatic runtime certificate.
