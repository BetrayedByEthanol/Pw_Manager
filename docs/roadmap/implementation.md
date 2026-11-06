# Vaulty — Implementation Roadmap

**As of:** 2026-11-06 | **Current evidence baseline:** merged PRs #1, #3, #4 and #5; `main` at `7c3ba719`.  
**Target:** [v0.4.5 specification](../specification/v0.4.5.md) | [architecture](../architecture/v0.4.5.md) | [feature ledger](features.md) | [acceptance register](acceptance-register.md)

> **Status rules:** MERGED means source merged; CI-PASSED means its specified automated checks passed; VERIFIED means explicit acceptance tests and independent review evidence; DESIGN-APPROVED means intent only. Do not use “DONE” for unverified cryptographic behavior. A green workflow is not authorization to store real credentials.

## A. Immediate state

| Track | Current disposition | Evidence / outstanding |
| --- | --- | --- |
| V01 — Prototype Safety & Build Foundation | **Merged + CI-PASSED; security acceptance incomplete** | PR #4/#5; 11 root tests and browser/config checks; main GitHub CI green |
| V01-A — Security Closure & Verification Hardening | **NEXT — not implemented** | Native host mock containment; legacy diagnostics; negative tests; crash/failure evidence |
| V02 — Canonical Format & Independent Keys | Not implemented | Requires OPEN-01 cryptographic review before production key graph |
| V04M — Safe Migration Foundation | Not implemented | Separate format detection, non-destructive import and verify-before-commit |
| V03 — Operations, States & Authenticators | Not implemented | Requires V02; masked LOADED VERS and virtual/physical adapter enforcement |
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
| **V01-A** | Security closure (next) | Remove reachable key-dump/debug helpers; make default native host fail closed rather than report fake success; test host IPC and executable; inject filesystem faults; classify remaining V01 security review items; update evidence | V01 |
| **V02** | Authenticated canonical format and separated roots | Bounded single-file codec, independent VMK/VERS/DEKs, policy-bound slots, full authenticity and version gates, generation index, tombstones, nonced AEAD, crash writer, negative/fuzz tests | V01-A + OPEN-01 approval before activating crypto |
| **V04M-1** | Migration foundation | Version detector, read-only legacy parser, backup manifest, separate destination output, reopen/verify and rollback instructions. Do not auto-import unknown files | V02 codec |
| **V03** | Session states and authenticator adapters | CLOSED/OPEN/LOADED/LOCKED, READ/WRITE; masked two-share VERS and virtual adapter while LOADED; no master-password prompt on reads; fresh physical FIDO2 on physical entry read; trusted prompt | V02 + OPEN-15 |
| **V04** | Recovery / rewrap provisioning | Distinct VMK/VERS/DEK slots; code-only optional non-isolated routes; Option A explicit code prompts; new-token and password-change repairs; READY/PENDING/MISSING/DEGRADED/UNVERIFIED/STRICT_NONE; recovery test matrix | V02–V03 |
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

## D. Proposed next PR: V01-A — Security Closure & Verification Hardening

**Scope (implementation-only; no new product decision):**
1. Strip or isolate `src/util/gocrypt.rs` master-key-dump and destructive experiment helpers from the compiled runtime, plus any uncontrolled credential logging. Keep tests synthetic.
2. Default native host must report UNAVAILABLE/NOT_IMPLEMENTED for secret and persistence operations unless an explicitly test-only mock is enabled; no default successful fake “saved” receipt or unlocked status. Add host protocol behavior tests.
3. Test executable fails nonzero, does not create/modify a vault and does not print real secrets.
4. Add deterministic fault-injection tests to atomic backup/rename/fsync/lock/crash paths, including path/symlink attacks.
5. Add malformed header/payload rejection and negative FIDO2 verification test harness planning. Legacy format rewrite stays in V02.
6. Update V01 status and checklists with concrete merged main commit and CI evidence; no false claim of production readiness.

**Out-of-scope for V01-A:** enabling legacy CLI or mock native host; implementing the canonical format; marking OPEN-01/15 approved; marketing Vaulty as safe for real credentials.

## E. Tracking and PR acceptance protocol

Every PR description should include: package ID; feature/FR and decision IDs; explicit source/changes; negative-path tests; linked test run/commit; migration/rollback implications; threat-model effects; reviewer findings and disposition; remaining blockers; and whether release gates changed.

Only move an item to DONE when merged implementation plus applicable acceptance evidence exist. Record proposed/provisional decisions separately from implementation status. Update [acceptance register](acceptance-register.md), [feature roadmap](features.md), and [decision register](../decisions/register.md) in the **same PR** as a material change. Never retroactively mark old work completed from a roadmap refresh.

## F. Current blockers and ownership

| Blocker | Needs new user decision? | Owner / next action |
| --- | --- | --- |
| V01-A cleanup and tests | No | Implement PR and run CI |
| OPEN-01 combined-factor KEK/key commitment | **Independent reviewer approval**; may require design decision if rejected | Secure review before V02 crypto enablement |
| OPEN-15 PRF scope/batching/UV | **Independent reviewer approval**; may require capability trade-off choice | Review before V03/V06 hardware policy |
| Canonical codec and authenticated ancestry | No for approved principles; cryptographic details require review | Implement V02 with adversarial tests |
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
