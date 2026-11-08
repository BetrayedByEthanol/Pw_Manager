# Vaulty — Design Decisions and Open Review Register

**Snapshot:** 2026-11-08 | **Target:** v0.4.5. Decisions here describe **approved product policy**, not implementation status. Round-two findings are accepted for follow-up, **not** approved changes.  
**Canonical spec:** [v0.4.5](../specification/v0.4.5.md) | **Current evidence:** [acceptance register](../roadmap/acceptance-register.md)

**Status meanings:** APPROVED (owner-selected target), PROVISIONAL (direction allowed for review but not security approval), OPEN (needs a protocol decision/review), DEFERRED (explicitly outside current release), SUPERSEDED (historical only).

Established v0.4.5 decisions retain identifiers **D-01 through D-32**. D-19 and D-20 are **RESERVED** (never assigned); D-23 and D-30 remain provisional/review-gated. The DEC-* IDs below are descriptive aliases, not replacements. See the [crosswalk](#historical-d-01d-32-crosswalk); new ADRs must cite affected D-IDs.

## A. Approved current product decisions

| ID | Topic | Status | Binding consequence / not yet implemented |
| --- | --- | --- | --- |
| DEC-KEY-01 | Independent VMK and entry keys | **APPROVED** | One VMK-authenticated outer body, independently encrypted entry ciphertext; VMK never derives/unlocks VERS/entry DEK |
| DEC-KEY-02 | Four entry modes | **APPROVED** | Default/custom first component, virtual/physical second component; every entry has its own random DEK |
| DEC-KEY-03 | LOADED masked VERS | **APPROVED v0.4; overrides v0.3 D-04/05** | Retain only rotating two-share XOR representation of VERS; reconstruct for bounded operation, clear plaintext and temporary KEKs/DEKs. Do not claim full memory-compromise resistance |
| DEC-KEY-04 | Virtual adapter lifetime | **APPROVED v0.4** | Minimal software PRF available while LOADED; helper/protocol parity, not independent 2FA; avoid default master-password re-prompt on reads |
| DEC-KEY-05 | Read/write distinction | **APPROVED** | Reads use entry factors without VMK; writes require fresh VMK plus relevant entry authorization |
| DEC-PROV-S1 | Entry-selected provider | **APPROVED** | Physical entries require fresh physical PRF on *each* read, no virtual fallback; virtual entries use software even if hardware is enrolled |
| DEC-REC-S2 | ISOLATED normal access and recovery | **APPROVED** | Every ISOLATED normal read requires fresh physical FIDO2 and every complete DEK route must be hardware-mandatory. Recovery may be hardware-mandatory or disabled with `STRICT_NONE`; `STRICT_NONE` never permits virtual/software-only normal access. No code-only ISOLATED entry recovery |
| DEC-REC-S3 | INDEPENDENT schema | **APPROVED / UI DEFERRED** | Retain/check INDEPENDENT policy and dedicated entry code in model/tests, defer user-facing enrollment |
| DEC-HIST-S4 | Authenticated ancestry | **APPROVED** | Bind generations/hashes/tombstones; local last-seen accidental rollback warning, not malicious rollback proof |
| DEC-REC-A | Option A slot provisioning | **APPROVED** | Require recovery code **when creating/replacing code-dependent slot**; new token also needs new token PRF; inactive until coverage verified; read/edit through existing route needs no code |
| DEC-REC-CODE | Code-only recovery scope (D-07/D-32) | **APPROVED** | Code-only VMK/metadata recovery is **password-only vaults exclusively**; hardware-backed vaults cannot enable code-only even by emergency override |
| DEC-REC-COVERAGE | Coverage states | **APPROVED** | READY/PENDING/MISSING/DEGRADED/UNVERIFIED/STRICT_NONE; never report new slot ready without actually producing/verifying envelope |
| DEC-REC-SCOPE | Outer vs entry recovery (D-12/D-26) | **APPROVED** | Show VMK/metadata paths separately from entry-DEK paths; code+master in hardware vault may reveal all outer titles/usernames/URLs without entry hardware |
| DEC-REC-R1 | Vault-mode recovery contract (D-07/D-32) | **APPROVED** | Password-only: code alone. Hardware: distinct provisioned code+existing master to replace token, and code+already registered physical token to reset password; no code-only override |
| DEC-SESSION-R5 | Session safety (D-04/D-05) | **APPROVED; not implemented** | Idle and absolute lifetimes; lock on OS session lock/suspend/hibernate and fail closed on listener failure; wipe shares/provider |
| DEC-TX-R6 | Staged writes (D-06) | **APPROVED; not implemented** | WRITE_TRANSACTION ID/base/TTL/cap without VMK; daemon-generated frozen change summary, fresh VMK for one atomic commit, abort on stale head |
| DEC-SEED-OPEN02 | Virtual-provider bootstrap | **APPROVED design; review open** | Independent random seed in separate pre-load normal/recovery envelopes; recover and rewrap the same seed across password resets |
| DEC-FIDO-UV | UV derivation invariants | **APPROVED design; OPEN-15 review open** | Pin credential/RP/salt/UV in slot AAD, verify two stable derivations at enrollment, no silent downgrade |
| DEC-BACKUP-R8 | Historical backup exposure | **APPROVED; not implemented** | Encrypted snapshot before migration/recovery/rewrap; factor-unlock inventory, purge-on-rotate and old code-only snapshot warning |
| DEC-CONFLICT-S4 | Divergence handling | **APPROVED; not implemented** | Refuse stale/diverged writes; retain encrypted conflict copy, explicit reconciliation; local head outside vault directory checked after decrypt/before LOADED |
| DEC-PRIVACY | One-file and minimum public metadata | **APPROVED design principle** | No plaintext entry names, provider keys, trusted registry or code in public framing; authenticated control state on load |
| DEC-CLIENT | Native host transport-only | **APPROVED** | No mock success in default production host; E2E extension↔daemon, pinned client identity, separate trusted authenticator/client registries |
| DEC-FILL | Browser user-gesture + exact origin/frame | **APPROVED** | No page-driven credential release; every request daemon-authorized by action and client capability |
| DEC-TELEMETRY | Non-authoritative read telemetry | **APPROVED** | Usage timestamps/counters outside VMK write path only if they cannot become authorization state |
| DEC-LEGACY | No silent legacy import | **APPROVED** | Old VLT1/JSON data requires explicit version detection/backup/re-encryption/reopen verification |
| DEC-N-01 | N-01 format migration P0 | **APPROVED feature** | FR-MIG-01; separate migration foundation V04M |
| DEC-N-02 | N-02 vault-to-vault copy/move P1 | **APPROVED feature** | FR-XFER-01; fresh destination keys and verify-before-source-delete |
| DEC-N-03 | N-03 manual distinct-vault merge P2 | **APPROVED feature** | FR-MERGE-01; explicit policy/conflict UI, no trust transplant |
| DEC-N-04 | N-04 automatic sync-conflict merge P3 | **DEFERRED** | FR-SYNC-01; not part of manual merge MVP |

## A1. V02-F policy proposals (NOT owner approvals)

The [V02-F recovery assurance and cryptographic policy contract](../security/V02F-recovery-assurance-and-cryptographic-policy.md) specifies owner/expert decision questions and testable design requirements without superseding approved R1, S2, S3, D-12/D-26, Option A, D-30 or the frozen V02-B/C transcript. **Merging V02-F does not approve a new recovery option, password encoding, KDF default, hardware UV level, PRF salt design, or final wire version.**

| Proposal ID | Status | Scope and decision owner |
| --- | --- | --- |
| PROP-REC-CONSENT | **PROVISIONAL — owner selection outstanding** | Explicit, unpreselected per-entry consent for a weaker Standard recovery path; include inherited ancestors, affected roots, downgrade and irrecoverability warnings; no implicit new slot or silent STRICT_NONE |
| PROP-ASSURANCE-REPORT | **REQUIRED by existing D-12/D-26; design proposal only** | Separate VMK metadata / VERS and seed ancestry / entry DEK normal and recovery reports; weakest configured vs usable path; verified coverage and historic-copy inventory |
| PROP-KDF-BENCH | **PROVISIONAL — benchmark/expert** | Compare 64 MiB/3 passes at 1 vs 4 lanes and published baseline; per-user-operation aggregate work/memory/concurrency cap; no production profile chosen |
| PROP-PASSWORD-NFC | **PROVISIONAL — owner/expert** | New-wire NFC→UTF-8, explicit encoding version, no trimming/casefold/truncation; old raw-byte vectors and old file formats unchanged |
| PROP-CODE-SCOPE | **PROPOSED for V02-G/OPEN-01/15** | Entry/group/vault ownership and recovery key-domain separation; no raw code accepted as an unrelated code-scope root |
| PROP-VNEXT-WIRE | **REVIEW REQUIRED** | Exact strict descriptor, password/KDF/PRF context, DEK-bound fill origin and explicit migration; no VLY2 reinterpretation |

## B. Recovery provisioning matrix (Option A)

| Operation | Recovery code prompt | Other prerequisite |
| --- | --- | --- |
| Normal entry read via existing valid route | **No** | Per-entry virtual or fresh physical policy |
| Normal entry edit, using existing recovery coverage | **No additional recovery code** | VMK for write and entry factors as appropriate |
| Create new code-dependent VMK/VERS/DEK slot | **Yes** | All other slot factors available |
| Enroll new hardware authenticator with recovery coverage | **Yes** | New device must produce verified PRF; update all affected slots |
| Add ISOLATED recoverable entry | **Yes** | A physical normal entry policy; fresh physical proof on each read; all recovery/alternate DEK routes also require hardware |
| Add STRICT_NONE entry | **No code-dependent recovery slot** | Warn about intentional unrecoverability. If ISOLATED, normal access **still requires fresh physical hardware** |
| Add INDEPENDENT recovery route | **Yes**, dedicated entry code | Schema supported in design; user-facing setup deferred |
| Change master password and code+password slot | **Yes** | Current authenticating factors and new password |
| Rotate VMK or recovery code | **Yes** | Relevant old code + all factors needed to reconstruct dependent slots |

If prerequisites are missing, fail without advertising READY coverage. Old valid slots must not be destroyed before the new set is durable, verified and policy-compliant.

## Historical D-01–D-32 crosswalk

The numbering remains authoritative for traceability; this crosswalk does **not** revive superseded v0.3 behavior.

| D-ID | Approved meaning or disposition | Related reference |
| --- | --- | --- |
| D-01 | Normal vault unlock selects password+virtual or password+physical; virtual is not 2FA | DEC-KEY-02 |
| D-02 | VMK protects outer authenticated body only | DEC-KEY-01 |
| D-03 | Four entry policies with independent DEKs | DEC-KEY-02 |
| D-04 | Key lifetime; narrow masked-VERS/virtual-provider LOADED exceptions | DEC-SESSION-R5 |
| D-05 | LOADED metadata and inner ciphertext only | DEC-KEY-03 |
| D-06 | Reads without VMK; bounded staged transaction, fresh VMK at commit | DEC-TX-R6 |
| D-07 | Approved R1 recovery routes and Option A provisioning | DEC-REC-R1 |
| D-08 | Shared/group/independent/strict recovery scopes | DEC-REC-S3 |
| D-09 | Trusted authenticator scope, no physical→virtual fallback | DEC-PROV-S1 |
| D-10 | Separately paired clients | DEC-CLIENT |
| D-11 | E2E extension–daemon; opaque native host | DEC-CLIENT |
| D-12 | Complete weakest routes including recovery ancestry | DEC-REC-SCOPE |
| D-13 | Authenticated ancestry, revisions, tombstones | DEC-HIST-S4 |
| D-14 | Fill gesture and origin/frame binding | DEC-FILL |
| D-15 | Hotkey P2; credential typing P3/deferred | OPEN-TYPING |
| D-16 | Rewrap normal slot changes without unnecessary DEK rotation | DEC-KEY-01 |
| D-17 | Preserve 67 historical feature occurrences | Feature ledger |
| D-18 | Independent combiner, commitment, IPC and rollback review | OPEN-01/OPEN-15/OPEN-IPC |
| D-19 | **RESERVED** (no assigned historical decision) | — |
| D-20 | **RESERVED** (no assigned historical decision) | — |
| D-21 | Reads never implicitly write authoritative state | DEC-TELEMETRY |
| D-22 | Usage/diagnostics non-authoritative | DEC-TELEMETRY |
| D-23 | Software passkey signCount=0 is **PROVISIONAL** | OPEN-PASSKEY |
| D-24 | No cached VMK, KEK or DEK beyond named LOADED exceptions | DEC-KEY-03 |
| D-25 | Trusted local pinentry-style prompts | DEC-CLIENT |
| D-26 | Separate VMK/metadata and entry-DEK route reports | DEC-REC-SCOPE |
| D-27 | Sensitive entry envelopes not publicly enumerated | DEC-PRIVACY |
| D-28 | One active encrypted vault file, crash-safe temps/backups | DEC-HIST-S4 |
| D-29 | Entry-selected physical/virtual; fresh physical read | DEC-PROV-S1 |
| D-30 | Batched token rewrap remains **PROVISIONAL** pending OPEN-15 | OPEN-15 |
| D-31 | Isolated physical mandatory; recovery hardware or STRICT_NONE | DEC-REC-S2 |
| D-32 | Code-only recovery for password-only vaults exclusively | DEC-REC-R1 |

## C. Open independent reviews and decisions

| ID | Status | What must be settled before enabling |
| --- | --- | --- |
| **OPEN-01** | **BLOCKED — independent cryptographic review** | [V02-H pinned adversarial review packet](../security/V02H-adversarial-conformance-and-review-submission.md) adds independent Python/Rust **wire-only** byte vectors, malformed inputs and simulated route/KDF attacks, **not** vNext key/AEAD/HMAC security vectors or a commitment proof. A named qualified reviewer must assess final combiner/commitment, authenticated code/entry ancestry, KDF/Unicode limits, wire/version and migration; green CI/AI not approval |
| **OPEN-15** | **BLOCKED — independent security/device review** | [V02-J opt-in Linux/native CTAP test harness](../security/V02J-isolated-fido2-hardware-verification.md) can obtain signed native test assertions with libfido2 **only when an operator runs it with physical keys**. No physical token has been tested by this PR; no browser WebAuthn parity, actual registered Vaulty key, full I-P01–09 or qualified independent verdict exists. UV/UP/salt decisions remain OPEN |
| OPEN-HW-ASSURANCE | **OPEN — owner UV/UP decision, OPEN-15 review required** | [V02-I](../security/V02I-fido2-prf-isolation-and-hardware-assurance.md) proposes UV-required hardware default versus a separately disclosed lower-assurance CTAP UP-only profile; no policy selected, no WebAuthn PRF no-UV claim, no silent rewrap/downgrade, no device proof |
| OPEN-PRF-SALT | **PROVISIONAL — unapproved transcript, OPEN-01/15** | [V02-I synthetic input/salt derivation](../security/V02I-fido2-prf-isolation-and-hardware-assurance.md#2-test-only-per-entry-prf-evaluation-input-not-a-final-wire-version): entry/slot/credential/purpose/RP scoping and WebAuthn eval.first versus CTAP `SHA256("WebAuthn PRF"||0||input)` mapping need real-device interoperability and cryptographic review; cannot be activated |
| OPEN-REC-CONSENT | **OPEN — owner decision required before provisioning** | F-1: propose explicit **unpreselected per-entry opt-in** when any complete recovery route weakens a Standard entry's normal assurance; full ancestry/affected entries and warning/receipt. Do not silently create weak routes **or** default to STRICT_NONE. [V02-F proposed contract](../security/V02F-recovery-assurance-and-cryptographic-policy.md); not approved or implemented, no S2/R1 change |
| OPEN-KDF-PROFILE | **OPEN — owner target plus OPEN-01** | Argon2id production floor/ceiling, lanes, per-ceremony memory/CPU/concurrency budget, hostile-header resource gating and cross-platform benchmarks; 8 MiB fixture is **not** a default, 64 MiB/3-pass comparison **not** a decision. [V02-F benchmark plan](../security/V02F-recovery-assurance-and-cryptographic-policy.md#3-kdfpassword-policy-benchmark-plan-f-2) |
| OPEN-PASSWORD-ENC | **OPEN — owner interoperability decision plus OPEN-01** | Propose versioned `UTF8_NFC_v1` input bytes, no silent whitespace/case/compatibility changes and explicit old-version migration; no new source-level password conversion selected. [V02-F proposal](../security/V02F-recovery-assurance-and-cryptographic-policy.md#password-representation-proposed-utf8_nfc_v1-not-frozen) |
| OPEN-VNEXT-WIRE | **REVIEW-ONLY candidate, not owner-approved or production** | [V02-G V3RV proposal](../architecture/v02g-vnext-cryptographic-protocol-review.md) is now [V02-H wire/context-differential tested](../security/V02H-adversarial-conformance-and-review-submission.md), but **no authenticated vNext slot or approved committing AEAD** exists, nor complete authorization ancestry, real FIDO2 or final migration. No silent VLY2 reinterpretation |
| OPEN-ENC | **OPEN implementation/security review** | Exact authenticated single-file envelope, header leakage/padding, KDF cost caps, full input fuzzing and key/nonce binding |
| OPEN-ROLLBACK | **OPEN if claiming stronger guarantees** | Independent trusted anti-rollback anchor if protection from malicious historical-file replacement is required; S4 otherwise only warns about accidental divergences |
| OPEN-IPC | **OPEN independent protocol review** | Authenticated E2E pairing, key pinning/rotation, replay resistance and trusted local approval UI |
| OPEN-PASSKEY | **DEFERRED** | Separate software-passkey signing/counter and origin/RP security policy |
| OPEN-TYPING | **DEFERRED** | X11 default disabled, Wayland support conditional, Windows desktop focus checks; no universal secure typing promise |

Further historical open questions OPEN-02 through OPEN-14 are documented in [the v0.3 archive](../specification/history/v0.3-design-reference.md#19-open-decisions-and-required-design-reviews). They must be reconciled with v0.4.5 decisions before implementing those functions, rather than silently treated as settled.

## C1. Round-two security-review acceptance — qualifications, NOT decisions

The [round-two V02-H findings disposition](../security/V02H-round-two-review-disposition.md), based on merged `9d854a6`, accepts F-1–F-9 and W1/probe observations into the [security findings register](../roadmap/acceptance-register.md#2l-round-two-findings-acceptance-scoped-to-source-review-only). **This is engineering issue intake, not an APPROVED owner policy, independent OPEN-01 cryptographic verdict, OPEN-15 hardware verdict or READY authorization.**

- **Q1 / F-1:** A weaker, separately provisioned recovery route for a **Standard** entry is an owner-controlled alternative requiring explicit informed consent **before** provisioning; it is not automatically prohibited or approved. Preserve R1/S2/Option A, no implicit weak route and no silent `STRICT_NONE`. `OPEN-REC-CONSENT` remains **OPEN**.
- **Q2 / P6 / V3RV:** Existing V02-B HMAC verification before AEAD and P6's narrow forgery rejection do **not** prove multi-key commitment or justify an unconditional `2^-256` bound. V3RV wire/context interoperability does **not** test vNext key derivation, AEAD authentication or commitment (no vNext seal/open). `OPEN-01` remains **BLOCKED**.
- **Implementation/review follow-ups:** F-2/KDF and password bytes; F-3 scoped PRF salt; F-4 separate UP/UV assurance profiles; F-5 structural parity **closed only at that level**; F-6 authenticated vNext wire; F-7 verified hardware factor provenance; F-8 lifetime/zeroization audit; F-9 DEK-bound origin/username/title; W1 cross-slot ancestor/owner/nonce-per-key constraints, code entropy, historical rollback and versioning. See disposition table; all existing blocked gate states persist.

## C2. V02-I FIDO2 hardware policy proposals — NOT owner-approved

The [V02-I PRF isolation and two-key coverage packet](../security/V02I-fido2-prf-isolation-and-hardware-assurance.md) preserves approved S1/S2/R1/Option A and existing D-30 provisional batching. It proposes per-entry/credential PRF evaluation inputs and UV-required versus optional touch-only assurance choices; **it neither selects a hardware UV default nor approves a CTAP PRF salt**, enrolls an authenticator, or provisions a DEK slot. Each separately trusted token needs its own independently sealed route for each Isolated entry: registration of two vault-level tokens alone provides no backup entry access, and a physically absent backup cannot become READY. `OPEN-HW-ASSURANCE`, `OPEN-PRF-SALT`, `OPEN-15`, `OPEN-01`, and G1–G3 remain OPEN/BLOCKED. Weaker Standard recovery remains an owner decision under `OPEN-REC-CONSENT`.

## C3. V02-J local device-test foundation — no owner approval

The [V02-J hardware runbook](../security/V02J-isolated-fido2-hardware-verification.md) adds an operator-only libfido2 CLI that can register **lab credentials** and locally compare signed native CTAP PRF observations without storing output secrets. A test-session public credential is not a Vaulty trusted registration, a signed libfido2 assertion is not a browser-origin check, and a successful laboratory comparison is not an I-P01–09 or OPEN-15 verdict. The harness makes no owner decision for `OPEN-HW-ASSURANCE` or `OPEN-PRF-SALT`; S1/S2/R1/Option A, D-30 provisional batching, and the two qualified F-1/P6 round-two dispositions are unchanged. **OPEN-15/OPEN-01 and G1–G3 remain BLOCKED**.

## D. Decision changes

A proposal to alter an APPROVED row must include: previous requirement, concrete alternative, security/UX trade-offs, affected recovery/key paths, threat-model change, migration compatibility, independent review where appropriate, and explicit owner approval. Changing roadmap status does not itself approve cryptography. Newly discovered implementation-only gaps belong in the workstream acceptance register, not as demands for a repeat policy decision.
