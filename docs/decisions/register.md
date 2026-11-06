# Vaulty — Design Decisions and Open Review Register

**Snapshot:** 2026-11-06 | **Target:** v0.4.5. Decisions here describe **approved product policy**, not implementation status.  
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
| **OPEN-01** | **BLOCKED — independent cryptographic review** | Reviewed factor combiner and key commitment, canonical transcript/slot/AAD binding, multi-key substitution resistance and negative cross-language vectors. Candidate KEK probes are **not approved** |
| **OPEN-15** | **BLOCKED — independent security/device review** | FIDO2 PRF scope and salts (vault/credential/entry/slot/purpose), UV/UP freshness, allowed batching/fanout, device capability fallback, hardware proof and recovery re-enrollment |
| OPEN-ENC | **OPEN implementation/security review** | Exact authenticated single-file envelope, header leakage/padding, KDF cost caps, full input fuzzing and key/nonce binding |
| OPEN-ROLLBACK | **OPEN if claiming stronger guarantees** | Independent trusted anti-rollback anchor if protection from malicious historical-file replacement is required; S4 otherwise only warns about accidental divergences |
| OPEN-IPC | **OPEN independent protocol review** | Authenticated E2E pairing, key pinning/rotation, replay resistance and trusted local approval UI |
| OPEN-PASSKEY | **DEFERRED** | Separate software-passkey signing/counter and origin/RP security policy |
| OPEN-TYPING | **DEFERRED** | X11 default disabled, Wayland support conditional, Windows desktop focus checks; no universal secure typing promise |

Further historical open questions OPEN-02 through OPEN-14 are documented in [the v0.3 archive](../specification/history/v0.3-design-reference.md#19-open-decisions-and-required-design-reviews). They must be reconciled with v0.4.5 decisions before implementing those functions, rather than silently treated as settled.

## D. Decision changes

A proposal to alter an APPROVED row must include: previous requirement, concrete alternative, security/UX trade-offs, affected recovery/key paths, threat-model change, migration compatibility, independent review where appropriate, and explicit owner approval. Changing roadmap status does not itself approve cryptography. Newly discovered implementation-only gaps belong in the workstream acceptance register, not as demands for a repeat policy decision.
