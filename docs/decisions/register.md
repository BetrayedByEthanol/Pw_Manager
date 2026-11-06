# Vaulty — Design Decisions and Open Review Register

**Snapshot:** 2026-11-06 | **Target:** v0.4.5. Decisions here describe **approved product policy**, not implementation status.  
**Canonical spec:** [v0.4.5](../specification/v0.4.5.md) | **Current evidence:** [acceptance register](../roadmap/acceptance-register.md)

**Status meanings:** APPROVED (owner-selected target), PROVISIONAL (direction allowed for review but not security approval), OPEN (needs a protocol decision/review), DEFERRED (explicitly outside current release), SUPERSEDED (historical only).

Historical v0.3 decision IDs D-01…D-18 are retained in [the full archive](../specification/history/v0.3-design-reference.md#decision-register). The v0.4.5 additions below use descriptive stable IDs rather than manufacturing an unverified reconstruction of the previous document's later numbering. Any formally numbered ADR should record which older item it supersedes.

## A. Approved current product decisions

| ID | Topic | Status | Binding consequence / not yet implemented |
| --- | --- | --- | --- |
| DEC-KEY-01 | Independent VMK and entry keys | **APPROVED** | One VMK-authenticated outer body, independently encrypted entry ciphertext; VMK never derives/unlocks VERS/entry DEK |
| DEC-KEY-02 | Four entry modes | **APPROVED** | Default/custom first component, virtual/physical second component; every entry has its own random DEK |
| DEC-KEY-03 | LOADED masked VERS | **APPROVED v0.4; overrides v0.3 D-04/05** | Retain only rotating two-share XOR representation of VERS; reconstruct for bounded operation, clear plaintext and temporary KEKs/DEKs. Do not claim full memory-compromise resistance |
| DEC-KEY-04 | Virtual adapter lifetime | **APPROVED v0.4** | Minimal software PRF available while LOADED; helper/protocol parity, not independent 2FA; avoid default master-password re-prompt on reads |
| DEC-KEY-05 | Read/write distinction | **APPROVED** | Reads use entry factors without VMK; writes require fresh VMK plus relevant entry authorization |
| DEC-PROV-S1 | Entry-selected provider | **APPROVED** | Physical entries require fresh physical PRF on *each* read, no virtual fallback; virtual entries use software even if hardware is enrolled |
| DEC-REC-S2 | ISOLATED route requirements | **APPROVED** | Every complete isolated entry-DEK route requires actual hardware; otherwise STRICT_NONE. No code-only isolated recovery |
| DEC-REC-S3 | INDEPENDENT schema | **APPROVED / UI DEFERRED** | Retain/check INDEPENDENT policy and dedicated entry code in model/tests, defer user-facing enrollment |
| DEC-HIST-S4 | Authenticated ancestry | **APPROVED** | Bind generations/hashes/tombstones; local last-seen accidental rollback warning, not malicious rollback proof |
| DEC-REC-A | Option A slot provisioning | **APPROVED** | Require recovery code **when creating/replacing code-dependent slot**; new token also needs new token PRF; inactive until coverage verified; read/edit through existing route needs no code |
| DEC-REC-CODE | Permitted code-only recovery | **APPROVED (with disclosure)** | Explicitly provisioned repair-only code-only slot for allowed non-isolated targets; no implicit hardware factor or normal stealth unlock |
| DEC-REC-COVERAGE | Coverage states | **APPROVED** | READY/PENDING/MISSING/DEGRADED/UNVERIFIED/STRICT_NONE; never report new slot ready without actually producing/verifying envelope |
| DEC-REC-SCOPE | Outer vs entry recovery | **APPROVED** | Recovery of VMK does not grant VERS or entry DEK; independent slots and their factor scope are required |
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
| Add ISOLATED recoverable entry | **Yes** | Authorized physical hardware; every path remains hardware-mandatory |
| Add STRICT_NONE entry | **No code-dependent recovery slot** | Warn about intentional unrecoverability |
| Add INDEPENDENT recovery route | **Yes**, dedicated entry code | Schema supported in design; user-facing setup deferred |
| Change master password and code+password slot | **Yes** | Current authenticating factors and new password |
| Rotate VMK or recovery code | **Yes** | Relevant old code + all factors needed to reconstruct dependent slots |

If prerequisites are missing, fail without advertising READY coverage. Old valid slots must not be destroyed before the new set is durable, verified and policy-compliant.

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
