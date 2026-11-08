# Vaulty Documentation Index

**Canonical design target:** **v0.4.5**, 6 November 2026.  
**Implementation reference:** GitHub `main` at V02-K PR #20 merge `f65615e8` (review-only Rust FIDO2 local runner). [EV-023 operator local hardware observations](security/V02K-local-hardware-evidence-received-2026-11-08.md) received for two reported YubiKey 5 NFC USB-A firmware 5.7.4 devices. **These are not independently verified; OPEN-01/15 and G1–G3 BLOCKED.**  
**Safety status:** Prototype foundation builds and tests; **not safe for real credentials and not security-certified**.

Start here rather than relying on previous chats or the historical README feature checklist.

## Current project documents

| Document | Purpose | Authority |
| --- | --- | --- |
| [Product & security specification v0.4.5](specification/v0.4.5.md) | Normative behavior, keys, states, entry policies, recovery, client trust and migration | **Canonical design** |
| [V02 candidate vault format v0](architecture/v02-format-candidate.md) | Merged experimental binary schema, independent keys, AEAD, strict parsing and explicit OPEN-01/15 limitations | **Candidate only; not approved runtime or frozen wire format** |
| [V02-A cryptographic protocol and key-slot review](architecture/v02a-crypto-keyslot-review.md) | Merged protocol gaps, transcript questions, recovery/PRF threat matrix and independent reviewer exit criteria | **Merged design; not approved cryptography** |
| [V02-B candidate key-slot cryptography](architecture/v02b-keyslot-candidate.md) | Merged private Argon2id/HKDF/AEAD/HMAC prototype and negative tests | **Merged, NOT activated or approved** |
| [V02-C cryptographic conformance and security verification](security/V02C-cryptographic-conformance.md) | Merged frozen cross-library KATs, adversarial byte/descriptor tests and independent review handoff | **Merged, NOT external approval or real hardware evidence** |
| [V02-D independent cryptographic review handoff](security/V02D-independent-review-handoff.md) | Merged source-hash manifest, 12 security gaps, recovery/hardware route tests and reviewer/device verdict templates | **Merged; OPEN-01/15 still BLOCKED** |
| [V02-E cryptographic review findings and pre-approval hardening](security/V02E-review-findings-and-preapproval-hardening.md) | Merged F-1–F-9 dispositions, shared route validator, partial memory and origin-integrity hardening, vNext test-only AAD | **Merged candidate only; no independent approval** |
| [V02-F recovery assurance and cryptographic policy decisions](security/V02F-recovery-assurance-and-cryptographic-policy.md) | Merged proposals for weaker-recovery informed consent, root-separated assurance, KDF benchmarking/work caps, NFC/UTF-8 encoding and code scopes | **Merged proposal; new owner/expert decisions open** |
| [V02-G cryptographic vNext review candidate](architecture/v02g-vnext-cryptographic-protocol-review.md) | Merged V3RV review-only frame/descriptor, strict test codec and proposed typed-factor transcript | **Merged test-only; no authenticated keys/approved wire** |
| [V02-H adversarial conformance and external review submission](security/V02H-adversarial-conformance-and-review-submission.md) | Merged two-language V3RV wire/context vectors, mutation/ancestry/KDF reference cases, source-pinned unsigned expert packet | **Merged internal evidence; OPEN-01/15 blocked** |
| [Round-two V02-H security-review findings](security/V02H-round-two-review-disposition.md) | F-1–F-9/W1 accepted for follow-up; owner controls weaker Standard recovery and P6/HMAC/V3RV are not security proof | **Merged issue register, NOT approval** |
| [V02-I FIDO2 PRF isolation & hardware assurance](security/V02I-fido2-prf-isolation-and-hardware-assurance.md) | Merged proposed entry-specific PRF salt input, two-token Isolated coverage and UV versus touch-only questions | **Merged public-input review only; no hardware proof** |
| [V02-J local FIDO2 hardware verification foundation](security/V02J-isolated-fido2-hardware-verification.md) | Merged opt-in libfido2 test harness, offline mock tests and I-P01–09 runbook | **No physical operation in V02-J merge CI; see later V02-K EV-023 observations** |
| [V02-K Rust physical test runner & evidence intake](security/V02K-physical-fido2-verification-and-evidence.md) | Merged Rust runner, partial I-P matrix and strict redaction | **Local operator results received; NOT independent OPEN-15 verification** |
| [V02-K EV-023 operator evidence received](security/V02K-local-hardware-evidence-received-2026-11-08.md) | Source-pinned redacted owner report; primary/backup model and firmware; I-P01–09 coverage and residual reviewer work | **RECEIVED, not VERIFIED; all release gates blocked** |
| [V02-L-A/B native FIDO2 negative/failure probes](security/V02L-native-fido2-negative-and-failure-verification.md) | Review-only native signed assertion mutations, UV/UP checks, wrong-device positive controls and private redacted receipts | **PR candidate; device execution pending, OPEN-15 blocked** |
| [Architecture v0.4.5](architecture/v0.4.5.md) | System components, single-file structure, trust boundaries, key flows and operation sequences | **Target design** |
| [Implementation roadmap](roadmap/implementation.md) | V01-A through V09, V04M workstream, dependencies and release gates | **Work plan** |
| [Feature roadmap](roadmap/features.md) | All 38 normalized requirements, four N-features and links to the 67 historical source items | **Feature ledger** |
| [Acceptance and evidence register](roadmap/acceptance-register.md) | PR/commit/CI proof, current V01 checks, security gaps and gate status | **Verification ledger** |
| [Decision & open-review register](decisions/register.md) | Approved S1–S4/Option A decisions, deferred scope, OPEN-01/OPEN-15 and approval boundaries | **Decision register** |
| [V01 prototype safety foundation](roadmap/V01-prototype-safety.md) | Historical implementation scope and explicit limitations | **Merged baseline + acceptance pending** |
| [Forgejo CI migration](ci/forgejo-actions.md) | GitHub/Forgejo workflow parity and runner requirements | **Infrastructure runbook** |
| [V01-A failure and stale-lock recovery](security/V01A-failure-recovery.md) | Operator steps for interrupted legacy writes, lock handling and native-host unavailable behavior | **V01-A merged; not a security certificate** |
| [v0.3 historical design](specification/history/v0.3-design-reference.md) | Full earlier 67-item O-ID traceability and pre-v0.4 rationale | **Superseded archival source** |
| [Crypto review request](../tools/security_probes/CRYPTO_REVIEW_REQUEST.md) | Candidate OPEN-01/15 evaluation requested of independent reviewer | **Not approved crypto** |

## Normative precedence

1. Newer **explicitly approved** decision/ADR for the affected requirement.
2. [Canonical v0.4.5 specification](specification/v0.4.5.md) and [decision register](decisions/register.md).
3. [Architecture](architecture/v0.4.5.md) implementing those constraints.
4. Roadmap, feature and evidence ledgers track work but cannot authorize behavior or rewrite cryptography.
5. Historic archived documents and pre-v0.4 source README are source history only.

The version number v0.4.5 describes the **design**, not the shipping application. The current binary intentionally exits nonzero, the native host fails closed and the daemon is not a trusted authorization service and policy probes are reference checkers. No release gate is certified merely by green CI.

## Change protocol

Each PR affecting keys, policy, recovery, storage, migration or client behavior must link:

- At least one stable FR identifier from the feature roadmap and affected decision IDs.
- Updated design/architecture sections if semantics changed.
- Explicit acceptance test(s), failure/negative coverage and merged CI evidence.
- Updated implementation status, blocker owners, independent review requirements and migration/rollback implications.
- A concrete statement of what remains unimplemented.

**Do not infer completion from a plan**, placeholder code, demonstration output or a synthetic crypto fixture. When source and design differ, mark the gap rather than changing the design to fit broken source.

## Recommended immediate milestone

**V02-H — Adversarial Cryptographic Conformance & Independent Review Submission**, following merged [V02-G PR #15](https://github.com/BetrayedByEthanol/Pw_Manager/pull/15). [Source-pinned attack/reviewer packet](security/V02H-adversarial-conformance-and-review-submission.md) offers independently coded **wire-only** cross-language checks and adversarial scenarios. Next step is named independent OPEN-01 cryptographer and parallel OPEN-15 physical FIDO2 tests; no unapproved vNext cryptography or real credential use.
