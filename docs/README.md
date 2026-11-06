# Vaulty Documentation Index

**Canonical design target:** **v0.4.5**, 6 November 2026.  
**Implementation reference:** GitHub `main` `6bc733b` ([V02-A PR #9 merged](https://github.com/BetrayedByEthanol/Pw_Manager/pull/9), review packet only), following [V02 PR #8](https://github.com/BetrayedByEthanol/Pw_Manager/pull/8). [V02-B PR #10](https://github.com/BetrayedByEthanol/Pw_Manager/pull/10) is an unmerged review-only crypto candidate. Independent approval is not obtained.  
**Safety status:** Prototype foundation builds and tests; **not safe for real credentials and not security-certified**.

Start here rather than relying on previous chats or the historical README feature checklist.

## Current project documents

| Document | Purpose | Authority |
| --- | --- | --- |
| [Product & security specification v0.4.5](specification/v0.4.5.md) | Normative behavior, keys, states, entry policies, recovery, client trust and migration | **Canonical design** |
| [V02 candidate vault format v0](architecture/v02-format-candidate.md) | Merged experimental binary schema, independent keys, AEAD, strict parsing and explicit OPEN-01/15 limitations | **Candidate only; not approved runtime or frozen wire format** |
| [V02-A cryptographic protocol and key-slot review](architecture/v02a-crypto-keyslot-review.md) | Merged protocol gaps, transcript questions, recovery/PRF threat matrix and independent reviewer exit criteria | **Merged design; not approved cryptography** |
| [V02-B candidate key-slot cryptography](architecture/v02b-keyslot-candidate.md) | Private test-only Argon2id/HKDF/AEAD/HMAC prototype, scoped descriptor and negative tests | **PR #10 in review; NOT activated or approved** |
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

**V02-B — Review-gated Key-Slot Cryptography Candidate**, following merged V02-A [PR #9](https://github.com/BetrayedByEthanol/Pw_Manager/pull/9). [Prototype contract](architecture/v02b-keyslot-candidate.md) describes bounded, internal-only synthetic wrapping and tests. OPEN-01/15 independent approval, final wire format and real hardware/daemon integration remain required before G1/G2 acceptance or any credential use.
