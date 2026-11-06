# Vaulty v0.4.5 — Feature Roadmap & Traceability

**Baseline:** 6 November 2026. **Feature accounting:** 67 original checklist occurrences from the historical design map to 34 normalized functional requirements. v0.4.5 adds four new requirements (N-01…N-04) for **38 total**.  
**Normative source:** [v0.4.5 specification](../specification/v0.4.5.md). **Evidence:** [acceptance register](acceptance-register.md). **Delivery:** [implementation roadmap](implementation.md).

> A name in this table means the feature is within planned product scope, **not** that the code is complete. “Prototype” and “unit-tested” do not imply the full v0.4.5 policy or safe production. The old O-01…O-67 source wording/mapping is preserved verbatim in [v0.3 archival Appendix 21](../specification/history/v0.3-design-reference.md#21-original-feature-list-traceability-source-baseline). Its older cryptographic decisions are superseded by the current specification.

## Requirement ledger

| ID | Capability / acceptance scope | Delivery | Current implementation status |
| --- | --- | --- | --- |
| **FR-LIFE-01** | Start / initialize / terminate | V01/V03/V07A | Planned; default binary fails closed |
| **FR-LIFE-02** | Open / load existing vault; transient VMK then discard | V02/V03 | Planned |
| **FR-LIFE-03** | Lock / close; wipe masked VERS and provider state | V03 | Planned |
| **FR-LIFE-04** | Start / stop / status daemon | V07A | Prototype socket only |
| **FR-VLT-01** | Create canonical one-file vault; independent entry DEKs | V02–V04 | Planned |
| **FR-ENT-01** | Add entry, independent DEK + VMK-authorized index write | V05 | Planned |
| **FR-ENT-02** | Edit entry, entry factors + VMK-authorized transaction | V05 | Planned |
| **FR-ENT-03** | Update stored credential vs entry-protection password | V05/V08B | Planned |
| **FR-ENT-04** | List authenticated metadata without decrypting entries | V05 | Planned |
| **FR-ENT-05** | Get / partial preview / explicit reveal | V05/V08B | Planned |
| **FR-ENT-06** | Remove entry, indexes, slots + tombstones | V05 | Planned |
| **FR-ENT-07** | Verify default entry via masked VERS + selected provider; no VMK read | V03/V05 | Planned |
| **FR-AUTH-01** | Password + virtual vs physical FIDO2 normal modes; weakest-route display | V03 | Planned |
| **FR-AUTH-02** | FIDO2 enrollment / use / verification / revocation | V03/V06 | Legacy partial; no policy engine |
| **FR-AUTH-03** | Master password change by reviewed slot rewrap | V04/V06 | Fail-closed stub |
| **FR-AUTH-04** | Bounded retry UX (not offline brute-force protection) | V03/V07A | Planned |
| **FR-DEV-01** | Distinct trusted authenticator and client inventory | V06/V07 | Planned |
| **FR-GEN-01** | CSPRNG password generator; selectable policy without modulo bias | V01/V08B | Prototype unit-tested; main disabled |
| **FR-CRY-01** | Argon2id/HKDF/AEAD/nonce and reviewed key commitment | V02 | Legacy helper only; OPEN-01 blocked |
| **FR-SEC-01** | Secret lifetimes; masked VERS/virtual adapter while LOADED | V03/V05 | Planned |
| **FR-PKY-01** | Software / hardware passkeys with RP-bound assertions | V08C | Deferred, separately gated |
| **FR-HOT-01** | Register and manage global shortcut activation | V08A | Prototype code; disabled |
| **FR-HOT-02** | Shortcut-assisted operation; risky typing optional | V08A | Deferred typing; no bypass allowed |
| **FR-CLI-01** | Secure password/confirm and yes/no UI | V07A | Legacy partial; main disabled |
| **FR-CLI-02** | CLI CRUD / devices / recovery via policy engine | V07A | Planned |
| **FR-CLI-03** | List separate authenticator and client states | V07A | Planned |
| **FR-IPC-01** | Bounded authenticated local IPC / opaque native relay | V07 | Mock socket only |
| **FR-IPC-02** | Owner-approved paired scoped client identity | V07 | Planned |
| **FR-IPC-03** | User-initiated fill with origin/frame and E2E binding | V08B | Extension prototype; no E2E |
| **FR-IPC-04** | Save/register through relay and durable receipt | V08B/V08C | Native mock returns false success |
| **FR-STO-01** | Atomic authenticated file writes + previous generation + ancestry | V02 | V01 partial writer tests; canonical format missing |
| **FR-REC-01** | Provisioned VMK/VERS recovery, permitted code-only routes | V04 | Planned; Option A approved |
| **FR-REC-02** | Lost hardware recovery and code-dependent new-device slots | V04/V06 | Planned; Option A approved |
| **FR-REC-03** | Backup authenticator and verified rewrap coverage | V06 | Planned |
| **FR-MIG-01** | N-01: verified legacy format migration (P0) | V04M-1 | Planned |
| **FR-XFER-01** | N-02: vault-to-vault copy/move (P1) | V04M-2 | Planned |
| **FR-MERGE-01** | N-03: manual merge of distinct vaults (P2) | V04M-3 | Planned |
| **FR-SYNC-01** | N-04: automatic sync-conflict merge (P3) | Post-V09 | Deferred |

## The four new v0.4.5 features

| Feature | Priority | Scope / negative constraint |
| --- | --- | --- |
| N-01 → FR-MIG-01 | **P0** | Safe old-format import, backup, bounded decrypt, fresh canonical destination, verified reopen. Never auto-upgrade unknown or malformed files. |
| N-02 → FR-XFER-01 | **P1** | Selective vault-to-vault copy/move; authenticate both sides and re-encrypt for destination, verify durable destination before deleting source. |
| N-03 → FR-MERGE-01 | **P2** | Explicit distinct-vault merge, with user-resolved ID/content/policy/ancestry conflicts, no silent trust transplant or policy weakening. |
| N-04 → FR-SYNC-01 | **P3 (deferred)** | Automatic synchronization-conflict merge; separate distributed trust/rollback threat model. Not implied by N-03. |

N-01, N-02 and N-03 should share vetted import/transaction primitives but require different operation-level authorization and user review.

## Source-feature preservation

The immutable historical baseline contains **exactly 67** O-ID occurrences across ten groups: Product (14), Start (4), CLI (14), Vault (12), Crypto (10), Fido (2), Socket (6), Hotkey (1), IO–File (1), Recovery (3). Duplicate occurrences are intentional. Every original O-ID points to one of the 34 preexisting FR-IDs; the 4 new FRs do not alter that history.

No original feature intent is silently removed. Existing `O-01`…`O-67` mappings are an accounting baseline, not an implementation claim.

## Status update requirements for every feature PR

1. Link FR/O/N identifiers and the approved security decision(s) in the PR.
2. Link merged commit and relevant CI, negative tests, reviewer disposition and any migration/rollback consequence.
3. Update the implementation stage, blocker and acceptance register **in the same PR**.
4. Report separately: design approved, implementation merged, tests verified, security review approved and production release gate.
5. Never mark a feature complete merely because reference route graphs, placeholder structs, mock native-host results or synthetic crypto vectors exist.

**Current recommended next work:** V01-A security closure, then V02 canonical format (OPEN-01 independent review required). See [implementation roadmap](implementation.md).
