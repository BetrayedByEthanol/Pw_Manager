# V02-E — Cryptographic Review Findings & Pre-Approval Hardening

**Status:** INTERNAL PRE-APPROVAL HARDENING CANDIDATE — **NOT APPROVED OR ACTIVATED**. Prepared 2026-11-07 after merged [V02-D PR #12](https://github.com/BetrayedByEthanol/Pw_Manager/pull/12) at `08815be06fa0bb45386c1c791b14463e29ac0672`.

**Input:** An AI-assisted (Claude) scratch security assessment dated 2026-11-07, with six reviewer probes P1–P6 and findings F-1–F-9. This is **not a qualified independent OPEN-01 reviewer verdict** even though the report uses the phrase "approved with required changes." Treat its source excerpts, probes and suggestions as security-review hypotheses checked against the repository and canonical [v0.4.5 specification](../specification/v0.4.5.md), **not** a protocol change authorization.

**Review source of truth:** [v0.4.5](../specification/v0.4.5.md), [decision register](../decisions/register.md), [V02-D reviewer handoff](V02D-independent-review-handoff.md), [V02-B candidate transcript](../architecture/v02b-keyslot-candidate.md), and [V02-C frozen known-answer tests](V02C-cryptographic-conformance.md).

## 1. Accepted technical findings vs unresolved decisions

| Finding | Confirmed behavior in reviewed code | V02-E action and disposition | Unmet external/owner gate |
| --- | --- | --- | --- |
| **F-1 — weaker Standard recovery** | A password-only vault's **separately created** code-only entry-DEK slot can unwrap a Standard physical/custom entry, while Isolated code-only entry-DEK recovery is forbidden. **Code-only VMK recovery alone does not unlock every Standard DEK**; VERS/DEK routes remain separate. | **Preserve existing structural allowance**. Candidate negative/positive tests document weakest alternative; propose **explicit per-entry owner opt-in**, before sealing a weaker recovery envelope, with a separate normal vs recovery assurance report. **No implicit slot or consent receipt created**. | Owner decision on exact consent/default policy; V04 trusted prompts, Option A code collection, and runtime effective-route closure |
| **F-2 — Argon2id cost** | Internal test lower bound 8 MiB / two passes / one lane is NOT a production minimum; high values can amplify pre-auth work. | Keep frozen V02-C Argon2 KAT and candidate limits unchanged. Specify a **provisional benchmark target** (64 MiB, three passes), hard bounds, total per-request pre-auth work budget, reuse of identical pre-KDF contexts, and explicit password byte encoding. **No cost selected or enforced in runtime**. | Platform benchmarks, owner UX/performance acceptance and OPEN-01 cost/DoS review |
| **F-3 — scoped PRF salt** | `EntrySlotPurpose` is an authenticated label but `prf_salt` is free-form; two Isolated slots can declare the same credential+salt and use the same captured PRF output. Different slot IDs still yield different KEKs but shared *factor material* increases blast radius. | Preserve frozen V02-B transcript. Require a future **canonical per-entry/per-slot and credential-specific PRF salt derivation** with cross-slot uniqueness checks, documented shared-root fanout and loss/re-enrollment behavior. | OPEN-15 real device scope and batching tests; reviewed KDF/PRF transcript and versioning |
| **F-4 — UV=false** | The candidate accepts UV=false while requiring UP; this bit binds to the transcript but does not prove a device operation. | **Do not silently force UV=true**: current specification pins the enrolled mode and forbids downgrade but does not mandate universal UV. Test and document the unresolved behavior. | OPEN-15 approved device/UV policy and per-read verified assertion |
| **F-5 — validator divergence** | VLY2's `Slot`, `EntryRecord`, `VaultBody` formerly admitted invalid root/seed/entry routes rejected by V02-B `Descriptor`. | **HARDENED in V02-E:** `model::route_is_allowed` is a common *structural* predicate for both, with exhaustive model-vs-descriptor test matrix (all vault modes, targets, policies, entry modes, tiers and recovery policies). Invalid VLY2 pending descriptors now fail closed. | Trusted owner/revocation registry and complete runtime ancestry remain V03–V06 |
| **F-6 — missing wire format** | VLY2's legacy pending 48-byte slot lacks KDF/PRF/commitment fields. | **NO FORMAT CHANGE**: keep existing VLY2 bytes and V02-C vectors. Future slot format must be explicitly versioned, strict-decoded/re-encoded, authenticated and migrated only after approval. | OPEN-01 approved portable protocol and migration plan |
| **F-7 — physical provenance** | `Components` can take arbitrary synthetic bytes; no verified FIDO2 assertion or fresh touch is in this private module. | Keep candidate inaccessible to runtime. Explicitly forbid extrapolating descriptor scope/UV to hardware proof; plan private verified-factor types with device-owned constructors. | OPEN-15 + V03/V06 real authenticators and real-device tests |
| **F-8 — secret lifetime** | Candidate IKM used heap `Zeroizing<Vec<u8>>`; library-internal HKDF/HMAC/Argon2 scratch handling is not proven wiped. | **HARDENED PARTIALLY:** replace candidate IKM with fixed-capacity `Zeroizing<[u8;128]>`, eliminating heap scratch reallocation/residual capacity. Maintain zeroized outputs. Preserve original transcript and KATs. **No assertion that dependent crypto crates, OS swap, allocator or all Argon2 scratch memory are wiped**. | Detailed crate-feature/memory-lifetime audit, failure/timeout tests and independent OPEN-01 |
| **F-9 — origin not DEK-bound** | VLY2 entry AAD binds vault/entry IDs, revision and policy, **not origin, username or title**. Changing them under a VMK alone can misdirect later use even though entry plaintext remains encrypted. | **HARDENED PARTIALLY:** normal `prepare_successor` and `storage::commit_candidate` transition checking rejects metadata-only changes without fresh **nonce and ciphertext**. A **test-only future-version AAD** prototype binds origin/username/title with explicit lengths and distinct domain; demonstrates tampering fails under DEK without silently altering VLY2. | A new authenticated entry payload format, authorized origin/frame normalization, migration, and browser fill E2E checks. Low-level `seal_file` bypasses this transition guard and is NOT owner authorization. |

**Other reviewer observations:** old encrypted `previous-<uuid>` snapshots remain a rotation exposure (approved R8 purge-on-rotate, **not implemented**); rollback protection is local accidental-divergence detection only (S4); metadata leakage/privacy budgets and library dependency audits remain release work. No claim of a secure password manager follows from green candidate tests.

## 2. Source/test changes and threat boundaries

- `src/v02/model.rs`: common `route_is_allowed` permits root/seed normal and recovery routes only for the correct vault mode, and entry-DEK normal/recovery routes according to entry mode/tier/recovery and S2/STRICT_NONE. **Standard** separately provisioned weaker recovery stays structurally representable (F-1 is not "fixed" by forcing STRICT_NONE).
- `src/v02/v02b.rs`: calls the **same structural predicate** before bound provider and password-parameter checks. The IKM is built in a zeroizing fixed array; the HKDF input prefix, salt and labels are **identical to frozen V02-C**. Physical provider metadata remains untrusted until device verification.
- `src/v02/v02e_tests.rs`: exhaustive route-policy parity across all two vault modes, all four targets, nine route factors, four entry modes, two tiers and four recovery policies; explicit tests for weaker Standard recovery and unresolved UV/salt risks; future-version DEK-AAD metadata-tamper test.
- `src/v02/mod.rs` and `src/v02/tests.rs`: revisioned metadata changes require a **fresh DEK-encrypted entry ciphertext and nonce** on normal successor and disk commit paths. The updated checks are not a cryptographic bind of metadata to the existing VLY2 entry AEAD; a malicious VMK writer or direct low-level `seal_file` remains outside normal writer authorization. More robust defense needs a **versioned AAD/payload change**.
- `src/v02/entry_binding_candidate.rs` is compiled **only under `#[cfg(test)]`** and uses a wholly separate vNext domain. It does not write or reinterpret VLY2. No test-only deterministic nonce is used in the application.

**Replay:**
```sh
cargo check --manifest-path tools/v02_verifier/Cargo.toml --locked --all-targets
cargo test --manifest-path tools/v02_verifier/Cargo.toml --locked --all-targets
python3 tools/v02_verifier/reference_v02c.py --verify
python3 -m unittest discover -s tools/v02_verifier -p 'test_review_bundle.py'
python3 tools/v02_verifier/review_bundle.py --write /tmp/v02e-review-inventory.json
python3 tools/v02_verifier/review_bundle.py --check /tmp/v02e-review-inventory.json
```

**This is an inactive candidate.** The main binary must still exit failure; no real credential support, hardware factor unlock, `READY` transition, silent VLY2 migration, new recovery path provisioning or permission to fill in a browser.

## 3. Decisions deliberately NOT made in V02-E

1. **F-1:** Should Standard physical/custom-password recovery that omits the normal entry factor be an explicit per-entry opt-in? Proposed **yes**, with default recovery selected explicitly during entry setup, and a warning showing exactly what a stolen recovery code can unlock. Do not silently default to STRICT_NONE or silently create weaker routes. Owner approval needed for final UI/receipt rules.
2. **F-2:** Candidate Argon2id recommendation for benchmarking: **64 MiB / three passes** (not a locked production minimum). Select by measured runtime, available memory, concurrency/DoS budget, entropy assumptions and device classes; define exact UTF-8/normalization policy before production. Raising the existing fixture floor would invalidate V02-C KATs and must use a new candidate version.
3. **F-3:** Specify salt derivation for physical and code-derived recovery materials, with distinct isolated entry roots and expected PRF fanout; review per-credential and per-scope PRF behavior. **No new PRF salt rule is approved by this test package.**
4. **F-4:** Which enrolled authenticator flows require UV (PIN/biometric) versus UP? No automatic UV downgrade; require **OPEN-15 device evidence** before a universal UV requirement or a UP-only option.
5. **F-6:** Final authenticated slot/entry wire protocol requires an independent OPEN-01 verdict and explicit upgrade strategy; **no VLY2 reinterpretation**.

The reviewer’s short key-commitment argument and P6 altered-AEAD ciphertext rejection are useful **hypotheses**, not a defined multi-key commitment security proof. The review phrase "approved with required changes" **does not qualify for OPEN-01**. Ask an independent cryptographer to specify the exact commitment notion, threat model, any attack or construction revision, and a signed/recorded verdict tied to the final protocol and code.

## 4. Acceptance and next security gates

**Candidate-only checks:** shared route parity and negative fixtures, unchanged cross-library HKDF/HMAC/AEAD KATs, transition guards for metadata edits, test-only future vNext DEK binding, unit/root/Forgejo workflow parity, source-manifest recheck, no production entry activation.

**Unchanged release states:** OPEN-01 **BLOCKED**, OPEN-15 **BLOCKED**, G1/G2/G3 **BLOCKED**, V03/V04/V05/V06 owner-approved recovery and trusted device paths not implemented, F-1/2/3/4/6 decisions unresolved. V02-E may merge as a hardening and review-readiness package after code review/CI, **not** as independent crypto certification.

**Recommended follow-up after V02-E:** obtain owner disposition on F-1 recovery opt-in and F-4 UV; benchmark F-2 Argon2id and F-3 real FIDO2 PRF behavior under OPEN-15; submit resulting explicit new wire proposal under OPEN-01; develop V03/V04 candidate APIs only behind review gates.
