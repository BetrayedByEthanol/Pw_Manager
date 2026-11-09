# Vaulty — Acceptance, Evidence and Security Gap Register

**Snapshot date:** 2026-11-09 | **Merged source baseline:** [V03-C PR #28](https://github.com/BetrayedByEthanol/Pw_Manager/pull/28), commit `0d2881acf6d5382bd93423b0c04f477d582074af`. **Local self-reported evidence received:** [EV-023 V02-K native PRF stability/scope](../security/V02K-local-hardware-evidence-received-2026-11-08.md) and [EV-025 V02-L negative verifier/wrong-key observations](../security/V02L-local-hardware-negative-evidence-received-2026-11-09.md). **No independent OPEN-15, OPEN-01 or G1–G3 approval; no actual Vaulty entry unlocked.**  
**Purpose:** provide a reviewable distinction between **design approved**, **source merged**, **CI passed**, **security behavior verified** and **release certified**. None is interchangeable. See [implementation roadmap](implementation.md).

## 1. Recorded merged evidence

| ID | Record | Verified observation | What it does NOT establish |
| --- | --- | --- | --- |
| EV-001 | [PR #1](https://github.com/BetrayedByEthanol/Pw_Manager/pull/1) | Python/Rust reference route graph and candidate KEK vectors merged | Neither canonical runtime enforcement nor independent approval of OPEN-01 |
| EV-002 | [PR #3](https://github.com/BetrayedByEthanol/Pw_Manager/pull/3) | S1–S3 owner policy and recovery-route checks added to reference probes | Does not implement physical/virtual runtime authorization or S4 file ancestry |
| EV-003 | [PR #4](https://github.com/BetrayedByEthanol/Pw_Manager/pull/4) | V01 prototype patches merged (nonce refresh, fail-closed default binary, bounded body parsing, writer/lock, unit tests) | Not production cryptography, safe legacy migration or external security review |
| EV-004 | [PR #5](https://github.com/BetrayedByEthanol/Pw_Manager/pull/5) | Linux native dependencies fixed, GitHub/Forgejo parity workflow files added, `CharSet::EMPTY` compilation fix; merged | Forgejo runner has not executed |
| EV-005 | [V01 workflow on merged main](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42217284380) | GitHub V01 jobs succeeded on merge commit `7c3ba719`: root Rust compilation + 11 root unit tests, native host build/test command, JS/manifest syntax | Root tests are not broad integration tests; native host crate ran 0 tests in inspected PR run |
| EV-006 | [Security probes on merged main](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42217284398) | GitHub Rust/Python reference probe jobs succeeded on merge commit `7c3ba719` | Synthetic policy/crypto vectors do not prove runtime encryption or authorization |
| EV-007 | [Independent cryptography review request](../../tools/security_probes/CRYPTO_REVIEW_REQUEST.md) | Review requirements and candidate construction documented; current disposition explicitly NOT APPROVED | OPEN-01 and OPEN-15 remain blockers |
| EV-008 | [PR #6](https://github.com/BetrayedByEthanol/Pw_Manager/pull/6) | Canonical v0.4.5 documentation/reconciliation merged into main `d192e6b` | Not evidence of cryptographic or runtime policy implementation |
| EV-009 | [V01-A PR #7](https://github.com/BetrayedByEthanol/Pw_Manager/pull/7); [first CI](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42236810534); [expanded CI](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42237908044) | **Merged PR #7:** expanded run passed 20 root unit, 1 executable integration, 6 native-host unit and 3 native stdio process tests, plus extension syntax/config; merge commit `ae6d387`. | V01-A implementation MERGED; does not establish G0 independent security certification, actual daemon or recovery |

| EV-010 | [Merged V02 PR #8](https://github.com/BetrayedByEthanol/Pw_Manager/pull/8); [final-head focused CI](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42296105084); [final-head product CI](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42296105131) | **Merged candidate** at `84f92be` from head `9264da3`: both final-head workflows passed; four Codex P2 findings resolved (transition validation, aggregate encoding bounds, sidecar collisions, relative vault filenames), with fresh final-head Codex review reporting no major issues. | No independent OPEN-01/15 approval; no real factor unwrapping, ready recovery, reviewed dirfd writer or production runtime |

| EV-011 | [V02-A candidate protocol review](../architecture/v02a-crypto-keyslot-review.md) | Documents current slot-schema gaps, proposed transcripts, Option A/OPEN-02 provisioning, threat matrix and OPEN-01/15 external reviewer exit criteria. **Merged design-review packet in PR #9; not an external cryptography review.** | Not independent cryptographic approval, runtime negative-test evidence, key commitment proof or V02-B implementation |

| EV-012 | [Merged V02-B PR #10](https://github.com/BetrayedByEthanol/Pw_Manager/pull/10); [final V02 CI](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42302525461); [final product CI](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42302525543); [security probes](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42302525447); [candidate transcript](../architecture/v02b-keyslot-candidate.md) | **MERGED candidate** (`0249bb6`) with all three final-head GitHub workflows successful; Codex final-head review at `5265e2e` found no major issues. Previously inspected V02 test run passed 26/26 including 9 candidate tests. | Not OPEN-01/15 independent approval, proven key commitment, real hardware, trusted factor sources, stable wire format, VERIFIED/READY slots or production unlock. |

| EV-013 | [Merged V02-C PR #11](https://github.com/BetrayedByEthanol/Pw_Manager/pull/11); [final V02 CI](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42309791103); [final product CI](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42309791121); [security probes](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42309791147); [conformance packet](../security/V02C-cryptographic-conformance.md) | **Merged synthetic conformance** at `961cde0`: all final-head workflows passed at `40b54ad`; 31 focused Rust tests, six Python/libsodium KATs and libargon2 KAT; one valid Codex P2 inner AEAD check fixed/resolved; final-head Codex reported no major issues. | No OPEN-01/15 independent approval, multi-key commitment proof, FIDO2 evidence, active slot, reviewed wire or release acceptance. |

| EV-014 | [Merged V02-D PR #12](https://github.com/BetrayedByEthanol/Pw_Manager/pull/12); [final V02 CI](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42313851246); [final product CI](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42313851198); [final security probes](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42313851212); [handoff](../security/V02D-independent-review-handoff.md) | **Merged** at `08815be`: all final-head workflows PASS, 35/35 Rust tests, six inventory integrity tests, six libsodium KATs and libargon2 check; both Codex P2 source/lockfile provenance issues resolved; final-head Codex no major issues. Standalone verifier Cargo.lock and committed-Git-blob manifest checks included. | Neither named independent review nor key-commitment proof, real FIDO2 evidence, verified slot or G1/G2/G3 release acceptance. |
| EV-015 | [Merged V02-E PR #13](https://github.com/BetrayedByEthanol/Pw_Manager/pull/13); [final-head V02 CI](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42402234740); [final-head product safety](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42402234821); [final-head security probes](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42402234870); [F-1–F-9 ledger](../security/V02E-review-findings-and-preapproval-hardening.md) | **Merged** at `122479b`, final-head `d32d55c`: all three GitHub workflows PASS; 40/40 Rust tests, six libsodium vectors, libargon2 KAT, six inventory tests and 27-file source verification; final-head Codex no major issues, zero unresolved findings. Shared structural eligibility, partial F-8 zeroizing scratch, F-9 transition guard and vNext-only AAD prototype. | No production KDF default, owner-approved weaker recovery, approved PRF salt/UV, final wire format, independently proven commitment, real hardware or OPEN-01/15 clearance. |
| EV-016 | [Merged V02-F PR #14](https://github.com/BetrayedByEthanol/Pw_Manager/pull/14); [final-head V02 CI](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42406130444); [product safety CI](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42406130545); [security probes](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42406130590); [V02-F policy packet](../security/V02F-recovery-assurance-and-cryptographic-policy.md) | **Merged** at `5b6b554` (head `900acd0d`): 40/40 Rust, six libsodium vectors, libargon2, six inventory and four policy tests, all three GitHub workflows PASS. Initial Codex P1 consent assertion and P2 source-doc workflow trigger fixed/resolved; final-head Codex no major issues. **Policy proposals only**; no crypto code enabled. | No owner-approved weak recovery/KDF/NFC policy, PRF salt/UV, cryptographic commitment or final wire; OPEN-01/15 and G1–G3 remain blocked. |
| EV-017 | [Merged V02-G PR #15](https://github.com/BetrayedByEthanol/Pw_Manager/pull/15); [final V02 CI](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42408365298); [final product CI](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42408365335); [final security probes](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42408365295); [review-only proposal](../architecture/v02g-vnext-cryptographic-protocol-review.md) | **Merged** at `239f80c` (head `10c62b11`): 47/47 Rust tests, six frozen libsodium vectors and libargon2, six manifest and four policy tests, 31-source inventory, all three workflows PASS; final-head Codex no major issues and no unresolved threads. Inactive V3RV strict codec. | No vNext cryptographic AEAD/commitment, registered FIDO2/UV, owner production KDF/password encoding/recovery consent, final format, migration, OPEN-01/15 or G1–G3. |
| EV-018 | [Merged V02-H PR #16](https://github.com/BetrayedByEthanol/Pw_Manager/pull/16); [final-head focused V02 CI](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42410966297); [product safety CI](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42410966231); [security probes](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42410966204); [reviewer packet](../security/V02H-adversarial-conformance-and-review-submission.md) | **Merged** as inactive reviewer evidence at `9d854a6` (head `3f36a442`). 49/49 Rust, five Rust/Python **wire/context-only** vectors, 1,800 Python + 4,096 Rust deterministic mutations, seven Python route/graph/KDF model tests, six **older V02-C** libsodium KATs, libargon2, six inventory/four policy tests and all three final-head GitHub workflows PASS; 36 source paths; Codex no major issues or unresolved threads. | No V3RV authenticated seal/open or security KAT, independently proven multi-key commitment, verified FIDO2, owner-approved recovery/KDF/encoding policy, external OPEN-01/15 verdict, G1–G3 or production credential activation. |
| EV-019 | [V02-H round-two review disposition](../security/V02H-round-two-review-disposition.md) | **Accepted as engineering findings** against merged `9d854a6`: F-1–F-9 and W1/probe observations; **Q1** keeps weaker Standard recovery owner-controlled (`OPEN-REC-CONSENT`), **Q2** explicitly rejects P6/HMAC and V3RV tests as cryptographic approval. No repository fixes or external verdict claimed. | F-1 owner choice, F-2 KDF profile/encoding, F-3/F-4/F-7 hardware provenance/PRF/UV, F-6/F-9 authenticated vNext, F-8 secret-lifetime audit, graph/nonce/rollback invariants, OPEN-01/15 remain open. |

Evidence links are immutable run/PR references where possible. New status claims require their own evidence and must not overwrite an older evidence record's scope.

## 2. V01 acceptance against merged implementation

| Check ID | Acceptance criterion | Code | Evidence | Remaining action / disposition |
| --- | --- | --- | --- | --- |
| A01-01 | Rust root crate, native host compile and tests execute | MERGED | EV-004/005 | **PASS build gate only** |
| A01-02 | Browser extension manifests and JS syntax valid | MERGED | EV-005 | **PASS syntax only**; no browser behavior tests |
| A01-03 | Default executable refuses real vault use | MERGED V01/V01-A | `src/main.rs`; V01-A child-process smoke | First PR #7 CI verifies nonzero exit, no file writes and synthetic secret suppression; acceptance pending merge/review |
| A01-04 | No master-password/PIN fallback to environment | MERGED | `src/cli.rs` secure terminal prompt | **PARTIAL:** scan/negative prompt tests before production |
| A01-05 | No dangerous secret-bearing debug operations in compiled paths | MERGED V01-A | PR #7 removes experimental gocrypt source, disables legacy direct stdout secret reveal and redacts password display | Security review and merged-main verification still pending |
| A01-06 | Fresh outer AEAD nonce per seal and legacy JSON re-encrypt | MERGED | V01 unit tests + EV-005 | **PASS V01 regression**, not multi-key security proof |
| A01-07 | FIDO2 attestation/assertion fail closed | MERGED | `src/fido2.rs` verifies results | **PARTIAL:** negative mocks/UV and mismatch tests missing |
| A01-08 | Strict body counts/truncation; reject unsupported client registry | MERGED | `src/vault/body.rs` regression tests | **PASS body decoder**, not header/payload parser |
| A01-09 | Atomic replacement + previous encrypted version + fsync | MERGED V01/V01-A | Deterministic checkpoints before/after temp/backup/commit sync, symlink rejection and simulated abrupt exit | Limited test-path assurance; V02 still needs fd-based race safety and authenticated ancestry |
| A01-10 | Single writer lock fails closed when lock exists | MERGED | `src/fsutil.rs` basic lock test | **PASS narrow lock test**, crash/stale-lock recovery procedures not certified |
| A01-11 | Native host must not falsely claim credential success by default | MERGED V01-A | Default `RELAY_ERROR/UNAVAILABLE` for all recognized requests; synthetic secret not echoed | Native host is NOT yet an E2E encrypted relay; pending merged CI/security review |
| A01-12 | Native host request/IPC behavioral tests | MERGED V01-A | Six native-host Rust unit tests and three child-process stdio tests passed in expanded PR #7 CI; merged-main evidence pending | Review and merged-main test evidence pending |
| A01-13 | Canonical header/payload parser safely reject malformed input | NOT V01 SCOPE | Legacy header/payload still index unchecked ranges | **V02 P1:** bounded parser/format replacement and fuzz |
| A01-14 | Exact v0.4.5 VMK/VERS/DEK, modes and recovery | NOT V01 SCOPE | No canonical runtime | **V02–V05**, independent reviews |
| A01-15 | Documentation/version/status consistent with merged evidence | MERGED PR #6 / V01-A PR #7 | PR #6, EV-008; V01-A branch adds provisional evidence | Update status after PR #7 merge and verify new CI; no release claim |

**Assessment:** V01 source and CI foundation are merged; do not label V01 security acceptance COMPLETE until V01-A controls and their tests pass. The main binary remains deliberately unusable for real credentials.

## 2a. Canonical v0.4.5 restoration audit — documentation only

The updated PR #6 restores nine binding requirements from the owner-approved v0.4.5 design. A documentation reconciliation is **not** evidence of runtime enforcement or independent cryptographic review.

| Contract | Current canonical location | Required runtime/negative evidence (still outstanding) |
| --- | --- | --- |
| R1 vault-mode recovery | Specification §4; decisions D-07/D-32 | Password-only code reset, two separate hardware admin routes, reject hardware code-only VMK slot; distinguish metadata and DEK recovery |
| R6 bounded write transactions | Specification §2; architecture state machine | Unique ID/base/TTL/cap; no VMK in stage; immutable daemon summary, one authorized fresh-VMK commit; abort stale/expired |
| R5 session lifecycle | Specification §2; architecture state machine | Idle **and** absolute expiry, lock on OS lock/suspend/hibernate; fail closed on monitor loss, wipe VERS/virtual provider |
| S4 authenticated ancestry and conflicts | Specification §5; architecture transaction | Pre-LOADED check of local head **outside vault directory**; refuse divergent write; retain encrypted conflict copy |
| OPEN-02 virtual bootstrap | Specification §4; architecture key graph | Independent seed, pre-load password + authorized recovery slots; recover identical seed after reset |
| Dual assurance views | Specification §3 | VMK/metadata and per-entry DEK weakest complete paths separately; disclose metadata access via hardware-vault admin route |
| Hardware UV invariant | Specification §4; architecture enrollment | Slot/AAD binds credential/RP/salt/UV mode; two stable enrollment derivations; no silent UV downgrade |
| R8 historical backups | Specification §5; architecture history | Durable encrypted pre-operation snapshots, historical-factor inventory, purge-on-rotate, old code-only snapshots after conversion |
| Historical decision traceability | Decision crosswalk D-01…D-32 | Keep D-19/D-20 RESERVED and D-23/D-30 provisional; map new DEC aliases to originals |

**All nine items are text-level contract restorations, not verified new security controls.** The V01-A gaps and OPEN-01/15 independent reviews remain open; do not change release gates merely because this PR is merged.

## 2b. V01-A implementation review checklist — no automatic security acceptance

| ID | V01-A review requirement | Proposed code and tests | Current disposition |
| --- | --- | --- | --- |
| VA-01 | Remove master-key dump/destructive experiment | Delete `src/util/gocrypt.rs`, remove module include | PR #7 MERGED; final runtime verification still required before product use |
| VA-02 | No false native-host success | Valid requests always `RELAY_ERROR/UNAVAILABLE` | Initial CI PASS; merge/review pending |
| VA-03 | Native-host framing and origin negative tests | Unit tests plus child-process stdio integration | Unit and process CI PASS on PR #7; merge/review pending |
| VA-04 | Default executable inert | Synthetic env-secret and sentinel-vault child-process smoke | Initial CI PASS; merge/review pending |
| VA-05 | Interruption safety checks | Deterministic fault stages, symlinks, simulated abrupt exit and stale lock | Initial CI PASS; not proof of power-loss durability |
| VA-06 | Legacy malformed header/payload rejection | Header length/record preflight, strict password payload decode, truncation tests | Initial CI PASS; V02 full format still required |
| VA-07 | FIDO2 fail-closed negative boundary | Unit tests for rejected verifier results; hardware UV/RP fixtures remain future | Synthetic CI PASS, **real hardware/OPEN-15 NOT VERIFIED** |
| VA-08 | Recovery/runbook and release boundaries | Document manual stale lock and ambiguous post-rename commit; keep G0 partial | PR #7 MERGED; security release gate remains partial; no production authorization |

This branch removes mock success; it **does not** implement native daemon authentication, canonical VMK/DEK, R1 recovery, S1/S2 route enforcement, secure provenance of a browser origin, or race-free dirfd/openat. G0 remains PARTIAL until source merge, reproducible tests, and accepted review receipts.

## 2c. V02 candidate codec v0 — acceptance matrix (PR #8 merged, candidate only)

| ID | Required property | Candidate evidence | Not yet verified |
| --- | --- | --- | --- |
| A02-01 | Public header bounded/versioned; outer metadata AEAD with complete header AAD | `src/v02/codec.rs`, `open_file`, tamper and malformed input tests | Independent byte-format freeze, parser fuzz signoff, public leakage budget |
| A02-02 | VMK, VERS, per-entry DEKs independently random; no VMK-derived entry encryption | Separate zeroizing key types and inner/outer AEAD negative tests | OPEN-01 approved transcript, real factor wrapping and key commitment |
| A02-03 | Four entry normal modes, Standard/Isolated and all recovery policy enum encodings | Typed slot/policy schema; reject hardware code-only VMK and software-only Isolated DEK descriptors | V04 route-graph integration and S1/S2 real hardware operation enforcement |
| A02-04 | Authenticated encrypted ancestry, revisions and tombstones | Commit/generation/predecessor hash; duplicate, revision and tombstone tests | Last-seen-head outside vault dir, full S4 conflict/restore review |
| A02-05 | Atomic candidate writer rejects stale base, preserves encrypted conflict copy | `src/v02/storage.rs` and deterministic pre/post-rename tests | Race-free descriptor-relative I/O, malicious same-user filesystem threat, full power-loss drill |
| A02-06 | Legacy VLT1/JSON never implicitly treated as v2 | Version discrimination and corrupt/truncated-format tests | V04M-1 authorized, read-only legacy import + verified backup |
| A02-07 | Root, native host and candidate codec tests in CI | Final-head V02 focused workflow `42296105084` **PASS**; full V01 product safety workflow `42296105131` **PASS** on `9264da3`. | OPEN-01/15 independent security and Forgejo runner evidence still outstanding |
| A02-09 | Cross-generation revision policy and bounded encoding | Shared prepare/commit transition validator; checked aggregate 16 MiB encoding preflight. Two P2 review threads resolved with negative tests. | No runtime slot authentication or production memory/commit certification |
| A02-10 | Complete-basename sidecar safety | Unique immutable encrypted `.previous-<uuid>` backups, separate `.lock`/`.tmp-<uuid>`/`.conflict-<uuid>` per active name; reject active sidecar aliases; fail-open-file never deletes preexisting file. Final-head V02 workflow PASS. | Descriptor-relative race-free storage and power-loss proof remain future G1 gates |
| A02-08 | Main executable and native host remain fail-closed | No changes to existing runtime entry points | No production unlock, key factor route, recovery, R5/R6 or trusted daemon implementation |

**V02 v0 is a merged experimental library only.** Do not mark A02 complete, OPEN-01/15 approved, G1 passed or any FR implementation DONE merely because it compiles or passes synthetic vectors. [Candidate format and limitations](../architecture/v02-format-candidate.md).

## 2d. V02-A protocol/key-slot design review — proposed evidence only

| ID | Review package acceptance | Recorded evidence | Still blocked |
| --- | --- | --- | --- |
| A02A-01 | Map merged V02 slot schema to missing algorithm/KDF/PRF/commitment parameters | [V02-A review §1–3](../architecture/v02a-crypto-keyslot-review.md) | Versioned production wire schema and independent OPEN-01 approval |
| A02A-02 | Distinguish VMK metadata, VERS, provider seed and DEK normal/recovery routes | [V02-A review §2–4](../architecture/v02a-crypto-keyslot-review.md) | Runtime ancestry-aware route enforcement and actual provisioning |
| A02A-03 | Define Option A and OPEN-02 bootstrap dependency/slot activation failure cases | [V02-A review §4](../architecture/v02a-crypto-keyslot-review.md) | Verified password-reset, token-loss and code-dependent rewrap tests |
| A02A-04 | Document FIDO2 PRF scope, fresh ceremony and blast-radius trade-off | [V02-A review §5](../architecture/v02a-crypto-keyslot-review.md) | Hardware capability results and independent OPEN-15 approval |
| A02A-05 | Record attack scenarios and independent reviewer deliverables | [V02-A review §6–7](../architecture/v02a-crypto-keyslot-review.md) | Formal/informal expert assessment, key-substitution vectors and reviewed implementation |

No A02A row certifies a security property. Code, test and runtime status are unchanged by this documentation PR; G1/G2/G3 stay **BLOCKED**.

## 2e. V02-B candidate — merged internal code, no runtime activation

| ID | Targeted property | Candidate evidence | Unmet gate |
| --- | --- | --- | --- |
| A02B-01 | Derive scoped KEKs and distinct commitment keys from candidate single/two-factor inputs | `src/v02/v02b.rs` code and synthetic unit round trips | Independent OPEN-01 analysis and multi-key/third-party KATs |
| A02B-02 | Reject target, slot, provider, KDF, factor, ciphertext or tag substitution | Validated descriptor, bound transcript and negative mutation tests | Exact canonical serializer/decoder, security-timing review and proven commitment |
| A02B-03 | Preserve R1/S2, Option A and pre-load virtual seed semantics | Structurally reject code-only hardware VMK, Isolated software routes and STRICT_NONE recovery; separate seed single-password vs code-only routes | Real hardware proof, recovery-code prompts, dependent-slot coverage and trusted activation |
| A02B-04 | Bounded Argon2id test parameters and zeroizing keys | Internal candidate password pre-KDF + Zeroizing keys | Production KDF calibration, offline guess security analysis and complete secret-lifetime testing |
| A02B-05 | Preserve VLY2 compatibility gate | V02-B prototype not linked to existing `Slot` codec or external API | Post-review versioned wire format and explicit authorized migration |

**All A02B rows are implementation candidates and review targets, NOT proof of secure protocol finalization. G1/G2/G3 remain BLOCKED.**

## 2f. V02-C conformance and adversarial verification (review candidate)

| ID | Acceptance test | Source/evidence | Still required |
| --- | --- | --- | --- |
| A02C-01 | Six route-specific deterministic descriptor/HKDF/AEAD/HMAC interoperability KATs | `src/v02/v02c_tests.rs`, frozen fixture and Python/libsodium reference | Independent **external** vector authorship/review; final protocol version |
| A02C-02 | Argon2id KAT and hostile KDF limits | system `libargon2` reference component, Rust test of parameter rejection | Production KDF calibration/DoS tests |
| A02C-03 | Bytewise ciphertext/nonce/tag tampering and descriptor/provider/KDF/policy substitution | Rust negative suite: original outer HMAC rejection **plus** recomputed synthetic HMAC to force inner Poly1305 failure; [V02-C matrix](../security/V02C-cryptographic-conformance.md) | Formal multi-key/key-substitution and timing/error-oracle review |
| A02C-04 | Hardware PRF enrollment, UV/UP, RP binding, freshness, batches and shared-root fanout | **Only an unexecuted test plan** in [V02-C packet](../security/V02C-cryptographic-conformance.md) | Independent OPEN-15 real-device trials + verdict |
| A02C-05 | Stay inactive and avoid silent wire migration | V02-B private module; no active VLY2 writer changes, existing CI fail-closed check | Real V03/V04/V06 authorization, canonical wire migration and full release gates |

**No A02C test alone can mark OPEN-01, OPEN-15, G1 or G2 complete.**

## 2g. V02-D reviewer readiness (NOT independent approval)

| ID | Review-preparation acceptance | Evidence to verify | Still blocked |
| --- | --- | --- | --- |
| A02D-01 | Exact reviewed source, fixture and dependency bytes identifiable | Deterministic Git-commit and SHA-256 inventory with explicit 24-file allowlist, committed-blob match, root **and standalone verifier** Cargo.locks; recheck rejects staged/unstaged/untracked file/commit drift and altered gate statuses; `--locked` in both workflows | Third-party authenticated signature/verdict and supply-chain assurance |
| A02D-02 | All sample factor/slot/route boundaries are executable as negative tests | Rust `v02d_tests.rs` checks valid/invalid route table, single/two-factor mismatch, forbidden Isolated/STRICT_NONE software or code routes | Full effective runtime graph, real device proof and actual code-dependent provisioning |
| A02D-03 | Key schedule cannot accidentally collapse tested vault/slot/target/purpose domains | Rust domain/KEK-versus-MAC separation regression | Expert multi-key/key-commitment attack analysis, not proven by finite tests |
| A02D-04 | Hardware trust gap is explicitly demonstrated | Synthetic caller-provided PRF bytes can unwrap candidate with no real assertion; recorded as **unresolved** OPEN-15 | Real credential/RP/UP/UV binding, freshness, device negative evidence and independent reviewer verdict |
| A02D-05 | Reviewer-ready questions and acceptance receipts | [V02-D handoff](../security/V02D-independent-review-handoff.md) with 12-gap ownership and blank OPEN-01/15 verdict/evidence templates | Named qualified reviewers and signed/recorded actual results |

V02-D **merged as review-preparation only**, leaving G1/G2/G3 **BLOCKED**.

## 2h. V02-E review response and hardening (candidate; no cryptographic approval)

| ID | Acceptance criterion | Current implementation evidence | Still required |
| --- | --- | --- | --- |
| A02E-01 | Model and descriptor agree on normal and recovery route eligibility | `model::route_is_allowed` shared by VLY2 and V02-B; exhaustive vault/target/route/entry/tier/recovery permutation test, including Isolated and STRICT_NONE | Actual factor provenance, owner-approved per-entry recovery consent and full ancestor graph |
| A02E-02 | Review-only combiner avoids heap scratch IKM | `Zeroizing<[u8;128]>` fixed combiner input; frozen V02-C vectors unchanged | HKDF/HMAC/Argon2 internal scratch and OS-lifetime audit; OPEN-01 |
| A02E-03 | VMK-only metadata edit cannot silently redirect via normal revisioned successor/commit | Reject origin/user/title change without new nonce and ciphertext; test legitimate DEK re-encryption and direct sealed bypass rejection at disk commit | DEK-authenticated metadata under **new wire version**, secure browser origin/frame authorization, malicious raw VMK writer threat |
| A02E-04 | Proposed entry-metadata binding isolated from VLY2 | `entry_binding_candidate` built `#[cfg(test)]`, vNext domain length-frames origin/user/title and tests tampering | Independent protocol review and explicit versioned re-encrypt migration |
| A02E-05 | Review findings do not rewrite approved security policy | [F-1–F-9 disposition](../security/V02E-review-findings-and-preapproval-hardening.md), Standard code-only DEK still structurally representable; no implicit recovery slots | Owner opt-in decision, KDF calibration, real hardware UV/salt, final format and external verdict |

**V02-E tests are synthetic security regression evidence, not OPEN-01/15 or G1–G3 sign-off.**

## 2i. V02-F recovery assurance and policy packet (PROPOSAL, not new owner approval)

| ID | Policy/design acceptance | Evidence / review criterion | Still blocked |
| --- | --- | --- | --- |
| A02F-01 | Never conflate VMK metadata unlock with VERS/seed/DEK authorization | [Root-separated complete route/report matrix](../security/V02F-recovery-assurance-and-cryptographic-policy.md#2-normal-access-vs-recovery-an-assurance-report-contract), normal/recovery, configured/usable and missing/cancelled factor states | V04/V06 actual verified factor graph and registered owner binding |
| A02F-02 | Standard weaker recovery explicitly distinguished from S2 Isolated | Weaker code-only entry route requires **proposed** informed opt-in, no automatic weak or STRICT_NONE default; Isolated every DEK route physical regardless of STRICT_NONE | Explicit F-1 owner approval and trusted V04 implementation |
| A02F-03 | Production Argon2id not inferred from low-cost synthetic fixtures | Benchmark profiles and resource-abuse cases; measured aggregate pre-auth bounds and per-ceremony work budget required | Platform measurements, owner cost target and OPEN-01 approval |
| A02F-04 | Password byte representation and migration questions captured | Versioned NFC→UTF-8 **proposal**, Unicode/space/NUL/length negative matrix, no silent change to frozen V02-B/C or old files | Explicit owner/OPEN-01 encoding decision and vNext test vectors |
| A02F-05 | Code scope/PRF-salt, final wire and OPEN-01/15 authority kept distinct | Proposed vault/group/entry code ownership, PRF salt review under OPEN-15, strict new version/DEK origin bind/authorized migration list for V02-G/H | Real FIDO2 trials, independent combiner/commitment and final cryptographic wire |
| A02F-06 | CI/document evidence cannot claim authorization or runtime readiness | All OPEN-01/15 and G1–G3 statuses remain blocked, no new approved decision or production code changed; V02-F contract included in commit-pinned review inventory | External approvals and future implementation-specific gates |

No A02F criterion is production cryptographic approval; V02-F can merge as a **review policy and design packet only**.

## 2j. V02-G strict vNext review-only format (candidate, not production)

| ID | Acceptance requirement | Evidence | Still blocked |
| --- | --- | --- | --- |
| A02G-01 | New magic and version never reinterpret existing VLY2 | `V3RV` test-only frame, strict big-endian version/suite and candidate `classify_file` rejection; frozen V02-C vectors unchanged | Final approved format and explicit V04M migrations |
| A02G-02 | Opaque untrusted descriptor and frame are unambiguous and bounded | `#[cfg(test)]` codec; strict optional flags, target/provider/scope/route enums, length checks, canonical re-encode and trailing-byte rejection; malformed and truncation matrix | Actual independently assessed cryptographic authentication and fuzz/interoperability V02-H |
| A02G-03 | S2/R1/Option A / weaker Standard recovery distinctions preserved | Shared `route_is_allowed` structural policy, Isolated physical-only recovery and `STRICT_NONE`, scoped owner record and test; no actual factor verification/owner consent | V04 effective graph, OPEN-REC-CONSENT and OPEN-15 device approval |
| A02G-04 | Context/commitment bytes and DEK metadata binding are reviewable but unapproved | Canonical review-only slot context and commitment-context bytes, vNext test-only origin/user/title AAD mutation tests | Independent OPEN-01 multi-key commitment verdict and trusted origin normalization |
| A02G-05 | KDF/password encoding/UV remain explicitly provisional | Test-only parse guards, proposed encoding ID, physical UV flag, no KDF-derived keys or active slot | Owner OPEN-KDF-PROFILE/OPEN-PASSWORD-ENC, OPEN-01 and OPEN-15 approval |
| A02G-06 | Reviewer evidence and release gates remain honest | Pinned source inventory, full candidate/product/security CI; `OPEN-01`/`OPEN-15`/G1–G3 BLOCKED | Independent security receipt, runtime integration and V02-H external vectors |

**No V02-G test alone proves key commitment or authenticates a real device.**

## 2k. V02-H adversarial cross-implementation conformance (candidate only)

| ID | Acceptance criterion | Source/test evidence | Not established |
| --- | --- | --- | --- |
| A02H-01 | Independent *implementation* wire bytes, not independent *expert* cryptography | Rust vs Python five frozen V3RV frame hex + SHA256 slot/commitment input; no fixture regeneration during CI | No vNext AEAD/MAC/KEK interoperability, external OPEN-01 or authenticated ciphertext |
| A02H-02 | Hostile bytes cannot bypass strict canonical V3RV decoding | All vector truncations, oversized/trailing/version-tag/selector negatives, 1,800 seeded Python and 4,096 deterministic Rust mutation attempts; any accepted bytes round-trip canonically | Crypto authenticity of accepted mutations; coverage-guided fuzz and formal parser proof |
| A02H-03 | Reviewer-only S2/R1 recovery scope and declared ancestry threat checks | Independently coded scope/route model; duplicates, cycles, dangling/cross-vault ancestry, Isolated code-only/STRICT_NONE and code-only VMK-versus-DEK contrast | Authenticated real owner registry, complete multi-route graph, hardware possession or READY state |
| A02H-04 | Demonstrate hostile KDF multi-slot cost amplification without executing it | Synthetic 256-slot workload and selected-route-count, memory, aggregate memory-pass budget model; reject before KDF in model | Production Argon2 cost, actual latency/OOM test or daemon-enforced aggregate work bounds |
| A02H-05 | Source-pinned reviewer handoff and separation of external approval | Frozen vector files, full Git-blob SHA256 inventory, reviewer H-T01–H-T09 threat register and blank scoped verdict; OPEN-01/15/G1–G3 remain BLOCKED | Signed independent verdict, approved committing primitive or hardware real-device tests |

V02-H can be merged as **internal review preparation only**, never as proof of vNext cryptographic security. The [review packet](../security/V02H-adversarial-conformance-and-review-submission.md) names the missing crypto cases explicitly.

| EV-020 | [Merged V02-I PR #18](https://github.com/BetrayedByEthanol/Pw_Manager/pull/18); [final-head V02 CI](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42495002180); [final-head product safety](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42495002213); [security probes](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42495002195); [proposed hardware policy](../security/V02I-fido2-prf-isolation-and-hardware-assurance.md) | **Merged** at `54a20268` (head `0e3db649`): 57 Rust tests, six frozen Python/Rust public-input/CTAP salt vectors, five Python PRF tests, five policy checks, 44-file source inventory, all three final-head GitHub workflows PASS and Codex no major issues. **No actual hardware or approved policy.** | Owner OPEN-HW-ASSURANCE/OPEN-PRF-SALT and independent OPEN-01/15, authenticated vNext, verified device and G1–G3 remain **BLOCKED**. |
| EV-021 | [Merged V02-J PR #19](https://github.com/BetrayedByEthanol/Pw_Manager/pull/19); [final-head V02 CI](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42498499507); [product safety CI](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42498499465); [security probes](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42498499457); [runbook](../security/V02J-isolated-fido2-hardware-verification.md) | **Merged** `9e7edb83` (head `44f916a1`): 57 Rust tests, 20 offline mock harness/policy tests, 48-file source inventory, all 3 final-head GitHub workflows PASS; Codex final review no major issues, four initial P2 threads resolved. **No actual hardware was exercised**. | I-P01–I-P09 physical device execution, external OPEN-15 approval, browser parity, trusted Vaulty enrollment/READY, OPEN-01 and G1–G3 remain **BLOCKED**. |
| EV-022 | [Merged V02-K PR #20](https://github.com/BetrayedByEthanol/Pw_Manager/pull/20); [Rust operator binary](../../tools/v02_verifier/src/bin/vaulty_v02k.rs); [regressions](../../tools/v02_verifier/src/bin/vaulty_v02k/tests.rs); [operator instructions](../security/V02K-physical-fido2-verification-and-evidence.md) | **Merged** at `f65615e8` (head `935ee1b0`): standalone Rust redacted receipt orchestrator and 11 offline regression tests, existing V02-J lab functions unchanged; no real keys operated in CI. | Independent OPEN-15 hardware proof, complete I-P matrix, OPEN-01 and owner security policies remain blocked. |
| EV-023 | [Operator-submitted redacted V02-K evidence](../security/V02K-local-hardware-evidence-received-2026-11-08.md); [verbatim JSON](../security/evidence/v02k-local-native-ctap-2026-11-08.json) | **RECEIVED 2026-11-08 (local self-report):** source commit `f65615e8` matches merged `main`; primary and backup reported as separate **YubiKey 5 NFC USB-A, firmware 5.7.4**; `LOCAL_OBSERVATIONS_CAPTURED` with both `OBSERVED`; I-P01/02/03/04/06 `PARTIAL`, I-P05/07/08/09 `NOT_EXECUTED`. Native signed-assertion and PRF stability/isolation observations are tool-generated claims, not independently reproduced; device identities/firmware unverified. | **OPEN-15 BLOCKED:** no externally verified attestation/signed-negative evidence or browser parity; no trusted Vaulty READY, OPEN-01 and G1–G3 blocked. |

| EV-024 | [Merged V02-L-A/B PR #22](https://github.com/BetrayedByEthanol/Pw_Manager/pull/22); [merged V02-L diagnostics and PRF context follow-up #23](https://github.com/BetrayedByEthanol/Pw_Manager/pull/23); [runbook](../security/V02L-native-fido2-negative-and-failure-verification.md); [lab code](../../tools/hardware/fido2_v02l.py) | **SOURCE MERGED**, including libfido2 CBOR framing correction, no-secret error reporting, full offline native PRF context checks, and negative verifier/failure harness. Local operator execution is recorded **separately** in EV-025. | No production vault route or device manufacturer attestation; independent OPEN-15/01, V03/V06 runtime; G1–G3 BLOCKED. |
| EV-025 | [V02-L redacted operator evidence intake](../security/V02L-local-hardware-negative-evidence-received-2026-11-09.md); [primary](../security/evidence/v02l-primary-verifier-local-2026-11-09.json); [backup](../security/evidence/v02l-backup-verifier-local-2026-11-09.json); [wrong-device](../security/evidence/v02l-wrong-device-local-2026-11-09.json) | **RECEIVED 2026-11-09 (local self-report):** three receipts source-pinned to merged `edd3256a`. Each physical-role verifier reports `positive_signed_up_uv=OBSERVED` and five corrupted-input negatives `LOCAL_VERIFIER_REJECTED`. Wrong-device reports `control_before=OBSERVED`, target credential `LOCAL_DEVICE_REJECTION_UNCLASSIFIED`, `control_after=OBSERVED`. Earlier invalid-credential/INCOMPLETE attempts are not counted as accepted negatives. | Not independent token/firmware/device-uniqueness proof, not a classified cause of cross-device rejection, not a signed-UV-absent test, not daemon replay/revocation/fallback, not browser parity or production key slot; I-P03/04/06 **PARTIAL**, OPEN-15/01 and G1–G3 BLOCKED. |

## 2q. V03 session state and authenticator adapter foundation (merged PR #25; limited acceptance)

**Source stage only — not a release gate or provider implementation.** The code
in [V03 foundation](../architecture/V03-session-and-authenticator-foundation.md)
can inspect bounded unauthenticated V02 headers and reports `authenticated=false`.
A real `LOADED` transition does not exist outside synthetic unit tests; the
default executable is unchanged and still refuses vault use. No operation
can return an entry secret, a verified hardware proof or an approved write.

| ID | Foundation acceptance | Candidate evidence | Still blocked |
| --- | --- | --- | --- |
| A03-01 | CLOSED/OPEN/LOADED/LOCKED transitions refuse untrusted loads | V02 public-header inspection in normal builds; synthetic authenticated open/LOADED in test-only code; close/lock drop owned metadata/secret shares | Real VMK/bootstrap authorization, trusted head/rollback reconciliation; OPEN-01/15 |
| A03-02 | VERS masked in LOADED; no VMK/DEK/PRF retained | Two Zeroizing XOR shares, fresh CSPRNG remask before each transient reconstruction (including panic), test-only Zeroizing virtual seed; no persisted key | No full-process-memory guarantee; OS mlock/core dump, transient crypto and real factor boundaries still need review |
| A03-03 | S1/S2 physical-vs-virtual routing and per-read freshness | Four normal entry modes + ISOLATED normal physical requirement; read intents have new random IDs, `authorized=false`; virtual adapter never claimed second factor; all completions refuse | Trusted FIDO2/authenticator adapters, fresh signature/PRF proof, entry DEK unwrap, recovery/ancestor paths and no fallback runtime |
| A03-04 | R5 idle/absolute expiry and fail-close on OS events/listener failure | Independent monotonic checks, explicit lock on suspend/hibernate/screen-lock/disconnect, no resume auto-unlock; simulated listener exists **only in tests** | Real Linux/Windows event subscriptions, independent timer, fail-safe listener lifecycle and OS memory policy |
| A03-05 | R6 bounded write plan cannot retain VMK or commit | Random transaction ID, base vault/commit/generation, 1–300 s TTL and 1–64 cap; no stage/approve/commit APIs | Trusted owner summary/digest and fresh VMK at commit, authenticated conflict checks, atomic writer |
| A03-06 | CI, evidence and releases remain bounded | Root and isolated-verifier compilation, synthetic Rust tests, source inventory including new files, no new runtime unlock | Qualified OPEN-01/15 reviews; G1–G3 BLOCKED, no READY route |

**Never interpret V03's local READ intent or test-only LOADED as a verified
authenticator, authorized credential release or runtime production availability.**
EV-023/EV-025 remain operator local self-reports, not approvals.

## 2r. V03-A trusted lifecycle / authenticator boundary (merged PR #26; negative evidence only)

Source: [V03-A boundary design](../architecture/V03A-trusted-lifecycle-and-authenticator-boundary.md),
`src/v03a.rs` and `src/v03a_tests.rs`. **No system-bus integration, production
LOADED path, trusted factor verification, new recovery slots or real hardware
operations.** Lifecycle and provider tests are synthetic, while G1–G3,
OPEN-01 and OPEN-15 remain blocked.

| ID | Review-gated acceptance | Expected source/tests | Remaining / no approval |
| --- | --- | --- | --- |
| A03A-01 | Lifecycle monitor starts unavailable and cannot be marked healthy by public library callers | Health watchdog 1–60 seconds; simulated verified source/heartbeat only `#[cfg(test)]`; stale or disconnected source locks and cancels pending operations | Real D-Bus signal authentication, local session/seat matching, initial lock state, independent liveness timer, OS integration proof |
| A03A-02 | Conservative Linux logind event handling | Session lock, sleep true/false, shutdown, unexpected unlock, subscription loss and malformed event all lock/clear; wake cannot resurrect loaded state | Linux logind subscription and trusted sender binding, delay inhibitor, Windows equivalents |
| A03A-03 | Entry read-intent policy cannot be silently substituted | Pending operation binds ID, entry, default-vs-custom first factor, physical-vs-virtual provider and tier; forged/stale/replayed requests rejected | Trusted daemon and per-entry factor authorizations / actual DEK unwrap |
| A03A-04 | No software substitute for physical or ISOLATED access | Sealed virtual/physical adapter types; physical→virtual and reverse substitution denied; virtual never called a second factor | Registered FIDO2 key, RP/UV/UP/salt proof on each read, V06 revocation registry, OPEN-15 |
| A03A-05 | Physical unavailable/suspended/revoked/active *synthetic* states cannot grant unlock | Test-only registry state and no external Active registration path; every attempt returns denial and cancels matched pending intent | Real authenticator integration and a trusted registry/owner consent |
| A03A-06 | CI and source evidence do not activate credentials | Root + isolated verifier compile/test, pinned V03-A sources, main executable remains fail closed | OPEN-01/15 and G1–G3 blocked, no independent validation |

**Do not classify a typed `LogindSafetyEvent` as an authenticated system-bus
message or a `ProviderAdapter` as a verified authenticator.** Production
activation is a separately reviewed later milestone.

## 2s. V03-B Linux logind observer and watchdog (PR candidate, not runtime security)

[Read-only Linux observer implementation/review limitations](../architecture/V03B-linux-logind-watchdog.md)
and `tools/lifecycle/v03b_logind.py` are separate from the Rust
authorization daemon. They can contact the actual system bus only during
explicit operator invocation, but their stdout, process exit status or
`OBSERVED_ONLY` report **never authorize V03 Session or a factor**. CI
uses a fully fake bus and does not exercise the physical desktop.

| ID | V03-B acceptance candidate | Tests/evidence | Still blocked |
| --- | --- | --- | --- |
| A03B-01 | Match actual logind service and local session, not guessed bus names/paths | Direct `dbus-next` system bus, `GetNameOwner`, `GetSessionByPID`, bound sender/path, startup subscriptions before snapshot; offline mocks | Real machine observation/confirmed systemd/logind behavior; no trusted in-process Rust session integration |
| A03B-02 | No secret activity before trusted session state | Fail if `LockedHint`, `Active`, `CanLock`, desktop session kind, UID, `PreparingForSleep` or `PreparingForShutdown` invalid; observe-only no authorization output | Desktop lock semantics vary; OS session/compositor pairing and true trusted client gate |
| A03B-03 | Lost or malformed OS signals fail closed | Owner restart/change, session removal, lock/unlock, property changes, malformed D-Bus, overflow, query failures and disconnect tests | Live D-Bus failure-injection, signal coverage and delay inhibitor |
| A03B-04 | Independent watchdog detects suspend gaps | Periodic owner/session/property refresh, bounded D-Bus query timeouts and `CLOCK_BOOTTIME` gap rejection; synthetic regressions | In-process Rust watchdog/lifecycle registration, OS suspend-before-secret-wipe confirmation |
| A03B-05 | No READY/cryptographic escalation | Optional dependency isolated from product, no VMK/DEK API, default executable inert, source-inventory and CI fixture checks | OPEN-01, OPEN-15, G1–G3 and trusted physical provider still blocked |

**No A03B criterion is production-verified by CI.** Completion of the
read-only transport milestone is not permission to wire browser, native host
or plaintext credential operations to an untrusted event-output channel.
An independently reviewed in-process daemon listener or authenticated
transport, initial-state TOCTOU defense and actual local failure testing
must precede production LOADED state.

## 2t. V03-C Rust in-process lifecycle lock / logind driver (merged PR #28; non-production)

[Implementation and review boundary](../architecture/V03C-trusted-rust-lifecycle-lock-enforcement.md):
a Rust `SessionSupervisor` owns V03 Session and handles terminal lifecycle
events synchronously. An opt-in, separate Rust `zbus` runner exercises this
controller in the same process with a **CLOSED** session, not the trusted
production daemon. The observer neither enables LOADED nor authenticates
VMK, DEK, PRF, owner consent or clients. No production gate is cleared.

| ID | Candidate verification | Evidence | Remaining requirement |
| --- | --- | --- | --- |
| A03C-01 | Rust-controlled lock/cancel on security events | Test-only synthetic LOADED fixture; terminal event matrix including lock, unlock, sleep, shutdown, bus loss, owner change, stale watchdog | Production loaded-session wiring and independent review |
| A03C-02 | No monitor-positive shortcut to secret authorization | SessionSupervisor owns Session, no mutable getter, snapshot remains diagnostic; normal Rust has no LOADED constructor | Actual trusted daemon authorization; G2 blocked |
| A03C-03 | Direct Rust logind D-Bus observation | Optional zbus manager/session signals, unique owner and PID-bound session; Ubuntu-compatible required `LockedHint` plus other supported, typed properties, no required `CanLock`; new local-session negative tests | Harden startup subscription race, real desktop lock/source provenance tests and watcher integration |
| A03C-04 | Failure propagation and suspend gap | Event loop checks independent 5 s watchdog every 100 ms while D-Bus owner/session/snapshot probe runs in separate, whole-probe 4 s timeout task; priority terminal-signal consumption and late-success rejection; offline hung-probe/lock-preemption/suspend-gap regressions | Pre-suspend wipe assurance/delay inhibitor, actual OS exercise and independent reviewer signoff |
| A03C-05 | No release/gate escalation | Separate review-only Cargo manifest, CI synthetic tests, inert default binary | OPEN-01/15, G1–G3, audited dependencies and production security review |

**Codex round one: both P2s accepted and corrected in PR #28.**
See [V03-C P2 findings and negative-test disposition](../security/V03C-codex-round-one-review-disposition-2026-11-09.md).
CI-successful code is **not** a live desktop test; the supported
`LockedHint` is not an independently authenticated compositor lock. A
bounded off-thread health probe now leaves the same-process Rust watchdog
and terminal event processing responsive even while logind is slow.

**Known blocker:** Subscribing to the specific Session after GetSessionByPID
can miss a transient Lock+Unlock during startup; the later unlocked snapshot
might be insufficient. Acquire the exact Session signal stream without that
gap or implement a stronger initial-state trust sequence before real loading.
Similarly, no delay inhibitor exists and the read-only Rust runner cannot
guarantee secret wipe before suspend. These are not minor release caveats.

## 2u. V03-D early Linux lifecycle subscription, delay inhibitor and operator verification (PR #29 candidate)

[Source design, operator-only evidence and limits](../architecture/V03D-linux-lifecycle-hardening-and-evidence.md).
**Source verification is not physical/desktop verification.** The Rust runner
owns only a non-unlockable V03 Session in normal builds. Release G1–G3,
OPEN-01 and OPEN-15 remain BLOCKED.

| ID | Review candidate / acceptance | Implementation and CI evidence | Remaining / no release inference |
| --- | --- | --- | --- |
| A03D-01 | No startup window between PID lookup and Lock/Unlock signal subscription | `zbus::MessageStream::for_match_rule` for all Session and PropertiesChanged path-namespace messages installed **before** GetSessionByPID, buffered startup signal rejection, mock rule regression | Local rapid lock/unlock, compositor fidelity and independent source review; not a privileged LOADED gate |
| A03D-02 | Delay inhibitor owned until after sensitive state lock | Fail-closed `Manager.Inhibit("sleep:shutdown", ..., "delay")`, FD bound to Rust SessionSupervisor via RAII; synchronous terminal lock precedes FD release, including scope exit; **P1 correction:** common startup/runtime classifier ignores only authenticated `DelayInhibited` bookkeeping; security-related/mixed/malformed manager properties remain terminal; synthetic D-Bus signal tests | Live baseline/inhibitor and pre-suspend handling still unverified; systemd max delay, forced suspend and crash-time cleanup uncontrolled |
| A03D-03 | No auth or restoration on resume/failure | V03-C watchdog remains independent, all normal-built sessions CLOSED, irreversible termination; no new ability to set loaded session | Actual daemon wiring, secure session event subscriptions and process memory policy |
| A03D-04 | Redacted operator evidence and readiness | `v03d_capture.py` compiles locked Rust runner, requires TEST and Git-clean source; waits for exact flushed Rust `OBSERVER_READY` after subscriptions/inhibitor/snapshot before action prompt; missing/early/invalid readiness always INCOMPLETE; private 0600 no-overwrite receipt; synthetic delayed-readiness/startup-failure/hung-child tests | Real local baseline/lock/sleep/disconnect receipts must be supplied by operator; no CLI output, D-Bus traces or private session data in PR |
| A03D-05 | Gate labels not escalated | Source inventory, GitHub/Forgejo Rust/receipt tests, no live CI suspend | OPEN-01/15 and G1–G3 blocked; no independent physical evidence |

**Codex P1 accepted and corrected in source**: see
[V03-D manager/inhibitor property notification disposition](../security/V03D-codex-manager-property-inhibitor-p1-2026-11-09.md).
No physical evidence or independent G2 approval follows from synthetic tests.

**Codex P2 review of operator timing accepted and source-corrected:** see
[V03-D observer readiness handshake disposition](../security/V03D-codex-readiness-handshake-p2-2026-11-09.md).
Only the Rust runner, after full startup validation, can emit the
diagnostic OBSERVER_READY line. The capture tool waits for it before
asking the operator to lock/suspend; no local physical evidence is
asserted by synthetic tests.

**No EV-026 physical receipt exists until an actual operator runs the
local desktop procedure and submits only redacted output.** Successful
source CI must not be recorded as a real logind lock/suspend verification.
The V03-B legacy Python observer was already made Ubuntu-compatible by
the V03-C P2 correction, but it does not control Vaulty's Rust session.

## 2l. Round-two findings acceptance, scoped to source review only

[**Full F-1–F-9 and W1 disposition**](../security/V02H-round-two-review-disposition.md) is part of the security findings register. It records **ACCEPTED FOR FOLLOW-UP**, not a cryptographic, device or owner decision. **Q1:** weaker Standard-entry recovery is structurally permitted but requires a separate explicit owner decision/consent; code-only VMK recovery alone does not unlock all entries, and ISOLATED remains hardware-mandatory. **Q2:** neither V02-B HMAC/P6 nor V3RV frozen wire/context vectors prove multi-key commitment, partitioning-oracle security or authenticated vNext operations. OPEN-01/15 and G1–G3 remain **BLOCKED**.

| Finding / related security ID | Accepted status | Required owner, implementation or review gate |
| --- | --- | --- |
| F-1 / SEC-14 | **OPEN — OWNER POLICY CHOICE** | `OPEN-REC-CONSENT`; trusted per-entry weaker-route opt-in and effective normal/recovery graph; no silent downgrade or forced `STRICT_NONE` |
| F-2 / SEC-15 | **OPEN — IMPLEMENTATION/OWNER/OPEN-01** | Benchmarked production Argon2, pinned work budget/concurrency, password encoding; Python work-budget model is not runtime enforcement |
| F-3 / SEC-06 | **OPEN — OPEN-15 + IMPLEMENTATION** | Per-entry/credential-scoped PRF salt, isolation and fanout proof, real token tests |
| F-4 / SEC-06 | **OPEN — OWNER PROFILE/OPEN-15** | Distinguish hardware UP and UV, no silent downgrade, hardware proof per read |
| F-5 / A02E-01 | **CLOSED — structural route validator only** | Preserve exhaustive VLY2/V02-B/V3RV parity; complete authenticated ancestry/owner graph still open |
| F-6 / SEC-05 | **PARTIAL — REVIEW-ONLY WIRE** | V3RV authenticated seal/open, reviewed committing construction, new cross-library vNext crypto KATs and migration |
| F-7 / SEC-06 | **OPEN — VERIFIED FACTORS** | Trusted FIDO2 factor constructors, registry/RP/UV/UP/freshness and device evidence |
| F-8 / SEC-09 | **PARTIAL — MEMORY AUDIT OPEN** | Audit intermediate copies, crypto crate internals, failure/timeout zeroization |
| F-9 / SEC-16 | **PARTIAL — METADATA AUTH OPEN** | DEK-bound origin/username/title in new version; canonical origin and trusted browser fill + migration |
| W1 / SEC-17 | **OPEN — FULL GRAPH / NONCE / ROLLBACK** | Rust commit-time ancestor ownership/cycles/duplicate checks; nonce uniqueness **per key**, not blanket cross-slot nonce ban; S4/R8 snapshot limitations |

**No task in this table is implicitly owner-approved by merging the findings PR; the F-5 closure is restricted to structural policy parity.**

## 2m. V02-I FIDO2 hardware assurance and PRF isolation (review-only)

[**V02-I protocol and two-key lifecycle proposal**](../security/V02I-fido2-prf-isolation-and-hardware-assurance.md) addresses SEC-06 (F-3/F-4/F-7), SEC-17 (W1 scope) and FR-AUTH-02/FR-REC-02 without shipping cryptography.

| ID | Candidate acceptance | Supporting evidence | Still blocked |
| --- | --- | --- | --- |
| A02I-01 | Distinct proposed per-entry/slot/credential/purpose public PRF evaluation input | Six cross-language frozen preimages/32-byte CTAP **salt hashes**, Rust `#[cfg(test)]` and Python reference verify; reject wrong entry owner, nil IDs, oversize credential, zero RP | Real FIDO2 PRF proof, OPEN-01/15 security review; hashing public context is NOT hardware or crypto proof |
| A02I-02 | No confusion of WebAuthn PRF versus native CTAP hmac-secret inputs | WebAuthn `eval.first=raw_input`; native CTAP `salt32=SHA256("WebAuthn PRF"||0||raw_input)`; reject proposed no-UV branch via browser PRF, permit synthetic native flag only as a review case | Same credential/UV/RP real-device compatibility and signed UP/UV verifier |
| A02I-03 | Separate vault-level trusted-key registration from entry-specific access | Primary-only creation leaves backup `PENDING`; later independently seal backup route with present device and authorized DEK, VMK write/Option A when code-dependent | V04/V06 runtime trustworthy slot provisioning, atomic commit/coverage verification |
| A02I-04 | No S2 or owner consent weakening | Isolated every complete DEK route physical; STRICT_NONE disables recovery only; explicit Isolated→Standard downgrade/re-encryption path; no silent weaker Standard recovery | OPEN-REC-CONSENT and OPEN-HW-ASSURANCE owner decisions, no complete runtime ancestry enforcement |
| A02I-05 | Hardware evidence and release boundaries stay open | Unexecuted I-P01–I-P09 OPEN-15 matrix, separately listed OPEN-PRF-SALT and UV/UP owner question, source-pinned reviewer inventory | No hardware operation, no authenticated vNext seal/open, no G1/G2/G3 release gate |

**V02-I can merge only as an unapproved policy and synthetic input-validation milestone.** It does not close OPEN-15, OPEN-01, SEC-06, SEC-17, recovery completeness, or any runtime safety gate.

## 2n. V02-J isolated FIDO2 hardware verification foundation (NO device evidence)

| ID | Internal foundation acceptance | Evidence and execution boundary | Not established |
| --- | --- | --- | --- |
| A02J-01 | Explicit device/terminal/CI opt-in; synthetic test credentials only | `tools/hardware/fido2_v02j.py` refuses CI, unselected devices, non-tty, repository session paths and symlinks; exact `--hardware-test` gate | Device availability, trusted RP/registry, hardware token proof or production unlock |
| A02J-02 | Signed assertion verification must precede trusting PRF observations | libfido2 `-G -h -p -v` signed native challenge + separate `-V -h -p -v`, saved test-only public key and challenge/RP binding; offline mocks, not live device | Actual attestation-chain verification, local PIN/biometric behavior, browser origin control or OPEN-15 |
| A02J-03 | Two token/entry PRFs never exposed in receipts | Primary+backup credentials are independently created, separate V02-I entry/slot/credential salts, repeated signed assertions compared only in memory; receipt excludes output/challenge/ID, `entry_route_ready=false`; Python full zeroization **not guaranteed** | Real hardware equality/isolation; independent physical devices; production key wipe/provenance |
| A02J-04 | I-P01–I-P09 gaps are not silently green | [Local operator runbook and I-P mapping](../security/V02J-isolated-fido2-hardware-verification.md#3-hardware-matrix-mapping-no-automatic-approvals), tests only in GitHub/Forgejo without devices, `full_i_p01_to_i_p09_matrix=NOT_EXECUTED`; no browser/atomic rewrap | Actual real-device reviewer results, signed negative/replay and browser/native parity, V04/V06 runtime |
| A02J-05 | Source inventory and release gates remain honest | Static policy tests plus explicit external reviewer scope; `OPEN-HW-ASSURANCE`/`OPEN-PRF-SALT` unresolved; OPEN-01/15 and G1–G3 remain BLOCKED | Approved UV/UP policy, PRF salt protocol, key commitment or production authentication |

**V02-J may merge as a local lab test harness only.** No suite runs a physical key in CI; local observations need independent qualified review and all incomplete I-P tests before OPEN-15 could close.

## 2o. V02-K owner-executed hardware evidence intake (not independent review)

| ID | Internal acceptance | Evidence scope | Still unavailable |
| --- | --- | --- | --- |
| A02K-01 | Rust operator runner works from a clean clone without new dependencies | `tools/v02_verifier/src/bin/vaulty_v02k.rs` in existing locked verifier crate; preflight has no HID access; explicit Linux/TTY/CI/device/primary+backup gates; **EV-023 records operator-observed execution** | Independently authenticated physical evidence; hardware safety review |
| A02K-02 | Strictly reduce source test receipts to a non-secret summary | Reject unknown/duplicate V02-J fields, altered hardware approval flags, invalid UV/string values and malformed reports; never read session credentials or PRF output bytes into Rust | Cryptographically signed provenance, real attestation and browser origin |
| A02K-03 | Preserve truthful evidence coverage and incomplete execution | Each key has local `OBSERVED`, `OBSERVED_MISMATCH` or `NOT_EXECUTED` status; only partial native I-P01/02/03/04/06, I-P05/07/08/09 unexecuted; always OPEN-15/01 and G1–G3 BLOCKED | Full I-P01–I-P09 hardware signoff, trusted Vaulty entry route/READY |
| A02K-04 | Owner-facing run command and redaction guidance | [V02-K source-pinned runbook](../security/V02K-physical-fido2-verification-and-evidence.md) specifies clone/checkout, cargo `--locked`, `fido2-token -L`, primary/backup device opt-in, share only `evidence-v02k.json` | CI cannot and does not produce physical token evidence |

**V02-K is merged; EV-023 operator observations received.** This does not upgrade the full I-P01–I-P09 matrix, prove physically distinct tokens or close OPEN-15. Mocked CI and local JSON receipt checks cannot approve hardware assurance.

## 2p. V02-L-A/B native negative verification — review-only

| ID | Acceptance target | Test-only evidence | Remaining |
| --- | --- | --- | --- |
| A02L-01 | Fail closed on modified signed native assertions | Local -V positive control followed by wrong challenge/RP/authenticator-data/signature/public-key negatives; offline mocks test expected exit and unexpected verifier acceptance | Hardware execution and independent signed transcript review; no daemon replay cache |
| A02L-02 | Require signed UP/UV and RP match using genuine CLI encoding | Canonical definite CBOR byte-string decode of `-G` authenticator data before inspecting RP/flags; original encoded third line retained unchanged for libfido2 `-V -h -p -v`; synthetic `58 25` CLI-format fixture plus malformed CBOR wrapper tests | No real signed UV-absent token, no full attestation/browser-origin proof |
| A02L-03 | Reject unauthorized credential on other token with controls | Physical probe first verifies control role, requests target credential, verifies control again; errors classified UNCLASSIFIED, not PASS | Operator must test actual tokens; separate physical-device identity not cryptographically proved |
| A02L-04 | Remain safe for PIN/timeout/removal | Never submit bad PIN, exhaust retries, reset or force token removal; absent-path precheck no device calls; CI mocks timeouts/tool errors as INDETERMINATE | Actual hardware PIN/UV/cancel/unplug & daemon fail-closed behavior later |
| A02L-05 | Source-pinned redacted reporting, blocked gates | 0600 receipts with only case statuses, clean Git SHA; no PIN/PRF/RP/credential/HID/claim of READY/APPROVED; offline test & review inventory | Independent OPEN-15/01 and G1–G3 BLOCKED |

**V02-L-A/B source is MERGED (PRs #22–23) and EV-025 records operator-reported physical execution.** The two positive signed UV/UP controls, ten modified-verifier rejects, and wrong-device before/after controls satisfy the local harness's narrow observation goals **according to the submitted redacted receipts**, not independent review. EV-023 remains the earlier separate V02-K evidence. I-P03/04/06 are still only PARTIAL; OPEN-15/01 and G1–G3 are BLOCKED. WebAuthn PRF I-P05 and passkey implementation are out of scope.

### V02-L operator feedback follow-up — TTY and safe failure classification

**Codex P2 on session preflight — ACCEPTED/FIXED IN PR CANDIDATE:** the earlier `check-session`
accepted the outer V02-J schema and two credential descriptors but did not
validate the `vault_id`, entry/slot UUIDs and PRF context fields needed by
`j._context()`. The amended offline preflight derives all four UV normal
contexts (primary/backup × alpha/beta) and rejects missing or malformed
fields, duplicate synthetic IDs/credentials, and malformed RP before reporting
`session_valid=true`. The same check guards live verifier/wrong-device
execution before operator prompts. A focused no-hardware regression creates
malformed retained private sessions and verifies blocked exit/status;
**this does not certify physical keys or runtime routes**.

**Source correction candidate (not new hardware evidence):** local user execution on
Pop!_OS reached `fido2-token -L` with both HID paths and returned
an `absent-precheck.json` with `LOCAL_ABSENCE_PRECHECK_OBSERVED`.
The user's offline suite had **one false negative** because the
non-TTY test actually ran inside an interactive terminal; remaining 32
tests passed. Generic blocked/cancelled reports did not identify whether
`$SESSION` or a receipt filename was valid. Fix the TTY regression
using explicit mocking, provide an offline `check-session`, print only
fixed-class diagnostics, and preserve no-overwrite receipts. The local
live verifier/wrong-device stages are **not accepted as tested** from
these generic failures; I-P04/I-P06 remain PARTIAL, OPEN-15/01 and
G1–G3 BLOCKED.

## 3. Security findings register

| Finding | Severity if enabled | Finding evidence | Fix workstream | Status |
| --- | --- | --- | --- | --- |
| SEC-01 | P1 | Legacy `src/util/gocrypt.rs` contains master-key dump/destructive experiments on main | V01-A | PR #7 deletes file; verification pending merge |
| SEC-02 | P1 | Native host previously returned realistic credential/save/unlocked success | V01-A | PR #7 fail-closed host + tests; pending merge |
| SEC-03 | P1 | Unbounded/indexing legacy header/payload parsing can panic on untrusted bytes | V02 | Open; default main disabled |
| SEC-04 | P1 | Legacy unkeyed header hash does not authenticate against malicious editing | V02 | Open; full canonical AEAD required |
| SEC-05 | P1 | Key hierarchy, V02-B HMAC commitment, and V3RV authenticated slot security are not externally established (F-6/Q2) | OPEN-01 + V02-G/V02-H + V04 | **BLOCKED:** P6 rejects a specific forgery but does not prove multi-key commitment; V3RV has only untrusted wire/context tests, no seal/open or authenticated vNext crypto vectors |
| SEC-06 | P1 | F-3/F-4/F-7: repeated entry PRF salt, unspecified UV/UP assurance and no verified FIDO2 factor provenance | OPEN-15 + V03/V04/V06 | **BLOCKED:** source descriptors may reuse salts and accept UV=false; decide owner assurance profile and test real physical tokens; structural flags alone are not authentication |
| SEC-07 | P2 | Native-host Rust behavior tests absent on old main | V01-A | First PR #7 CI: six host unit tests; child-process tests pending |
| SEC-08 | P2 | Filesystem crash/fault and malicious path risks | V01-A/V02 | PR #7 deterministic negative tests; TOCTOU/openat guarantee remains V02 |
| SEC-09 | P2 | F-8 partial secret-lifetime handling; fixed Zeroizing IKM scratch does not demonstrate all copies wiped | V02/V03/OPEN-01 | **PARTIAL:** audit transient copies, HKDF/HMAC/SHA2/Argon2 internals, failure/timeout and OS memory semantics |
| SEC-10 | P1 | Trusted E2E extension→daemon pairing and runtime capabilities unimplemented | V07 | Open |
| SEC-11 | P2 | Browser extension requests broad sites access; no real user-gesture authorization E2E proven | V07/V08B | Open |
| SEC-12 | P2 | Authentic file rollback may bypass local record; S4 only detection of accidental rollback | V02/V04M | Design limitation accepted, implementation missing |
| SEC-13 | P2 | No Forgejo runner execution / branch-gate evidence | Infra | Pending; no code safety claim |
| SEC-14 | P1 | F-1: separately provisioned weaker Standard-entry recovery can drop the normal password/hardware factor (Q1) | OPEN-REC-CONSENT + V04 | **OWNER DECISION OPEN:** structurally valid, not categorically forbidden; require informed per-entry choice/assurance report before any sealed weak route |
| SEC-15 | P1 | F-2: attacker-influenced Argon2 route count/cost; no approved production KDF/profile/encoding/work budget | OPEN-KDF-PROFILE/OPEN-PASSWORD-ENC + OPEN-01 + V03/V04 | **OPEN:** reviewer's ms times environment-specific; benchmark, pin parameters locally and enforce aggregate pre-auth work in Rust before active unlock |
| SEC-16 | P1 | F-9: origin/username/title remain non-DEK-authenticated in VLY2; nonce/ciphertext transition guard is bypassable by VMK holder | V02-vNext + V04M + V08 | **PARTIAL:** test-only AAD exists; new authenticated entry format, origin canonicalization, migration and trusted fill authorization required |
| SEC-17 | P1 | W1: cross-slot ancestry, duplicate owner/group/PRF scope, rollback and nonce/key reuse invariants not enforced in production Rust | V03/V04/V06 + OPEN-01/15 | **OPEN:** Python model is not runtime; enforce full authenticated graph and per-key nonce uniqueness, not an unconditional ban on cross-key repeated nonce |

Findings are prioritized by consequences **when code is enabled**. Inert legacy source does not imply a live exploit path. Treat re-enabling it without review as a high-risk regression.

## 4. Verification gaps to close before enabling the vault

**V01-A (immediate):** default binary smoke/fail-closed test; default native host UNAVAILABLE behavior; framed IPC invalid JSON/length/oversize/unknown origin; synthetic credential logging checks; removal of gocrypt diagnostic executable; deterministic filesystem failure matrix and explicit recovery instructions.

**V02–V03:** malformed/truncated/version-skew canonical header and record fuzzing; authenticated index/generation mutation; key/nonce uniqueness and key-substitution negative cases; zeroization on all error/timeout paths; low-resource/hostile KDF settings; physical FIDO2 wrong RP/credential/signature/UV or missing PRF rejection; virtual-only policy and masked-VERS lifecycle.

**V04–V09:** recovery-code repair/inactive coverage; full/hardware-loss scenarios; ISOLATED policy graph closure; independent source/destination migration and merge crashes; E2E origin/client replay and paired-identity revocation; passkey RP/counter checks; external security review with signed release criteria.

## 5. Release gate checklist

| Gate | Status | Blocking evidence |
| --- | --- | --- |
| G0 — Prototype safety | **PARTIAL** | V01-A SEC-01/02/07/08 closure, updated reproducible tests |
| G1 — Canonical cryptography | **BLOCKED** | OPEN-01 review, codec and end-to-end key graph evidence |
| G2 — Session/FIDO2 | **BLOCKED** | OPEN-15, hardware per-read checks, masked VERS lifecycle |
| G3 — Recovery/client authorization | **BLOCKED** | Complete Option A coverage and E2E pairing/IPC |
| G4 — Pilot / release | **BLOCKED** | Full real operations, restore/migration, independent review |
| G5 — passkeys/typing/sync | **DEFERRED** | Separate risk gates |

## 6. Evidence update template

For each implementation PR record:

- **Package / FR / decision IDs** and exact acceptance criterion.
- **Merged commit / PR / workflow run(s)** and test output summary.
- **Negative path(s)**, parser/fault/safety case and test names.
- **Independent review findings and disposition** where security-critical.
- **Data/migration/rollback impact** and operator recovery procedure.
- **Status before/after**, explicit **not implemented** items, gate impacted.

Claims of COMPLETE or CERTIFIED require primary evidence for the exact behavior; do not infer from code being present or a mock response.
