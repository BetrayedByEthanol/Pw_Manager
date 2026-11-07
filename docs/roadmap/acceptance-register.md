# Vaulty — Acceptance, Evidence and Security Gap Register

**Snapshot date:** 2026-11-07 | **Repository evidence baseline:** `main` merge commit `122479b439210964af39dae7e7d5ae025217394b` (V02-E PR #13 merged, inactive candidate hardening only). V02-F is a **proposed** owner/expert decision packet, not production security approval.  
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
| EV-016 | [V02-F PR #14](https://github.com/BetrayedByEthanol/Pw_Manager/pull/14); [focused V02 CI](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42405940188); [product safety CI](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42405940176); [security probes](https://github.com/BetrayedByEthanol/Pw_Manager/actions/runs/42405940269); [V02-F policy packet](../security/V02F-recovery-assurance-and-cryptographic-policy.md) | **Unmerged design proposal:** code head `d2a9cb67` passed 40/40 Rust tests, six libsodium vectors, libargon2 reference, six manifest tests, four document/approval-boundary tests and all three GitHub workflows; Git-blob-verifiable 29-file inventory PASS. Normal/recovery root matrix, weaker-route consent/KDF/encoding owner questions, vNext review contract. Initial P1 wording and P2 GitHub workflow trigger Codex findings corrected; final-head independent review is separately tracked. | No approved F-1 consent, production Argon2 profile or NFC policy, PRF salt/UV, cryptographic commitment or final wire; OPEN-01/15 and G1–G3 still blocked. |

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

## 3. Security findings register

| Finding | Severity if enabled | Finding evidence | Fix workstream | Status |
| --- | --- | --- | --- | --- |
| SEC-01 | P1 | Legacy `src/util/gocrypt.rs` contains master-key dump/destructive experiments on main | V01-A | PR #7 deletes file; verification pending merge |
| SEC-02 | P1 | Native host previously returned realistic credential/save/unlocked success | V01-A | PR #7 fail-closed host + tests; pending merge |
| SEC-03 | P1 | Unbounded/indexing legacy header/payload parsing can panic on untrusted bytes | V02 | Open; default main disabled |
| SEC-04 | P1 | Legacy unkeyed header hash does not authenticate against malicious editing | V02 | Open; full canonical AEAD required |
| SEC-05 | P1 | Authoritative key hierarchy/slot commitments are not production-approved | OPEN-01 + V02-A/V02-B | Blocked; internal V02-B HMAC/slot prototype is not an independently proven committing-AEAD |
| SEC-06 | P1 | Hardware PRF salt/UV/freshness/fanout not approved or enforced at runtime | OPEN-15 + V02-A/V03/V06 | Blocked; V02-A review questions documented, real device evidence needed |
| SEC-07 | P2 | Native-host Rust behavior tests absent on old main | V01-A | First PR #7 CI: six host unit tests; child-process tests pending |
| SEC-08 | P2 | Filesystem crash/fault and malicious path risks | V01-A/V02 | PR #7 deterministic negative tests; TOCTOU/openat guarantee remains V02 |
| SEC-09 | P2 | Secret copies not consistently scoped to failure-path RAII zeroization | V02/V03 | Partial V02-E candidate: fixed zeroizing combiner IKM; crypto-library internal scratch and failure/timeout paths remain open |
| SEC-10 | P1 | Trusted E2E extension→daemon pairing and runtime capabilities unimplemented | V07 | Open |
| SEC-11 | P2 | Browser extension requests broad sites access; no real user-gesture authorization E2E proven | V07/V08B | Open |
| SEC-12 | P2 | Authentic file rollback may bypass local record; S4 only detection of accidental rollback | V02/V04M | Design limitation accepted, implementation missing |
| SEC-13 | P2 | No Forgejo runner execution / branch-gate evidence | Infra | Pending; no code safety claim |

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
