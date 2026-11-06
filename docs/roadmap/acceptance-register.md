# Vaulty — Acceptance, Evidence and Security Gap Register

**Snapshot date:** 2026-11-06 | **Repository evidence baseline:** `main` merge commit `84f92be9849fab2afce57223d4bf3c113bcf5e46` (PR #8 merged, V02 candidate only). V02-A is a design-review branch, not independent approval.  
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

| EV-011 | [V02-A candidate protocol review](../architecture/v02a-crypto-keyslot-review.md) | Documents current slot-schema gaps, proposed transcripts, Option A/OPEN-02 provisioning, threat matrix and OPEN-01/15 external reviewer exit criteria. **Document review only; PR not merged at this checkpoint.** | Not independent cryptographic approval, runtime negative-test evidence, key commitment proof or V02-B implementation |

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

## 3. Security findings register

| Finding | Severity if enabled | Finding evidence | Fix workstream | Status |
| --- | --- | --- | --- | --- |
| SEC-01 | P1 | Legacy `src/util/gocrypt.rs` contains master-key dump/destructive experiments on main | V01-A | PR #7 deletes file; verification pending merge |
| SEC-02 | P1 | Native host previously returned realistic credential/save/unlocked success | V01-A | PR #7 fail-closed host + tests; pending merge |
| SEC-03 | P1 | Unbounded/indexing legacy header/payload parsing can panic on untrusted bytes | V02 | Open; default main disabled |
| SEC-04 | P1 | Legacy unkeyed header hash does not authenticate against malicious editing | V02 | Open; full canonical AEAD required |
| SEC-05 | P1 | Authoritative key hierarchy/slot commitments are not production-approved | OPEN-01 + V02-A/V02-B | Blocked; V02-A design gaps documented, external review needed |
| SEC-06 | P1 | Hardware PRF salt/UV/freshness/fanout not approved or enforced at runtime | OPEN-15 + V02-A/V03/V06 | Blocked; V02-A review questions documented, real device evidence needed |
| SEC-07 | P2 | Native-host Rust behavior tests absent on old main | V01-A | First PR #7 CI: six host unit tests; child-process tests pending |
| SEC-08 | P2 | Filesystem crash/fault and malicious path risks | V01-A/V02 | PR #7 deterministic negative tests; TOCTOU/openat guarantee remains V02 |
| SEC-09 | P2 | Secret copies not consistently scoped to failure-path RAII zeroization | V02/V03 | Open |
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
