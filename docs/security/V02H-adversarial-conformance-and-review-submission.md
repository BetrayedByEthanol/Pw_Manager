# V02-H — Adversarial Cryptographic Conformance & Independent Review Submission

**2026-11-07 — PRE-APPROVAL SECURITY REVIEW PACKAGE / NOT A CRYPTOGRAPHIC VERDICT**

**Baseline:** merged [V02-G PR #15](https://github.com/BetrayedByEthanol/Pw_Manager/pull/15), `239f80cb85cdbd4fb890fed0a6abf1edb247499c`. Normative owner policy: [v0.4.5](../specification/v0.4.5.md). Proposed slot bytes: [V02-G V3RV](../architecture/v02g-vnext-cryptographic-protocol-review.md). Recovery/KDF/encoding decisions: [V02-F](V02F-recovery-assurance-and-cryptographic-policy.md). **Status: OPEN-01 and OPEN-15 BLOCKED; G1/G2/G3 BLOCKED; V3RV test-only, untrusted, not an implemented authenticated slot or approved production format.**

## 1. What is actually verified in V02-H

| Evidence | Inputs and checks | Does NOT prove |
| --- | --- | --- |
| **H-01 independently coded Python V3RV codec** | `tools/v02_verifier/reference_v02h.py` uses Python `struct`/cursor and a separately authored policy matrix; five fixed synthetic examples cover password-only VMK, Standard weaker recovery, Isolated independent/group recovery and custom physical normal routes | Independent **person** reviewed the protocol; real factor provenance; AEAD/commitment or cryptographic security |
| **H-02 source-frozen cross-language wire vectors** | `tools/v02_verifier/fixtures/v02h_wire_vectors.txt`: exact V3RV hex, SHA256 of `slot_context` and SHA256 of `commitment_context`; `src/v02/v02h_tests.rs` independently constructs Rust examples and checks byte equality and 5/5 context hashes | New cross-language **vNext KEK, AEAD or MAC** vectors: there is **no implemented vNext seal/open to test**; only opaque public framing/context |
| **H-03 strict parser/mutation corpus** | Every proper truncation of all five vectors, appended bytes, invalid magic/version/suite, 1,800 seeded Python mutations, and 4,096 deterministic Rust mutations; accepted mutations must round-trip canonically and VLY2 must reject V3RV | CSPRNG/fuzzer completeness, constant-time crypto, authentication of mutated ciphertext |
| **H-04 recovery and ancestor attack model** | `test_v02h_adversarial.py`: fail wrong vault/group/entry code scope, Isolated code-only/STRICT_NONE recovery, physical descriptor mismatch, duplicated slots, ancestor cycles/dangling links/cross-vault declared parent | Trusted owner registry, complete multi-parent/alternate-route graph or claimed hardware proof. This is an **independent reference model**, not production enforcement |
| **H-05 hostile KDF budget model** | Simulated 256 valid expensive candidate slots, owner-selected route count, cumulative `memory_kib × passes`, single-derivation memory and duplicate selection gates; no expensive Argon2 work run. Numeric limits in tests are **illustrative only** | Production Argon2 minimum/maximum, actual p95 latency, memory allocation bounds, server DoS resistance |
| **H-06 committed source provenance** | `review_bundle.py` includes Rust, Python, fixtures, dependency lockfiles, and design/gate records. Exact Git-blob compare, 6 tamper tests, canonical JSON manifest and immutable workflow artifact; OPEN-01/15/G1/G2/G3 read as BLOCKED | Digital signature, external review, SBOM completeness or successful Forgejo runner execution |

**Independent reference** here means independently authored *Python and Rust parsing implementations* tested against frozen output. Both were produced in the same development effort. This is **not** a qualified independent cryptographer's security assessment, and the frozen fixture file alone cannot test the security of key commitment.

## 2. Reproduction and exact evidence

Source-of-truth:
- `src/v02/vnext_review.rs` — `#[cfg(test)]` V3RV strict decoder/encoder, opaque fields; `src/v02/v02h_tests.rs`— cross-language vector and hostile byte regression.
- `tools/v02_verifier/reference_v02h.py` — separately implemented Python parser, canonical encoder, seeded mutation generator. `--print-fixtures` reproduces expected rows **for inspection only**; CI uses `--verify` against the **committed** fixture, never self-updating it.
- `tools/v02_verifier/test_v02h_adversarial.py` — graph/scope and work-budget negative model. `tools/v02_verifier/fixtures/v02h_wire_vectors.txt` — five **synthetic** fixed untrusted envelopes and two SHA256 context digests each.
- `tools/v02_verifier/review_bundle.py` — source-pinned reviewer inventory; verifier Cargo.lock and root Cargo.lock included.

Run on a clean, exact PR commit, with Python 3 and Rust locked dependencies:

```sh
cargo check --manifest-path tools/v02_verifier/Cargo.toml --locked --all-targets
cargo test --manifest-path tools/v02_verifier/Cargo.toml --locked --all-targets
python3 tools/v02_verifier/reference_v02h.py --verify
python3 -m unittest discover -s tools/v02_verifier -p 'test_v02h_adversarial.py' -v
python3 tools/v02_verifier/reference_v02c.py --verify
python3 -m unittest discover -s tools/v02_verifier -p 'test_review_bundle.py' -v
python3 -m unittest discover -s tools/v02_verifier -p 'test_v02f_policy_contract.py' -v
python3 tools/v02_verifier/review_bundle.py --write /tmp/v02h-review-inventory.json
python3 tools/v02_verifier/review_bundle.py --check /tmp/v02h-review-inventory.json
```

**Differential check:** The Python source constructs V3RV specimens without calling the Rust encoder. The frozen text lines contain `case_name|frame_hex|slot_context_sha256|commitment_context_sha256` with no secret material. Rust encodes the same distinct typed cases and checks all four fields, rejects them as VLY2, then performs independent mutations; Python separately decodes, re-encodes, rejects all truncations and mutates deterministic bytes. Any change to framing, metadata semantics or review domain labels requires an explicit version and conscious vector revision, **not silent fixture regeneration**.

**The V02-C cryptographic KATs are still for V02-B**: six Python/libsodium versus Rust Argon2id/HKDF/AEAD/HMAC synthetic vectors are not rebranded as V3RV crypto conformance. V02-H currently has cross-language wire and *context* conformance only, because no reviewed vNext key derivation/authentication has been implemented. Closing that gap requires a new protocol/candidate implementation plus new independent cryptographic vectors and OPEN-01 approval.

## 3. Threat/failure probes for external cryptographer

| ID | Question / attack scenario | Local evidence | Required independent finding |
| --- | --- | --- | --- |
| H-T01 | Can one ciphertext validate under two distinct factor-derived keys or targets? | **NOT TESTED for vNext**: only unverified 32-byte commitment field and separate input-domain hashes; tests intentionally accept parse-valid altered ciphertext | Define formal multi-key commitment notion; prove/attack proposed construction or prescribe established committing AEAD. P6-style wrong-tag forgery isn't sufficient |
| H-T02 | Can correlated/malicious physical PRF, weak password, shared recovery code or virtual provider collapse KEK factor independence? | V02-C old-schedule synthetic KATs and V02-H policy matrix only | Review exact typed-factor HKDF IKM and salt/domain transcripts for all root/seed/VERS/entry paths |
| H-T03 | Does code-only VMK recovery imply a hidden DEK bypass? | Synthetic root/entry split and S2 Isolated rejection; default Standard weak code-only DEK route is **separate** and structurally permissible | Analyze complete effective routes with correct code owner, authorized group ancestry, weak-path consent/repair and access to original virtual-provider seed |
| H-T04 | Can hostile graph ancestry reference revoked, duplicate or non-owned slots and still appear READY? | Review-model detects duplicate/cyclic/dangling/cross-vault links; Rust V3RV codec only rejects self-ref/nil; no authenticated registry exists | Specify multi-parent route graph/ancestry and atomic approval/revocation protocol; demonstrate implementation before G1/G2 |
| H-T05 | Can untrusted public descriptor cost produce offline/online guessing or resource exhaustion? | Test-only parse bounds and simulated 256 slots/aggregate memory-pass work; **no real expensive cost measurements** | Select benchmarked Argon2id work floor/ceiling, cap number of authoritatively selected alternatives, reject headers before costly work, cap concurrency |
| H-T06 | Does UV, RP, credential and salt scope actually tie a fresh token operation to this slot? | `V3RV` flags/PRF salts remain **attacker claims**; test shows Isolated entries can share same salt in current prototype | Complete OPEN-15 hardware P01–P09 matrix with real enrolled tokens, fresh per-read user presence/verification and approved per-entry salt derivation |
| H-T07 | Can VMK-only metadata writer redirect an entry fill to attacker origin? | V02-E DEK-AAD future proposal and V02-H context references; **no vNext encrypted entry format** | Authenticated origin/RP canonicalization, DEK-bound metadata, trusted fill authorization and explicit VLY2 migration |
| H-T08 | Can a review-only V3RV envelope be automatically interpreted as a VLY2 or downgrade an existing slot? | Cross-language distinct magic/version and VLY2 classifier rejection | Independently review final authenticated version negotiation, safe rollback/migration and no unauthenticated legacy switch |
| H-T09 | Can all secret copies be zeroized on failure/cancellation, including HMAC/HKDF/Argon2 internals? | V02-E fixed combiner IKM only; V02-H doesn't manipulate secrets | Inspect crate internals/features, memory lifecycle, error paths, desktop process isolation; no false total zeroization guarantee |

**Important attacker model distinction:** A parse-valid altered `ciphertext`, `nonce`, `commitment`, `credential_id` or `uv` field *is expected* to parse if structurally valid. That is not an exploit in a parser; it is the reason a full authenticated implementation, trusted factor provenance and key commitment approval remain blockers. The tests assert canonicality, **not** false authentication rejection.

## 4. Reviewer packet and request for explicit verdicts

Provide a qualified independent reviewer:
1. Exact pinned V02-H PR-head/merge Git hash and generated `review_bundle.py` JSON inventory (full-file SHA256/bytes) with both Cargo lockfiles, protocol docs, source, Python/Rust tests and frozen fixture.
2. The [V02-G proposed wire and schedule](../architecture/v02g-vnext-cryptographic-protocol-review.md), [V02-F decision contract](V02F-recovery-assurance-and-cryptographic-policy.md), v0.4.5 S1/S2/R1/Option A and [V02-D gap register](V02D-independent-review-handoff.md).
3. Threat questions H-T01–09, code-only versus hardware-vault VMK matrix, Isolated route graph and code-scope examples; highlight proposed but **not authorized** F-1 weaker Standard recovery opt-in, numeric Argon2 and NFC decisions.
4. Independent device reviewer separately receives [P01–P09](V02D-independent-review-handoff.md) with specified real credentials, RP/UV/UP settings and physical-device evidence collection; none of these are executed by this PR.

**External OPEN-01 cryptographer's required deliverable (blank until actually completed):**

| Field | Status / reviewer must supply |
| --- | --- |
| Named reviewer, expertise/organization, date, reviewed Git commit and full dependency/fixture digest | **NOT PROVIDED** |
| Security model, exact multi-key commitment property and assumptions | **UNREVIEWED** |
| Determination on typed factor combiner, code scope/ancestor routes, hostile KDF/Unicode inputs | **UNREVIEWED** |
| Final authenticated vNext wire, key schedule, nonce and version/migration rules | **NOT APPROVED** |
| Reproducible attacks, severity, recommended changes and negative vectors | **AWAITING REVIEWER** |
| Independent cryptographic verdict: APPROVED / REJECTED / CONDITIONAL, scope and conditions | **NO VERDICT** |

**External OPEN-15 FIDO2 review:** distinct independent credentials/device runs, per-entry PRF salt/freshness/batching/UV and fail-closed negative cases; **NO DEVICE TESTS/VERDICT**. One external review does not implicitly close the other.

## 5. Merge criteria and remaining blockers

A V02-H PR may merge as an **internal adversarial conformance and submission package** when:
- Both independent-language wire verifiers and frozen vector/context digests pass, hostile mutation corpus reproducible, graph/KDF negative tests pass, and source manifest is pinned to the exact commit.
- Existing V02-C KATs unchanged, VLY2 format untouched, no real credentials or active slots, no production password normalization/Argon2 or trusted FIDO2 implementation.
- Security/reference/full-product workflows pass; full-head code review findings addressed; docs and acceptance/decision/feature registers explicitly distinguish simulated models, candidate syntax and external approval.

**Remain blocked after merge:** OPEN-01, OPEN-15, OPEN-REC-CONSENT, OPEN-KDF-PROFILE, OPEN-PASSWORD-ENC, OPEN-VNEXT-WIRE, G1/G2/G3, full authenticated V3RV cryptographic conformance, pre-auth resource limits, real hardware and recoverability, trusted daemon/browser, key lifetime/fuzz property coverage, and final authorized VLY2→new-format migration.

**Next recommended action:** deliver the pinned packet to a qualified independent cryptographer **early**, while separately planning real FIDO2 tests. Treat their attack findings as inputs to an explicit revised protocol and new frozen cryptographic test vectors, never as implicit acceptance. 
