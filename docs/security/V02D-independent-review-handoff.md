# V02-D — Independent Cryptographic Review Readiness & Security Gap Closure

**Disposition:** REVIEW HANDOFF READY FOR EXPERT ASSESSMENT, **NOT INDEPENDENTLY REVIEWED OR PRODUCTION APPROVED**. Prepared 2026-11-07 against merged [V02-C PR #11](https://github.com/BetrayedByEthanol/Pw_Manager/pull/11), `main` merge commit `961cde0eba27a35edf84f20310c09f15ef576f7a`. Do not use test fixtures for real credentials. This work packages source and closes *test/traceability gaps only*. It does **not** claim to close OPEN-01, OPEN-15, G1–G3, or the security issues requiring independent assessment and trusted runtime.

**Normative sources:** [specification v0.4.5](../specification/v0.4.5.md); [architecture](../architecture/v0.4.5.md); [decision register](../decisions/register.md); [V02-A protocol threat review](../architecture/v02a-crypto-keyslot-review.md); [V02-B candidate transcript](../architecture/v02b-keyslot-candidate.md); [V02-C conformance packet](V02C-cryptographic-conformance.md); [independent crypto review request](../../tools/security_probes/CRYPTO_REVIEW_REQUEST.md).

## 1. Precisely what is being submitted

| Item | Evidence, scope and limitation |
| --- | --- |
| Source to assess | `src/v02/v02b.rs`, `src/v02/model.rs`, `src/v02/codec.rs`, `src/v02/mod.rs` and isolated candidate tests `v02c_tests.rs` / `v02d_tests.rs`; candidate crypto **not exposed to production runtime** |
| Replayable evidence | Six synthetic route-scoped cross-library fixture vectors, Python/libsodium/libargon2 reference `tools/v02_verifier/reference_v02c.py`, 31 V02-C Rust tests plus V02-D route-domain tests; results must be rerun on the *reviewed commit* |
| Inventory / commit binding | `tools/v02_verifier/review_bundle.py` records a **full git SHA** and SHA-256/byte lengths for an explicit source/spec/fixture allowlist, canonical JSON and **BLOCKED** gates; no implicit files, no symlinks, no false self-approval |
| Non-security evidence | CI pass, Codex review, and a self-produced manifest show reproducibility/change tracking only. **They are not independent cryptographic assurance or an authenticated reviewer signature** |
| Unavailable evidence | Independent named cryptographer's verdict, committing-AEAD proof or accepted substitute, independent third-party vectors, authenticated FIDO2 PRF/UV assertions, device capability data, trusted owner registry, real VMK/VERS/DEK and recovery flows, production wire format and verified storage lifecycle |

**Review snapshot procedure** (from exact commit; no confidential data):
```sh
git rev-parse HEAD
python3 tools/v02_verifier/reference_v02c.py --verify
cargo check --manifest-path tools/v02_verifier/Cargo.toml --all-targets
cargo test --manifest-path tools/v02_verifier/Cargo.toml --all-targets
python3 -m unittest discover -s tools/v02_verifier -p 'test_review_bundle.py'
python3 tools/v02_verifier/review_bundle.py --write /tmp/v02d-review-manifest.json
python3 tools/v02_verifier/review_bundle.py --check /tmp/v02d-review-manifest.json
sha256sum /tmp/v02d-review-manifest.json
```

Repeat on independently cloned repository at the **identical full commit**, compare manifest hashes, CI logs and input vectors, and record the commit and toolchain. This checks that the same bytes were reviewed; it **does not authenticate** who supplied those bytes, prove their safety or create a signed audit receipt. Never put secrets, raw PRF values or real recovery codes in review artifacts. GitHub CI may upload the manifest as a short-lived artifact; Forgejo can emit a digest, but **Forgejo runner execution has not been established**.

## 2. Concrete gaps and ownership (as of this PR)

| ID | Observed fact / risk if activated | Severity if enabled | Closure owner / prerequisites | Current status |
| --- | --- | --- | --- | --- |
| VD-01 | Draft `HKDF + XChaCha20-Poly1305 + HMAC` binding is **not proved key committing** in a multi-key adversarial setting; verifier can be an offline factor oracle | P1 | **Independent OPEN-01 cryptographer**: threat-model verdict, replacement/revision if rejected, independent vectors | BLOCKED — external |
| VD-02 | `Components` accepts arbitrary 32-byte bytestrings; physical descriptor/UV booleans **are not** a signed assertion or fresh PRF operation | P1 | **OPEN-15 device/security reviewer** + V03/V06 trusted authenticator implementation | BLOCKED — external + code |
| VD-03 | VLY2 pending `Slot` format lacks final factor/KDF/PRF/commitment transcript fields; candidate has no canonical on-disk serialization | P1 | **OPEN-01** approved version, then new explicit wire format / authorized migration | BLOCKED — external + code |
| VD-04 | No authenticated owner registry, revoked-credential check or complete ancestry-aware normal/recovery route proof; serialized `VERIFIED` is not authorization evidence | P1 | V03/V04/V05/V06 runtime and negative tests | OPEN — implementation |
| VD-05 | Code-dependent slot creation/rotation not connected to owner-prompted code and new-device PRF; Option A is specified but inactive | P1 | V04/V06 provisioning transaction + repair/coverage tests | OPEN — implementation |
| VD-06 | Argon2id parameter bounds are test harness limits, **not calibrated production costs**; malicious header before authentication may be expensive | P1 | OPEN-01 KDF review, platform memory/performance measurements, trusted resource budgets | BLOCKED — external + implementation |
| VD-07 | Repeatable PRF/standard shared root and VERS common ancestor imply compromise fanout; batching D-30 is only provisional | P1 | OPEN-15 scope/capability/fanout trials; **owner's explicit D-30 decision** after evidence | BLOCKED — review + decision |
| VD-08 | Masked VERS software share lifecycle, zeroization under failure, transient VMK handling and secure daemon authorization not implemented | P1 | V03/V05/V07 memory + session negative checks | OPEN — implementation |
| VD-09 | Outer file AEAD authenticates content but not freshness; S4 local rollback record and descriptor-relative race-free storage are unfinished | P1/P2 | V02 storage / V04M recovery, authenticated ancestry and restore tests | OPEN — implementation |
| VD-10 | Public pre-auth metadata leakage budget, padding, allowed descriptor semantics and strict version rejection are not finalized for future slots | P2 | OPEN-01 external review + owner privacy/design decision if needed | BLOCKED — protocol |
| VD-11 | FIDO2 hardware UV flag can be declared by the candidate without device proof; UI/daemon must not infer a hardware read from that flag | P1 | OPEN-15 credential/RP/UP/UV binding + fresh assertion test | BLOCKED — real-device |
| VD-12 | Synthetic conformance and finite mutation tests cannot prove absence of multi-key substitution, side channels or all parser bugs | P1 | Independent OPEN-01 security analysis, differential fuzz/property and production parser tests | BLOCKED — external + code |

**Already addressed only at candidate-test level in V02-D:** route/factor-count table, invalid code-only hardware-vault and Isolated/STRICT_NONE paths, distinct KEK/MAC/slot/vault/target domains, and an explicit regression demonstrating that synthetic physical bytes *still unwrap* the candidate without a real authenticator. This is a **negative assurance finding**, not a hardware success. A hash inventory allows reviewers to see whether the files changed after the analysis. None of VD-01..12 is labeled APPROVED or production-closed by those tests.

## 3. OPEN-01 independent cryptography reviewer instructions

The reviewer must **not** assume that a green KAT establishes cryptographic security. Evaluate the exact v02b descriptor framing (in-memory struct rather than finalized wire bytes), byte order, domain separation, factor recipes and source of entropy, version ambiguity, lengths and KDF salts. Consider at least:

1. **Key commitment / substitution:** Can an attacker arrange a single candidate envelope that passes under two keys or routes, or adapt ciphertext/commitments to pass with an unintended key? What precisely is committed (descriptor, slot nonce, AEAD ciphertext, MAC) and what is missing? Demand an explicit accepted construction/proof or redesign with tests.
2. **Offline and online guessing:** Model weak master passwords, code-only 256-bit recovery, software virtual seed, leaked/correlated PRF, mixed-key confusion and compromised scoped PRF. Compare attack cost with and without hardware, especially when a seed is bootstrapped before outer VMK authentication.
3. **Factor order and roles:** Examine single-input seed bootstrap versus normal password+virtual and password+hardware; administrative code+password/token routes; prohibit software normal Isolated and code-only hardware-vault VMK. Evaluate whether splitting VMK metadata vs VERS vs entry DEK keys actually prevents implied access across roots.
4. **Untrusted metadata / resource bounds:** Are all descriptor flags, registry references, KDF parameter values, salts, provider identity and target/policy fields authenticated *after* verification? What can be safely read/processed before costly KDF? Are error responses/timing revealing a password verification oracle?
5. **Implementation correctness:** Evaluate memory and secret lifetimes, RNG and nonce uniqueness, wiping temporary IKM/KEK/DEK, malformed decoding, related-key multi-slot contexts, and library versions. Do not equate `Zeroizing` wrapper usage with complete secrecy of all allocations.
6. **Migration/versioning:** Specify final portable byte-level schema, unknown-field behavior and explicit conversion; no silent reinterpretation of VLY2 candidate/pending slots or transplantation of DEKs across vaults.

**Required signed/recorded outcome:** reviewer identity + organization/qualifications; review date; full source commit and inventory digest; threat model and exact protocol/version; scope of files and hardware tested; reproducible attacks/findings (severity/reproduction); independent vectors or explanation why not possible; conditions/tests/migration changes; **APPROVED / APPROVED WITH CONDITIONS / REJECTED**; how remediation is independently rechecked. **No such external verdict currently exists.** Record a negative outcome instead of silently revising the candidate in place.

## 4. OPEN-15 independent FIDO2 PRF/UV device review plan (NOT executed)

This section is an **empty operator/reviewer evidence template**, not actual device evidence. Reviewer must record test platform, OS, browser/CTAP API, authenticator make/model and firmware (no personal credential identifiers), enrolled RP ID and credential-binding method, UP and UV policy, PRF extension availability and resulting asserted flags. Record *pass/fail* and an evidence artifact for each:

| ID | Device test | Evidence to capture (no secrets) | Observed |
| --- | --- | --- | --- |
| P01 | Two same-salt/credential derivations with enrolled UV/UP | Matching output digest **inside trusted test process only**; authenticated credential/RP/UV association | NOT RUN |
| P02 | Fresh physical access operation twice | Two distinct authorized assertion ceremonies, no old assertion/PRF replay | NOT RUN |
| P03 | Wrong RP ID, credential, PRF salt or UV mode | Rejection, no software fallback, no VMK/DEK release | NOT RUN |
| P04 | PIN/UV disabled/downgraded, missing UP or unsupported PRF | Fail closed without falling back to UV=false or virtual token | NOT RUN |
| P05 | Unplug, timeout, cancel, suspended/revoked device | Abort, wipe temporary material, preserve old valid envelopes | NOT RUN |
| P06 | Shared Standard root: one authorized batch | Recorded salt count, touches, latency, max batch and fanout; ensure each sensitive read stays fresh | NOT RUN |
| P07 | Per-entry/per-slot root for Isolated | Demonstrate entry-scoped salt and operation, independent of shared Standard material | NOT RUN |
| P08 | Loss/replacement/forgot-password recovery | Option A code prompts when **new** code-dependent slots are created, new device PRF, no VMK-to-DEK bypass | NOT RUN |
| P09 | PRF output not bound to assertion or replayed assertion | Reject swapped results; no trust from a public descriptor `uv_required=true` flag alone | NOT RUN |

**OPEN-15 required outcome:** credential/RP/UV/salt transcript, device support matrix and limitations, failure evidence, scoping/fanout review, code-dependent re-enrollment behavior, explicit decision on D-30 batching recommendation, independent reviewer conclusion tied to full commit. No hardware verdict may be fabricated from synthetic PRF input tests.

## 5. External reviewer response / decision log template (unfilled)

| Field | Required value |
| --- | --- |
| Ticket | OPEN-01 or OPEN-15 (separate verdicts) |
| Reviewer, role and date | **NOT ASSIGNED** |
| Source commit and manifest digest | **TO BE CAPTURED** |
| Exact cryptographic protocol, scope, threat model | **NOT REVIEWED** |
| Findings and severity, reproducer/evidence | **NOT REVIEWED** |
| Independent vectors / real hardware device matrix | **NOT PROVIDED** |
| Verdict (APPROVED / CONDITIONS / REJECTED) | **NO VERDICT** |
| Required remediation, implementing PR and retest | **NOT REVIEWED** |
| Signed/recorded approval and owner acceptance | **NOT PROVIDED** |

**Acceptance rules:** The V02-D PR itself may merge after normal CI/code review, but it **must not** mark OPEN-01/15 as approved, change gate G1/G2/G3 to PASSED, enable use of real credentials, mint active READY/VERIFIED slots, or silently update existing v0.4.5 policy. If the external reviewer rejects any design, revise with a new versioned protocol and independent regression vectors before any activation.

## 6. Subsequent execution order

1. Obtain a qualified independent OPEN-01 review of this pinned code and synthetic KATs, respond to findings in an explicitly versioned follow-on PR.
2. Acquire representative FIDO2 devices and run P01–P09 with authenticated assertions; obtain independent OPEN-15 assessment. Resolve D-30 provisional shared-root batching with actual capability and fanout evidence.
3. Only with approved crypto/device protocols implement canonical slot serialization, owner registry, trusted factor acquisition, complete route graph, Option A sealing/verification, rollback-aware storage, and negative end-to-end checks.
4. Re-submit changed implementation bytes and evidence to reviewers and keep production runtime **disabled** until all release gates are independently accepted.

**Invariants not relaxed:** VMK never derives VERS/DEKs; password-only software adapter is not 2FA; normal Isolated reads always physically mandatory regardless of STRICT_NONE; Isolated recovery physically mandatory or disabled; hardware-vault VMK never code-only; Option A code required when a code-dependent envelope is created/replaced; no silent wire migration.
