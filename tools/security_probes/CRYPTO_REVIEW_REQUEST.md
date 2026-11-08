# Vaulty OPEN-01 — independent cryptographic review request

**Review status: REQUESTED / NOT COMPLETED.** See the merged [V02-A threat and key-slot review](../../docs/architecture/v02a-crypto-keyslot-review.md) for R1/Option A/OPEN-02 dependencies and the [V02-B internal candidate prototype](../../docs/architecture/v02b-keyslot-candidate.md) for an additional, **unapproved** experimental HKDF/HMAC/AEAD transcript. The older reference transcript below is also an *unapproved candidate*, not production code. Review is requested before enabling it in the vault engine, advertising key commitment, or declaring G1 complete.

## Scope and reviewer deliverables

Please independently assess (a) factor-combining security and authentication-factor assumptions, (b) two-input versus code-only isolation, (c) wrap KEK and commitment key separation, (d) binding of vault, target key, wrapping slot, policy, nonce, AAD and ciphertext, (e) multi-key/key-substitution attacks, (f) online/offline oracles and side channels, (g) FIDO2 PRF salt and fanout (OPEN-15), (h) recovery-code semantics, and (i) exact migration/versioning requirements.

Return a concrete attack analysis, required protocol changes, test-vector corrections and an explicit approval/rejection with threat-model caveats. Matching reference vectors is **not** evidence of cryptographic security.

## Candidate derivation — precise bytes

**Historical probe framing, not the frozen VLY2 slot transcript:** This formulation does not distinguish every administrative recovery route by a dedicated `route_kind`, does not include authenticated PRF salt/credential/RP/UV or production Argon2id parameters, and has no demonstrated committing-AEAD security. Those omissions and the old 48-byte V02 envelope assumption must be addressed before V02-B. Existing vector parity must not be promoted to independent approval.

All text context is UTF-8. `frame(x)=u16be(len(x)) || x`; maximum frame size 65535. Context strings are nonempty and <=255 UTF-8 bytes. Context field order is fixed.

```
P    = ASCII("VAULTY-KEK-v0.4-CANDIDATE") || 0x00
C    = frame(vault_id) || frame(target_id) || frame(slot_id)
       || frame(purpose) || frame(policy)
salt = SHA256(P || ASCII("SALT") || 0x00 || C)

IKM_2 = P || ASCII("TWO-FACTOR") || 0x00
        || frame(first_component_32) || frame(prf_component_32)
IKM_R = P || ASCII("CODE-ONLY") || 0x00 || frame(recovery_code_32)
PRK   = HKDF-Extract-SHA256(salt, selected_IKM)
info  = P || ASCII("EXPAND") || 0x00 || frame(mode) || C
KEK   = HKDF-Expand-SHA256(PRK, info, 32)

commit_info = P || ASCII("COMMIT-KEY") || 0x00 || frame(mode) || C
commit_key  = HKDF-Expand-SHA256(PRK, commit_info, 32)
commit_input = P || ASCII("COMMIT-TAG") || 0x00 || C
             || frame(nonce_24) || frame(AAD_bytes) || frame(wrapped_ciphertext_bytes)
commit_tag   = HMAC-SHA256(commit_key, commit_input)
```

`mode` is exactly `two_factor` or `recovery_code_only`. The candidate `first_component_32` is random VERS or 32-byte Argon2id output; `prf_component_32` must be a policy-authenticated, domain-scoped FIDO2 PRF output or the **software-only** virtual adapter output. The virtual adapter does **not** add a second independent security factor. The `recovery_code_32` is a uniformly random 256-bit secret and deliberately has no dummy second component. The draft does **not** define how to verify FIDO2 assertions, how to choose production Argon2id costs, whether credentials support PRF batching, or a final AEAD/key-commitment construction.

### Commitment-key boundary

The separate `commit_key` is not itself a formally established committing-AEAD result. The proposed `commit_tag` MAC binds the canonical AEAD nonce/AAD/ciphertext and slot context, but reviewers must determine whether it gives the required multi-user, multi-key, ciphertext-and-key commitment against chosen-key/ciphertext attacks and whether checking it leaks password/slot information. Do not claim AEAD commitment or implement "try all candidate keys until one tag matches" outside a reviewed fixed transcript, constant-time comparison and bounded authorization protocol. The JSON fixtures contain **synthetic** nonce/ciphertext bytes; there is no claim of AEAD integration testing.

### Attacker capabilities and key custody

Consider offline stolen-file attacks, file+recovery-code theft, malicious/compromised browser client, stolen authorized hardware, compromised LOADED daemon (VERS two-share mask recoverable under full compromise), and historical vault file rollback. Compromise of VMK alone reveals outer state, **not** nested entry DEKs. A hardware-salt output is meaningful only under the precise credential and purpose scope; an attacker with both the scoped PRF material and VERS may unwrap all default-entry DEK slots derived from that same PRF root. An individual DEK still isolates one entry's payload ciphertext.

### OPEN-15 preliminary architecture decision

**Provisional choice for independent review:** permit a stable **vault+credential+purpose-scoped physical PRF output** during one explicitly authorized batch administration operation for ordinary default entries, combined through per-entry, slot-bound KEK contexts. Keep PRF material ephemeral, forbid caching across operations, and expose `blast_radius` fanout. Maximum-isolation / strict entries SHOULD use a distinct entry/slot-scoped PRF request rather than the shared batch root. Device ceremony, salt derivation, test vectors and capabilities remain OPEN-15 until review: some authenticators cannot derive arbitrary many distinct PRF salts in a single presence ceremony. Do not assume a single touch grants 200 independent PRF responses.

### OPEN-18/assurance cross-check

The graph reads only authenticated policy snapshots, distinguishes VMK outer access from DEK unwrapping, requires `INDEPENDENT` recovery codes to be entry-scoped and directly tied to their own DEK, detects shared ancestor bypass, and computes dependent-entry fanout plus residual factors under single-material compromise. The fanout model is static, neither a compromise probability nor a device-PRF proof. Shared JSON conformance cases are used for Python and Rust.

## Review material

- `fixtures/kek_vectors.json`: 9 frozen candidates, including four normal entry modes, two code-only recovery modes, and three commitment-specific cases (empty/long AAD, altered context).
- `kek_vectors.py`, `make_vectors.py`: Python reference and synthetic vector generator.
- `rust/src/kek.rs`: separate Rust interoperability port; Rust test output required.
- `fixtures/routes.json`, `fixtures/conformance.json` plus invalid fixtures: shared OPEN-18 policy cases.
- `route_graph.py`, `rust/src/lib.rs`: read-only route and material-fanout evaluators.
- `test_probes.py`, `rust/tests/conformance.rs`: negative tests, binding tests and parity tests.

## Specific V02-A adversarial review questions

1. Can two differently derived candidate keys plausibly authenticate the same envelope under the proposed slot AEAD/commitment? What exact attacker model and cryptographic proof or accepted construction is required?
2. Does the combiner remain safe with user-chosen weak passwords, independently random recovery codes, repeatable PRFs, correlated or attacker-controlled inputs, and multiple code+factor routes? Are route type/domain labels unambiguous?
3. Which authenticated fields are public pre-load, which are verified only after VMK load, and how are target/slot identity, owner registry and revocation proven before permitting a normal read?
4. How must password KDF parameter bounds, salts, algorithm versions, nonce lifecycle and parser limits be encoded to resist resource exhaustion and silent downgrade?
5. How are matching FIDO2 credential/RP/PRF result, UP/UV and per-operation freshness established? Can representative hardware support entry-salted versus bounded batch-scoped operations?
6. Can password-only recovery restore **both** VMK and the original pre-load seed without the forgotten password? Can either hardware administrative recovery path replace factors without turning VMK access into an Isolated DEK bypass?
7. What changes to VLY2 wire format and migration strategy are required before producing `VERIFIED` slots, including future compatibility with v0.4.5 Option A code prompts?

The reviewer should return reproducible attack examples where possible, independent vector changes, a revised wire/transcript proposal and an explicit scope-limited verdict for **each** of OPEN-01 and OPEN-15; no cross-review status is implied.

**Review versioning note:** Existing `tools/security_probes/fixtures/kek_vectors.json` tests the historical `VAULTY-KEK-v0.4-CANDIDATE` transcript, **not** V02-B's `Vaulty/V02-B/REVIEW-ONLY/slot/v1`. Neither matching suite is an independent cross-implementation known-answer test; the review must explicitly choose/revise one version and generate a new external vector corpus. Never implicitly treat V02-B envelopes as compatible with the VLY2 `Slot` codec.

## V02-C cross-library evidence and security-review submission

The [V02-C conformance report](../../docs/security/V02C-cryptographic-conformance.md) now packages six **synthetic** Python/libsodium versus Rust frozen descriptor/HKDF/HMAC/XChaCha20-Poly1305 vectors and an Argon2id cross-library KAT. The `src/v02/v02c_tests.rs` suite rejects bytewise ciphertext/nonce/tag mutations and altered vault/slot/target/entry, KDF, credential/RP, scope, UP/UV and virtual-provider fields. These are **interoperability and negative-test observations**, NOT an independent cryptographic review or proof of key commitment. The external OPEN-01 reviewer must explicitly analyze multi-key/key-substitution attacks and approve or reject a fixed, final transcript. The [OPEN-15 test matrix](../../docs/security/V02C-cryptographic-conformance.md#4-open-15-real-device-verification-packet-not-executed) is **not executed**; no real token PRF capability/UV/freshness claim is made.

## V02-D pinned external reviewer handoff and residual risks

The [V02-D independent review handoff](../../docs/security/V02D-independent-review-handoff.md) assigns **VD-01..VD-12** to external reviewer, trusted-runtime implementation or later explicit owner choice; it provides an unfilled reviewer verdict template and unexecuted FIDO2 P01–P09 device matrix. The tool `tools/v02_verifier/review_bundle.py` builds/verifies a **source + root and standalone verifier dependency locks + fixture SHA256 inventory pinned to the exact full Git commit**; it compares every allowlisted file with its committed Git blob, rejects modified/untracked inputs, and CI enforces `--locked`, with all OPEN-01/15 and G1–G3 fields marked BLOCKED. The inventory is **not a reviewer signature or supply-chain attestation**. The V02-D Rust synthetic tests additionally demonstrate that arbitrary caller bytes can masquerade as a physical PRF in the current private prototype; this must be resolved by trusted real-device integration and independent OPEN-15 findings, **not** by claiming that descriptors authenticate hardware.

## V02-E AI-assisted findings and candidate hardening (NOT a security verdict)

The [V02-E findings ledger](../../docs/security/V02E-review-findings-and-preapproval-hardening.md) evaluates an AI-assisted scratch review with F-1–F-9 and six probes. The review's phrase *approved with required changes* is **not a named qualified independent OPEN-01 verdict**. V02-E shares structural route checks between VLY2 and experimental descriptors, adds exhaustive policy parity tests, zeroizes fixed HKDF input scratch, rejects metadata-only origin/username/title changes in the normal successor/commit path, and tests a **version-separated, test-only** entry metadata AAD. Existing VLY2 bytes and V02-C frozen KATs are not silently reinterpreted. External reviewers must still assess multi-key commitment, KDF costs, real FIDO2 PRF salt/UV and per-operation freshness, full route ancestry, owner-approved weaker Standard recovery and final wire migration. F-1 recovery consent is a proposed explicit owner decision, not an automatic STRICT_NONE default. No active credential unlock or verified hardware is introduced.

## V02-F owner/expert decision packet (NOT a production protocol)

The [V02-F recovery-assurance and cryptographic policy contract](../../docs/security/V02F-recovery-assurance-and-cryptographic-policy.md) maps F-1/F-2/F-3/F-4/F-6/F-9 into the next review. It preserves the **approved** hardware-vault VMK R1, Isolated S2, separate VMK/VERS/provider-seed/entry-DEK ownership and Option A recovery-code provisioning, while distinguishing **proposed** per-entry informed consent for weaker Standard recovery, numeric Argon2id resource budget selection, NFC→UTF-8 password encoding version and recovery-code scope/domain separation. None of those proposals is a new owner-approved default.

For OPEN-01, request a scoped verdict on: the precise factor-combiner and key-commitment notion, whether cross-route recovery code and password bytes are correctly domain-separated, which KDF floors and pre-auth *aggregate work* constraints are defensible, Unicode input byte-to-KDF interoperability, and strict vNext slot/entry metadata authentication with migration. For OPEN-15, request real enrolled device PRF-salt/scope/UV evidence, physical per-read assertion freshness and shared-root fanout. The two expert reviews can proceed on drafts while V02-G/H add independent vectors; **neither can be replaced by a green CI gate**.

## V02-G test-only versioned slot wire and transcript (NOT authenticated)

[Exact review-only `V3RV` frame/descriptor layout and OPEN-01 questions](../../docs/architecture/v02g-vnext-cryptographic-protocol-review.md) now has a `#[cfg(test)]` Rust strict decoder/encoder in `src/v02/vnext_review.rs`, pinned in the reviewer inventory. It encodes route/target/scope/Argon2/physical-provider context with big-endian lengths and isolated candidate magic. The codec is **not** a key-slot implementation; ciphertext, 32-byte proposed commitment and claimed physical PRF are **opaque, unauthenticated attacker input**. It cannot create READY, unlock VMK/VERS/DEKs or migrate VLY2. The proposed typed-factor HKDF and post-AEAD HMAC remain **an unimplemented and unapproved hypothesis**, not multi-key commitment proof.

Reviewer: challenge target/owner scoping, cross-slot/cross-vault and group/entry ancestry, corruption/failure oracle, production Argon2 budgets and Unicode byte encodings, per-entry DEK-bound origin authenticity, and whether the chosen commitment design should be replaced entirely. V02-H must provide independent byte/crypto vectors after any design revisions. OPEN-15 must separately test actual registered FIDO2 PRF/UP/UV/salt/freshness and batch behavior; neither descriptor flags nor an LLM code review close either gate.

## V02-H pinned wire/conformance and adversarial attack packet (NO external sign-off)

The [V02-H reviewer handoff](../../docs/security/V02H-adversarial-conformance-and-review-submission.md) supplies five committed, independently implemented Python/Rust V3RV **wire/context** vectors; deterministic malformed-input and random-bit mutation suites; a separately authored *reference-only* recovery/ancestor graph and hostile KDF-selection cost model; immutable Git-blob source inventory and H-T01–H-T09 cryptographer questions. The newer vector suite does **not** contain independently implemented vNext authenticated slot ciphertext/committing-key vectors, because V02-G only parses opaque ciphertext and unverified commitment fields. Historical V02-C crypto KATs remain valid solely for the older V02-B experimental schedule. **Do not sign off** OPEN-01 based on parser interoperability or a MAC field's existence.

The external reviewer should provide their name, expertise, exact reviewed commit/file hashes, chosen multi-key commitment definition, factor/domain analysis, hostile work-budget parameters, necessary wire/KDF/Unicode revisions and evidence-backed APPROVE/REJECT/CONDITIONAL verdict. OPEN-15 remains a separate **unexecuted** physical enrolled FIDO2 PRF/UV/UP/salt/batch test. No real credential handling, READY slots or approved vNext wire is enabled.

## Round-two AI-assisted findings accepted for tracking (Nov 8, 2026)

See the [source-commit-bound F-1–F-9 / W1 disposition](../../docs/security/V02H-round-two-review-disposition.md) and [security/acceptance register](../../docs/roadmap/acceptance-register.md). **Qualification 1:** a separately provisioned weaker Standard recovery route is an **owner choice requiring explicit informed consent** before sealing, not automatically a forbidden path or an approved downgrade. **Qualification 2:** V02-B HMAC-before-AEAD and scratch probe P6 are **not** formal multi-key commitment or partitioning-oracle proofs; V3RV's Python/Rust wire vectors are **not** vNext authenticated cryptographic vectors. The AI source review is issue intake, **not** a named independent OPEN-01/15 verdict. The new review must independently assess PRF salt sharing/UV, factor provenance, Argon2 aggregate work, authenticated ancestry, DEK metadata, and final committing vNext seal/open, while real-device OPEN-15 remains separately blocked.

## V02-I scoped PRF inputs, two-key assignment and UV/UP device review (UNEXECUTED)

[V02-I policy and test-only reference](../../docs/security/V02I-fido2-prf-isolation-and-hardware-assurance.md) records F-3/F-4/F-7: proposed entry/slot/credential/purpose salt inputs, WebAuthn PRF `eval.first` versus CTAP `SHA256("WebAuthn PRF" || 0x00 || input)` mapping, distinct UV-required and potentially weaker UP-only profiles, and the **two trusted hardware keys are not automatically assigned to every Isolated entry** rule. Six frozen Python/Rust samples are **public evaluation inputs**, not output secret proof; no FIDO2 assertion/device/PRF/UV test was executed. Ask the OPEN-15 reviewer to run I-P01–I-P09 on real enrolled tokens, verify claimed backend interoperability/UV results, per-entry salt fanout, backup token provisioning and loss/revocation, and return a named version/device-scoped verdict. Ask OPEN-01 separately to assess the final authenticated factor transcript and key commitment; the V02-I SHA256 candidate does not establish it. `OPEN-HW-ASSURANCE`, `OPEN-PRF-SALT`, `OPEN-01`, `OPEN-15`, G1–G3 all remain OPEN/BLOCKED.

## V02-J operator-run native CTAP hardware harness (NOT EXECUTED HERE)

[V02-J local Linux/libfido2 verification foundation](../../docs/security/V02J-isolated-fido2-hardware-verification.md) can **when run with an actual FIDO2 token by an operator**, register distinct public synthetic test credentials and request/verify signed RP/challenge/UP/UV/hmac-secret assertion observations. In this PR/CI **no physical FIDO2 device has been tested**: all negative tests mock CLI results; output-secret comparisons have only best-effort Python wiping and never appear in receipts. It does not assert hardware attestation chain trust, browser WebAuthn PRF/native CTAP equivalence, complete I-P01–I-P09, source-to-backup DEK slot rewrap or READY. External OPEN-15 should use the runbook and pinned commit, test real primary and offline backup devices, independently audit signed negative paths, native/browser parity and PIN/UV/UP freshness, then provide a named scoped verdict. OPEN-01 separately must review authenticated vNext cryptography. No owner `OPEN-HW-ASSURANCE`/`OPEN-PRF-SALT` selection is implied; G1–G3 remain BLOCKED.

## V02-K owner-executed FIDO2 evidence intake (no hardware run in CI)

[V02-K redacted Rust runner](../../docs/security/V02K-physical-fido2-verification-and-evidence.md) provides a clean-clone `cargo run --locked` command for real owner-operated primary and backup test keys via the existing V02-J native libfido2 CLI. The shareable `evidence-v02k.json` includes only observed boolean stable/different-entry tests and a partial I-P01–09 matrix; it deliberately excludes credential IDs, challenges, raw PRF results, device paths, RP and PINs. **Do not infer a qualified independent OPEN-15 verdict** from an owner's local JSON file. The expert must inspect signed assertions, attestation limits, device/firmware/UV freshness, negative tests and browser/native comparison separately. OPEN-01, OPEN-15, owner assurance/salt decisions and G1–G3 remain blocked. No physical hardware has been exercised by repository CI.

**EV-023 operator hardware intake (2026-11-08):** [redacted report, provenance and I-P matrix](../../docs/security/V02K-local-hardware-evidence-received-2026-11-08.md). Owner reports two distinct YubiKey 5 NFC USB-A devices, both firmware 5.7.4, with `primary=OBSERVED` and `backup=OBSERVED` on V02-K merged source `f65615e8`. The claim is **not independently confirmed**; redaction intentionally omits credentials/challenges/PRF values and prevents external signature re-verification. I-P01/02/03/04/06 remain PARTIAL, I-P05/07/08/09 NOT_EXECUTED, OPEN-15 BLOCKED. Independent reviewer must validate hardware/firmware provenance, UV/UP flags, wrong RP/credential/replay/UV negatives and WebAuthn/native same-credential PRF compatibility before any signoff.

## V02-L-A/B native verifier negatives and failure probe (NO LOCAL HARDWARE RESULT YET)

[V02-L-A/B review-only packet](../../docs/security/V02L-native-fido2-negative-and-failure-verification.md) introduces a test-only native libfido2 signed-positive / modified-challenge, RP, authenticator-data, signature and wrong-public-key verifier matrix, plus controlled wrong-credential-on-other-device probes and an absent-HID-path precheck. Synthetic tests check missing UP/UV flags and timeouts. No real signed UV-absent assertion, wrong PIN attempts, actual nonce/replay-cache, trusted registry/revocation, hardware attestation, browser WebAuthn PRF or daemon fail-closed evidence is claimed. Require full local redacted reports, independent signed transcripts, and eventual integrated runtime tests before any OPEN-15 or release acceptance; OPEN-01/G1–G3 remain BLOCKED.

## Review gates to resolve before shipping

1. Formal/independent analysis of the combiner and committing construction, including password-derived input, arbitrary PRF output correlations and domain separation.
2. Reviewed FIDO2 credential PRF salt construction, batch/exposure domain, UV/presence freshness and backup/rotation semantics.
3. Full real AEAD integration: canonical serialization, rejection behavior, nonce uniqueness, wrapped DEK validity and failure timing.
4. Independent implementations and vectors beyond shared fixture matching; known-answer/KAT and mutation/fuzz/integration evidence.
5. Trust binding (authenticated owner registry, no revoked/disabled slot acceptance, old-snapshot rollback disclosure) and safe migration/version negotiation.

**Current disposition:** OPEN-01 remains **BLOCKED — independent cryptographic review pending**. OPEN-15 salt/capability protocol remains **BLOCKED**; fanout design may be provisionally selected after review. OPEN-18 Rust integration remains a design/reference validation until CI and security review are complete.


### Approved S1/S2 constraints added after initial review request

The owner approved **S1 entry-policy-selected provider**: each normal read of
an `ENTRY_*_PHYSICAL` entry must invoke a fresh registered physical FIDO2 PRF
and never use a cached hardware result or virtual fallback. `ENTRY_*_VIRTUAL`
reads use the live software provider even within mixed-policy vaults.

**S2 ISOLATED** entries must require actual cryptographic physical hardware on
*every* complete entry-DEK route, including `INDEPENDENT` code+hardware
recovery, or have `STRICT_NONE`. Isolated code-only DEK recovery is invalid;
outer VMK code-only recovery is not a DEK bypass. Please assess PRF UV mode,
per-entry salt separation, scope/identity binding and whether a device output
can be reused across normal reads without violating S1. This remains a design
requirement, **not independent cryptographic approval**.
