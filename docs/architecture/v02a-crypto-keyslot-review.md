# V02-A — Cryptographic Protocol & Key-Slot Design Review

**Disposition:** REVIEW CANDIDATE / NOT APPROVED. **Date:** 2026-11-06. This is a threat-oriented specification and reviewer handoff, **not** an independent cryptographic review, a normative wire-format freeze, or an implementation of usable key wrapping. V02-A may merge as documentation while **OPEN-01 and OPEN-15 remain BLOCKED**. Do not store real credentials or enable the disabled executable.

**Authority:** [canonical v0.4.5 specification](../specification/v0.4.5.md) §§2–4, 7–9; [architecture](v0.4.5.md); [decisions](../decisions/register.md) D-02/03/07/12/16/18/26/29/30/31/32; [OPEN-01 reference request](../../tools/security_probes/CRYPTO_REVIEW_REQUEST.md); [V02 candidate codec](v02-format-candidate.md). Normative approved **product policies** below are distinct from proposed **protocol mechanisms** and unapproved external security conclusions.

## 1. Findings against merged V02 (PR #8)

| ID | Current evidence | Gating gap / consequence |
| --- | --- | --- |
| A-01 | `src/v02/model.rs` has independently random zeroizing VMK, VERS, DEK types. `mod.rs` has independent outer/entry AEAD. | No approved password/physical/virtual/recovery derived KEK, commitment validation, or sealed-slot unwrap. |
| A-02 | `Slot` encodes target, target UUID, factor enum, state, 24-byte nonce and opaque ciphertext; `SealedUnverified/Verified` assume a 48-byte 32-byte-key envelope. | **Insufficient for final protocol**: no explicit algorithm/transcript version, KDF bounds and salt, scoped PRF identity/salt/UP/UV requirements, root/fanout reference, or commitment tag. Widening slot schema requires **explicit new wire version / authorized migration**; never silently reinterpret VLY2. |
| A-03 | Public header provides separately encoded bootstrap and VMK descriptors. | Descriptors are *untrusted hints before VMK authentication*, not proof of owner policy, token registration, verified enrollment or real factor availability. Slot AEAD and authenticated post-load registry must corroborate them. |
| A-04 | Typed route validation rejects code-only hardware-vault VMK and software-only Isolated DEK slots. | Structural checks do **not** evaluate all effective complete normal/recovery routes through shared ancestors, descendants, disabled/revoked state or virtual substitutions. Reference route checker is not a runtime oracle. |
| A-05 | Codec binds full header to outer AEAD and entry ID, revision and policy to inner AEAD. | Slot KEK, envelope AAD, key commitment and key-substitution defenses are not defined or tested against actual factor-derived keys. |
| A-06 | V02 tests use `Slot::pending` and synthetic random keys. | No real hardware assertion, recovery ceremony, password-derived normal VMK slot, cross-implementation sealed-slot vectors or fail-closed runtime verifier exists. A serialized `VERIFIED` enum is not authorization evidence. |

**Review consequence:** Do not activate `SlotState::Verified` based on decoding or the current 48-byte envelope shape. Freeze protocol parameters only after external review and a versioned interoperability test corpus. V02's existing bytes are a **candidate**, not a production compatibility commitment.

## 2. Key custody and dependency graph (approved policy)

```text
master password --Argon2id--> password input ─┐
                                               + [physical FIDO2 PRF, or virtual provider]
authorized recovery factors ------------------┤
                                               v
                          separately scoped, independently AEAD-sealed VMK slots
                                               v
                        VMK (only OPEN→LOADED / WRITE_OPERATION)
                                               │
                          VMK-authenticated metadata/body only
                                               │
            transient VMK wiped; NOT a VERS or entry-DEK parent

random independent VERS → masked shares while LOADED ─┐
fresh entry password (custom path) --------------------┤ primary entry input
fresh hardware PRF OR LOADED virtual PRF ---------------- second input
                                                       ↓
                                         scoped normal entry KEK
                                                       ↓
                                            wrapped random DEK
                                                       ↓
                                          entry payload (inner AEAD)

separate preauthorized recovery slots → VMK / VERS / provider seed / DEK
```

- VMK **never derives VERS, entry KEKs, or DEKs**. A recovered VMK reveals authenticated outer metadata; it does not grant entry-secret access.
- Password-only `VaultPasswordVirtual` is **software-only assurance** even though the derivation passes two bytestrings. The virtual adapter adds no independent possession factor. Hardware-backed VMK routes have no code-only alternative and are described by their **weakest** effective route.
- All normal Isolated DEK paths require fresh registered physical hardware for every read. Recovery, if any, must also have physical hardware; `STRICT_NONE` means **no recovery path**, not permission for software normal access.
- Hardware PRF output is repeatable for a fixed salt; a fresh ceremony is an **authorization/freshness event**, not a guarantee the output cannot be copied. Shared Standard PRF + VERS compromise fanout must be reported.

## 3. Candidate route and envelope contract — proposed, NOT approved

A prospective explicit `protocol_version` and `route_kind` MUST distinguish at least:

| Target/ceremony | Allowed factor recipe | Context/lifetime |
| --- | --- | --- |
| VMK normal, password-only | master-password KDF + password-bootstrapped virtual adapter | Password-only assurance, OPEN→LOADED/WRITE_OPERATION only |
| VMK normal, hardware | master-password KDF + fresh registered physical PRF | Fresh hardware operation, no virtual fallback |
| VMK recovery, password-only | recovery code alone | Authenticated **administrative** reset, not entry bypass |
| VMK recovery, hardware: replace token | recovery code + existing master-password KDF | No missing token PRF reconstruction; metadata may be visible |
| VMK recovery, hardware: reset password | recovery code + fresh registered hardware PRF | Already-registered credential and pinned UP/UV; no code-only fallback |
| Provider seed pre-load, password-only | master-password bootstrap and separate code-only recovery bootstrap | Same random seed, separately sealed; available before VMK outer decrypt |
| Provider seed in hardware-backed mixed vault | only from reviewed valid policy routes; may be unwrapped after VMK if not needed for VMK authorization | Do not introduce software-only VMK bootstrap route or claim hardware-backed assurance from a virtual provider |
| VERS / DEK normal | default VERS or custom entry password + **entry-selected** provider | VERS reconstructed transiently; physical read always fresh |
| VERS / DEK recovery | separately provisioned, policy-valid code + required password/hardware, or explicit approved shared ancestor | Never implied by VMK recovery; for Isolated, physical hardware on every complete route |

**Candidate envelope fields to review before implementation:** explicit format/algorithm version; `vault_id`, `slot_id`, `target_kind` and `target_id` (nil only where defined); operation purpose/route kind; exact factor recipe and assurance tier; random AEAD nonce; canonical KDF identifier, work parameters and random salt where applicable; provider type, credential identifier or authenticated reference, RP ID, PRF salt derivation/scope and pinned UP/UV; root/ancestor/fanout reference where shared; wrapped-key length and AEAD ciphertext; **reviewed** key-binding/commitment material. Public-header visibility of all these fields is a separate privacy decision. Do not duplicate secret provider material in the header.

**Proposed cryptographic *review* baseline, not deployment parameters:**
1. Run a resource-capped, per-password-salt Argon2id only for actual password components; record authenticated parameter bytes and enforce hard lower/upper bounds before expensive work. No hard-coded production cost is selected by this document; calibrate and review per platform.
2. For each distinct route kind, use unambiguous length-delimited, domain/version-separated HKDF-SHA-256 **Extract then Expand** inputs and distinct labels for wrap KEK versus any commitment key. Bind vault/target/slot/route/provider context and algorithm identities, not just the count of factors. Reject unrecognized or mixed factor order, absent components or downgraded settings.
3. XChaCha20-Poly1305 is the current candidate slot AEAD; authenticate the exact canonical descriptor (including policy, scope, KDF/PRF parameters, nonce and all fields necessary to interpret the ciphertext) with slot-specific AAD. Reject wrong target, swapped slot, altered context and partial/trailing frames *before releasing any key*.
4. `tools/security_probes/CRYPTO_REVIEW_REQUEST.md` contains an **unapproved** draft HKDF/HMAC commitment. A separate MAC over AAD/nonce/ciphertext **does not by itself establish a proved committing-AEAD construction**. Obtain a specific expert verdict on multi-key/key-substitution resistance, timing/oracles, verification order and tag handling; either revise and revector the scheme or reject it. Never assert the V02 AEAD is key-committing.
5. Treat public descriptors as attacker-controlled until factor-derived slot cryptography succeeds and then the authenticated outer body/owner registry is compared. No trust in client-requested `Verified`, `READY`, factor ID, revoked flag or provider class.

**Canonical transcript questions for reviewer:** exact binary framing and type domains; password Argon2 parameters and pepper/secret assumptions; whether key-commitment is required separately for outer, bootstrap and DEK slots; how wrong passwords/PRFs and corrupted ciphertext produce safe indistinguishable failures; why each descriptor byte and key-length are authenticated; serialization/rotation versioning and cost bounds; feasibility of a two-input KDF if PRF outputs are repeated/correlated.

## 4. OPEN-02 bootstrap and Option A dependency/coverage checks

**Password-only opening:** public normal seed-bootstrap envelope → password KDF → recover original virtual seed → derive current virtual output → unwrap normal VMK slot → authenticate outer body → verify the seed/VMK policy and owner registry. Do not place the **only** copy of this seed in the VMK-encrypted body. Code-only administrative recovery must independently unwrap *the same seed*, in addition to the VMK, if the recovery operation needs virtual-entry access. Recovery creates a new password-derived bootstrap envelope without regenerating the seed.

**Hardware opening:** password + fresh hardware PRF unwraps VMK. An Isolated entry still requires its own valid physical normal DEK route after load. A virtual provider used for mixed-mode virtual entries remains a software adapter; its seed path must not turn an otherwise hardware-only normal VMK into a software-only route.

**Recovery code is a write/provisioning prerequisite, not a read prerequisite:** mint a 256-bit random code with confirmation/checksum in a trusted UI, never a passphrase. **Option A** requires the actual relevant code every time a new/replacement code-dependent VMK/VERS/seed/DEK envelope is sealed, plus all other slot factors. Inherit already verified shared recovery roots without reprompting *only when no new code-dependent envelope is made*. Code changes/VMK rotation/new token enrollment must enumerate and rewrap dependent slots. No speculative recovery slot or delayed background success.

**Activation transaction (fail closed):** inventory normal, administrative and entry recovery coverage → acquire factors and two matching hardware PRFs where required → seal proposed slots into isolated staged candidate → verify key identity/unwrapping and complete effective routes with the actual registered factors → owner-approved, bounded atomic commit and authenticated reopen → mark READY only with witnessed evidence. Until then use PENDING / SEALED_UNVERIFIED / MISSING / DEGRADED or STRICT_NONE, and preserve old valid slots. If replacing a lost factor cannot re-provision every dependent DEK, explicitly surface those entries as unrecoverable/degraded; VMK access does not conjure the missing DEKs.

**Potential circularity hazards to test:** seed required to unwrap VMK yet stored only under VMK; provider seed recovery requiring a reset password that has not yet been established; old token PRF needed to seal new-device code slots when old token is lost; VMK-only administrative route accidentally unwrapping DEKs; attempting to promote `Verified` from a serialized byte. None is acceptable.

## 5. OPEN-15 physical adapter and blast-radius review

Before permitting a hardware slot, the authenticated registry must pin credential identity, RP ID, accepted authenticator capabilities, PRF salt and derivation scope, UP/UV mode, revocation status and explicit operation purpose. Enrollment requires **two identical outputs** for the same salt, credential and required UV mode, each from a properly authenticated ceremony; no weaker PIN/UV fallback. Every physical entry read requires **new trusted user-presence/verification evidence** bound to that operation even if the PRF output for the same salt repeats. No cached PRF, prior browser assertion, software adapter or fake touch may meet this gate. Evaluate how to prove assertion and PRF output belong to the same authorized credential/ceremony rather than trusting an unbound PRF response.

**Two reviewable salt choices (NOT a silent implementation choice):**
- **Scoped shared Standard root (D-30 provisional):** vault + credential + purpose scoped; one ceremony may facilitate a bounded batch rewrap, but compromised scoped PRF output plus VERS exposes all default entries sharing it. Must show fanout and limit bytes/lifetime.
- **Entry/slot-isolated root:** entry + slot + purpose context in device PRF salt; narrower compromise scope, potentially one ceremony per salt. Required capability/performance evaluation; never assume bulk independent PRFs from one touch.

Record verified device support (PRF extension/hmac-secret behavior; credential and UV capabilities; multi-salt practical limits), test mismatched RP/credential/salt/UV, PIN state change, timeout, removal, disabled device, duplicated assertion and mixed virtual/physical routes. **OPEN-15 remains BLOCKED** until independent review and hardware-backed negative evidence. Manufacturer claims or attestation presence alone are not a security certificate.

## 6. Threat-model decisions and concrete negative evidence

| Threat / potential failure | Review requirement | Implementation test that will be needed |
| --- | --- | --- |
| Stolen file + offline guesses of weak master password | Real password-only/virtual mode is **not 2FA**; capped Argon2 and metadata confidentiality, honest UI classification | Known password/salt KAT, malicious parameter extremes, offline dictionary cost assessment |
| Swap one sealed slot/target/credential/policy for another | Exact descriptor + key commitment; reject substitution before key release | Mutate every AAD field, sibling vault/target/slot, ciphertext and commitment; wrong-key multi-key suite |
| Self-reported VERIFIED or revived/revoked credential | Independently authenticate complete effective route against owner registry after load | Serialized VERIFIED, disabled, stale owner registry and unauthorized provider rejection |
| Lost physical device; recovery code + password | VMK metadata recovery **only**, no missing PRF/entry DEK leap | Replacement-token ceremony, verify each rebuilt slot and same key, isolated entry still hardware |
| Forgot password; code + registered hardware | VMK admin route; new password/code slots require Option A | Re-enrollment, password-reset and missing-factor abort preserving old state |
| Wrong/missing UV, PRF scope or stale assertion | Pinned authenticated mode, fresh per-read device proof, fail closed | Real-device UV/PIN perturbations, unplug, wrong RP/credential, replay, PRF mismatch |
| Full LOADED memory compromise | Masked VERS and software provider are **friction only**; no security claim against full memory read | Key-lifetime/zeroization tracing, no VMK after load and no PRF cache between operations |
| Stale/rolled-back whole file | AEAD authenticates contents, **not freshness**; local last-seen-head is best-effort | Encrypted old-head restore; separate local record warning, explicit reconciliation |
| Key fanout through shared default Standard material | Explicit ancestry-aware metadata vs DEK route reporting | Capture VERS + one scoped PRF; enumerate reachable entry DEKs and residual hardware factors |

## 7. Exit criteria, reviewer artifact and decision ownership

**V02-A document-only completion:** code/spec discrepancy register; precise candidate slot/transcript interface; R1/Option A state transition matrix; threat matrix and negative-test plan; reference probe links; CI/docs review; explicit unresolved decisions. This PR **must not claim** an external independent review took place.

**OPEN-01 acceptance requires:** named independent reviewer, versioned signed/recorded findings and caveats, formal reasoning about combiner and multi-key commitment, revised exact bytes and production KDF limits, independently produced interoperability/negative vectors, real AEAD sealed-slot integration, and a review-to-implementation change mapping. Outcomes must be explicitly APPROVED, APPROVED WITH CONDITIONS, or REJECTED; silence or synthetic fixture parity is not approval.

**OPEN-15 acceptance requires:** independent device/security review, exact salts/credential/UV/UP/RP transcript, hardware capability matrix including failures, signed-off freshness and batching/fanout semantics and real representative token negative tests. D-30 shared batching remains provisional until this gate.

**Implement-after-review sequence:**
1. **V02-B:** versioned production slot format, authenticated descriptors and reviewed key wrapping/commitment; deterministic KAT, substitution and parser fuzz tests; retain legacy VLY2 only as non-active candidate or explicit migration source.
2. **V03/V06:** trusted session/physical and virtual adapters, owner registry, independent per-read hardware evidence and scoped secret lifetime.
3. **V04:** Option A recovery provisioning and repair/rotation; independently verify VMK/seed/VERS/DEK access graph, backups and migration.
4. **V05/V07/V09:** complete source-native entry policy, authorization, external crypto and restore evidence before any production use.

**Gate status after V02-A:** G1 BLOCKED (OPEN-01), G2 BLOCKED (OPEN-15), G3 BLOCKED (recovery/authorization); V02 remains merged *candidate foundation*. No user decision to weaken R1/S2 or to suppress future reviews is implied.
