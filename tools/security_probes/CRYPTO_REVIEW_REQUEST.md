# Vaulty OPEN-01 — independent cryptographic review request

**Review status: REQUESTED / NOT COMPLETED.** The reference transcript is an *unapproved candidate*, not production code. Review is requested before enabling it in the vault engine, advertising key commitment, or declaring G1 complete.

## Scope and reviewer deliverables

Please independently assess (a) factor-combining security and authentication-factor assumptions, (b) two-input versus code-only isolation, (c) wrap KEK and commitment key separation, (d) binding of vault, target key, wrapping slot, policy, nonce, AAD and ciphertext, (e) multi-key/key-substitution attacks, (f) online/offline oracles and side channels, (g) FIDO2 PRF salt and fanout (OPEN-15), (h) recovery-code semantics, and (i) exact migration/versioning requirements.

Return a concrete attack analysis, required protocol changes, test-vector corrections and an explicit approval/rejection with threat-model caveats. Matching reference vectors is **not** evidence of cryptographic security.

## Candidate derivation — precise bytes

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

## Review gates to resolve before shipping

1. Formal/independent analysis of the combiner and committing construction, including password-derived input, arbitrary PRF output correlations and domain separation.
2. Reviewed FIDO2 credential PRF salt construction, batch/exposure domain, UV/presence freshness and backup/rotation semantics.
3. Full real AEAD integration: canonical serialization, rejection behavior, nonce uniqueness, wrapped DEK validity and failure timing.
4. Independent implementations and vectors beyond shared fixture matching; known-answer/KAT and mutation/fuzz/integration evidence.
5. Trust binding (authenticated owner registry, no revoked/disabled slot acceptance, old-snapshot rollback disclosure) and safe migration/version negotiation.

**Current disposition:** OPEN-01 remains **BLOCKED — independent cryptographic review pending**. OPEN-15 salt/capability protocol remains **BLOCKED**; fanout design may be provisionally selected after review. OPEN-18 Rust integration remains a design/reference validation until CI and security review are complete.
