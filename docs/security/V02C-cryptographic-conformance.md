# V02-C — Cryptographic Conformance & Security Verification v0

**Disposition:** TEST EVIDENCE / CANDIDATE SECURITY REVIEW, **not approved cryptography**. Date 2026-11-06. Built on merged [V02-B PR #10](https://github.com/BetrayedByEthanol/Pw_Manager/pull/10) (merge `0249bb6`). This milestone increases evidence for the **private, inactive V02-B candidate**, not a finalized protocol or a production vault. **OPEN-01, OPEN-15, G1, G2 and G3 remain BLOCKED** pending independent expert and real-authenticator approval.

**Normative references:** [v0.4.5](../specification/v0.4.5.md), [V02-A review](../architecture/v02a-crypto-keyslot-review.md), [V02-B candidate](../architecture/v02b-keyslot-candidate.md), [crypto review request](../../tools/security_probes/CRYPTO_REVIEW_REQUEST.md), [decisions](../decisions/register.md). Requirements: FR-CRY-01, FR-AUTH-01/02, FR-REC-01/02, FR-SEC-01; D-02/03/07/12/16/18/26/29/30/31/32; S1/S2, R1, Option A, OPEN-02.

## 1. Reproducibility and immutable fixture provenance

- **Tested Rust DUT:** `src/v02/v02b.rs` (unexported, not connected to VLY2).
- **Independent-library reference program:** `tools/v02_verifier/reference_v02c.py` uses Python stdlib `hashlib`/`hmac` for HKDF-SHA256 and candidate commitment HMAC, system **libsodium XChaCha20-Poly1305** through ctypes, and required system **libargon2 Argon2id** through ctypes. The reference is separate from Rust `hkdf`/`hmac`/`chacha20poly1305`/`argon2` implementations, **but was written in this project and has not been externally reviewed**. It is cross-library interoperability evidence, **not independent security approval**.
- **Frozen data:** `tools/v02_verifier/fixtures/v02c_kats.txt` contains **six** synthetic, deterministic cases with descriptor SHA256, wrap KEK, MAC key, XChaCha20-Poly1305 ciphertext+tag, and candidate HMAC. Never use deterministic fixture nonces for actual sealing. A separate Argon2id v0x13 KAT covers 8 MiB, 2 passes, one lane, fixed 16-byte salt and fake test password.
- **Rust conformance:** `src/v02/v02c_tests.rs` rebuilds the descriptor *from explicit typed fields*, derives both keys, encrypts under the **fixture-only** nonce, and compares **each** frozen output; it then decrypts and rejects modified factor inputs. A Rust round-trip alone is not a sufficient interoperability test.

**Replay commands:**
```sh
# Independent-library reference reproduction (Python 3 + system libsodium
# and libargon2, both required; CI installs system shared libraries):
python3 tools/v02_verifier/reference_v02c.py --verify

# Standalone exact-module CI harness:
cargo check --manifest-path tools/v02_verifier/Cargo.toml --all-targets
cargo test  --manifest-path tools/v02_verifier/Cargo.toml --all-targets

# Root application/test build (including inert executable checks):
cargo check --locked --all-targets
cargo test  --locked --all-targets
```

**Versioning:** Reference covers exactly `Vaulty/V02-B/REVIEW-ONLY/slot/v1`; it is **not** the historical `VAULTY-KEK-v0.4-CANDIDATE` probe transcript, does not freeze the VLY2 wire format, and does not establish commitment under adversarial multi-key attacks. Any expert-required change invalidates and regenerates these fixtures under a *new explicit version*, never silently changes their meaning.

## 2. Adversarial test matrix (actual vs pending)

| ID | Property or attack | Reproducible evidence in this PR | Remaining evidence |
| --- | --- | --- | --- |
| VC-01 | Six route-distinct deterministic KATs | Frozen SHA256/HKDF/HMAC/XChaCha reference outputs compared in Rust, plus one Argon2id KAT | Third-party authored/checked interoperable vectors and production transcript approval |
| VC-02 | Wrong factor/recipe or injected second component | Per-case single/two-factor rejection; fail on altered first/second input | Formal factor-combiner/entropy analysis, password/virtual PRF dependence |
| VC-03 | Ciphertext/nonce/candidate commitment tamper | Deterministic mutation of **every byte** of a 48-byte ciphertext, 24-byte nonce and 32-byte tag; truncated envelope | Review of oracle/timing/error behavior under online/offline chosen-key attacks |
| VC-04 | Slot, vault, target, policy and KDF substitution | Vault/slot UUID, target, vault mode, factor route, protocol version, Argon2 salt/memory/passes/lanes, missing parameters rejected | Canonical serialized schema, key commitment proof, key/nonce misuse threat analysis |
| VC-05 | Credential/RP/salt/UV and physical scope | Mutation of credential ID, RP digest, PRF salt, scope, UP, UV; all reject | **Real assertion verification and token PRF**, no software proof of per-read freshness |
| VC-06 | Entry tier, recovery policy, virtual provider context | Entry ID/tier/recovery/provider UUID/purpose substitution rejected; cross-envelope nonce/tag splice rejected | Effective route graph, owner registry/revocation and ancestor checks in trusted daemon |
| VC-07 | Hostile KDF parameter bounds | Reject forbidden memory, lanes, passes, all-zero salt and overlong password before attempting expensive hash | Resource budgets on platforms, Argon2 calibration, weak password/offline-guess assessment |
| VC-08 | R1/Isolated/STRICT_NONE/code routes | Existing V02-B tests: no code-only hardware VMK, Isolated fresh physical *policy*, optional code+physical Isolated recovery even when VMK is password-only; strict-none disables recovery | Authentic hardware operations, real provisioning and prompt/owner approval (Option A) |
| VC-09 | Bootstrap code/password independence | Existing synthetic seed recovery uses password-only seed bootstrap and independent code-only seed slot | Actual seed persistence/rewrap, recovery user journey, replay/rollback tests |
| VC-10 | Fail-closed default runtime | Source remains private; active VLY2 slot representation is unchanged; existing CI asserts inert executable | V03/V04/V06/V07 runtime authorization and V09 release evidence |

**Specific limits:** These are finite deterministic mutations, **not coverage-guided fuzzing** and not a proof that there is no substitution attack. Hardware context in a descriptor is **attacker-provided metadata** until an enrolled credential and a fresh signed assertion/PRF result are validated. The current prototype **does not enforce** a physical security property on a real device. `SlotState::Verified` remains a serialized label, not a proof of factor availability.

## 3. OPEN-01 review submission and required verdict

A qualified independent cryptographic reviewer must receive the **source and exact frozen vectors** and analyze at least:
1. Whether the factor-combiner is secure with a user-chosen password, correlated virtual-provider material, repeatable and possibly exposed PRF output, recovered code paths, and multiple slots using related roots.
2. Whether the draft separate HMAC actually achieves the desired **multi-user, multi-key key commitment** under a clearly specified attacker model. Consider distinct keys verifying the same ciphertext, tag verification order, chosen-key and ciphertext-swapping attacks, and offline key-guessing or timing oracles. **Do not claim XChaCha20-Poly1305 is inherently committing.**
3. Exact canonical framing, key order, salts, KDF parameter floors/caps and authenticated descriptor encoding; handling of missing/unknown fields and future transcript revisions. Current `Descriptor` is a Rust struct, **not** an approved portable wire serializer.
4. Whether a captured VMK can ever yield VERS or independent entry DEKs (it must not); whether all alternate ancestry and recovery routes retain actual factors.
5. Reviewed deployment parameters, zeroization of raw password and PRF handling, resource exhaustion and errors; distinct key labels and reuse/fanout.
6. Return an explicit **APPROVED / APPROVED WITH CONDITIONS / REJECTED**, scoped to version and threat model, with independent KAT and corrected implementation changes. **No reviewer receipt exists yet.**

**OPEN-01 status after V02-C: BLOCKED.** Internal tests and Codex review cannot approve the protocol.

## 4. OPEN-15 real-device verification packet (NOT executed)

For each representative physical authenticator and credential, record firmware/model (without personal identifiers), FIDO2 PRF/hmac-secret capability, configured UP/UV/PIN mode, credential/RP binding, registration/revocation status, and these **measured** cases:

| Case | Required observation |
| --- | --- |
| Two same-scope enrolled derivations | Both produce the same 32-byte PRF output, with authenticated assertion/credential/RP and required UP/UV, before the slot becomes eligible |
| Fresh physical normal entry read | Every read causes a new *trusted* device operation; prior cached/replayed PRF material alone is rejected |
| PIN/UV mismatch or unsupported mode | No UV-to-UP or software fallback; fail closed with no key release |
| Wrong credential, RP, PRF salt/scope or assertion | Rejected, no fallback and no conversion to a virtual route |
| Unplug/timeout/denied user presence | Abort operation, drop transient PRF/KEK/DEK and keep prior valid slot |
| Single vs batched salts | Measure supported salt counts/touches; do not assume many independent entry PRFs from a single touch |
| Shared Standard vs entry-isolated root | Enumerate accessible DEKs after compromise of VERS + one scoped output; record and surface fanout |
| Lost device and code-dependent re-enrollment | Code + existing password recovers VMK metadata but not lost PRFs/Isolated DEKs; new token PRF + code required for affected slots |
| Forgotten password with registered device | Code + currently registered physical proof recovers VMK admin authority; no code-only hardware-vault route |

**OPEN-15 status after V02-C: BLOCKED.** No hardware was connected or measured by this PR. D-30 Standard batching remains PROVISIONAL; do not hide shared-root compromise blast radius.

## 5. Gate/accountability and next deliverables

V02-C is **code/CI conformance verification only**. It is mergeable as a test-hardening work package after ordinary review/CI, **without** marking OPEN-01/15 resolved. G1 cryptography, G2 physical authenticator and G3 recovery/daemon are **BLOCKED**. These tests do not activate real-credential unlock.

Next:
1. Submit the exact V02-B/V02-C source, fixture generator, negative suite and this packet for **independent OPEN-01 review**; document the named reviewer, date, approved version and conditions, or explicit rejection and necessary revision.
2. Perform **real representative FIDO2 device trials** and independent OPEN-15 review, recording capability, UV/presence, credential/RP/salt and scope/batching behavior.
3. Only after approvals, implement a **new versioned** fully authenticated slot serialization and trusted runtime factor source with explicit migration and Option A coverage, not a retrofit of existing pending VLY2 bytes.
4. Complete fuzz/property tests, S4 protected head and race-free storage, memory-lifetime analysis, recovery restore/rotation and adversarial daemon/IPC tests before G1–G4 certification.

**Security claim boundary:** cross-library KATs and negative mutation coverage increase confidence in *consistency* of a candidate; they do **not** prove its cryptographic security, verify hardware provenance, or establish production readiness.
