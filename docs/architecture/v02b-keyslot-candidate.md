# V02-B — Versioned Key-Slot Protocol and Factor Wrapping Candidate v0

**Status: EXPERIMENTAL IMPLEMENTATION / NOT APPROVED / NOT ACTIVATED (2026-11-06).** Built after merged [V02-A review PR #9](https://github.com/BetrayedByEthanol/Pw_Manager/pull/9) and merged V02 [PR #8](https://github.com/BetrayedByEthanol/Pw_Manager/pull/8). This milestone cannot honestly be called **cryptographic protocol finalization** while OPEN-01 and OPEN-15 remain unapproved. The package implements a bounded, *internal-only* review prototype and tests; production VLY2 wire schema, actual hardware authorization, recovery and runtime unlock remain deliberately disabled.

**Normative policy:** [v0.4.5 spec](../specification/v0.4.5.md) §§2–4, [V02-A discrepancy/reviewer packet](v02a-crypto-keyslot-review.md), [decisions D-02/03/07/12/16/18/26/29/30/31/32](../decisions/register.md), and [OPEN-01/15 review request](../../tools/security_probes/CRYPTO_REVIEW_REQUEST.md).

## 1. Source and isolation

- `src/v02/v02b.rs`: private Rust module compiled as part of `src/v02/mod.rs`, **not exported as a public API**, not reachable from CLI, daemon or native messaging host. No code in V02 calls this candidate during vault open/read/write. No key-slot transitions to VERIFIED, no new file format magic, no automatic migration.
- `src/v02/model.rs` and `codec.rs` continue to accept **pending VLY2 descriptors only**; their existing 48-byte sealed-slot shape is not declared compatible with this candidate. A future production version requires a new explicit wire revision, strict decoder, and authorized re-encryption/migration. A VLY2 file must never be silently interpreted as V02-B.
- `src/v02/v02b.rs` owns isolated test vectors and negative tests. Source uses existing crate dependencies (`argon2`, `hkdf`, `sha2`, `hmac`, `chacha20poly1305`, `zeroize`, OS RNG). Do **not** present matching self-generated test vectors as independent KATs.

## 2. Candidate cryptographic transcript (NOT final)

The `Descriptor` contains:
`protocol_version=1` (V02-B **candidate descriptor version**, **not VLY2 wire version**);
nonzero vault and slot UUID; target type and target UUID (nonzero only for EntryDek); vault mode; factor route; optional bound entry mode/tier/recovery policy; optional password Argon2id parameters (random 16-byte salt, explicit memory/passes/lanes); one of None, Virtual (provider UUID and purpose digest), or Physical (credential identifier, RP digest, PRF salt, scope, pinned UP/UV).

The descriptor is validated *before* cryptographic work. It is deterministically framed in a dedicated, versioned and domain-separated `transcript` with explicit lengths for variable credential bytes, fixed-width integral fields, strict absence markers and maximum transcript length of 1 KiB. The protocol's **API struct is not yet a portable wire serializer**; a reviewer-approved canonical byte format with unknown-field behavior is still needed.

**Candidate key derivation:**
```text
D        = candidate canonical descriptor transcript
IKM      = DOMAIN || [one | two] || component_1[32] || optional component_2[32]
HKDF-salt= SHA256(D)
PRK      = HKDF-Extract-SHA256(HKDF-salt, IKM)
KEK      = HKDF-Expand-SHA256(PRK, "Vaulty/V02-B/review-only/wrap-key", 32)
MAC-KEY  = HKDF-Expand-SHA256(PRK, "Vaulty/V02-B/review-only/commitment-key", 32)
AAD      = D
nonce    = OS-CSPRNG 24 bytes per new seal
cipher   = XChaCha20-Poly1305.encrypt(KEK, nonce, AAD, scoped 32-byte key)
MAC      = HMAC-SHA256(MAC-KEY,
           DOMAIN || "/mac-v1" || u32be(len(D)) || D ||
           nonce || u32be(len(cipher)) || cipher)
```

Decrypt checks version/route/descriptor bounds, verifies the HMAC using the MAC library's comparison before AEAD decrypt, then returns only 32-byte zeroizing key material. The HMAC is a **draft factor/slot binding**, **not an independently evaluated committing-AEAD security guarantee**. In particular the review must assess chosen-key/multi-key substitution, offline oracles, factor entropy/correlation, timing, KDF and version downgrade. Never report the construction as cryptographically approved.

**Argon2id component pre-KDF:** `password_component` uses Argon2id version 0x13 with explicit 16-byte salt and bounded params (test/review range: 8–256 MiB, 2–8 passes, 1–4 lanes), returning a zeroizing 32-byte component. These are **bounds for a candidate harness, not calibrated production minimum/cost defaults**; the caller is responsible for clearing raw password input. 256 MiB memory usage must remain resource-gated by a trusted daemon before future integration. No password is handled by the shipping app.

## 3. Factor recipes, bootstrap and limits

| Slot route | Candidate components | Status/constraints |
| --- | --- | --- |
| Password-only normal VMK or VERS | Argon2id master component + software virtual PRF component | Two protocol inputs, but software-only assurance |
| Hardware normal VMK or VERS | Argon2id master component + physical PRF component | Pinned credential/RP/salt/UP/UV descriptor; **no actual proof of fresh physical operation in this module** |
| Default/custom entry normal | VERS or Argon2id entry password + selected virtual/physical PRF | Entry mode bound; Isolated hardware-only; no active entry read |
| Password-only code-only recovery | 256-bit code component alone | No fake second factor; never allowed for hardware-vault VMK or other hardware-vault protected keys |
| Hardware administrative code + password | Recovery code + Argon2id current master component | Replaces token; VMK route does not unwrap missing-token DEKs |
| Hardware administrative code + physical | Recovery code + registered physical PRF | Resets password; no virtual substitute |
| Password-only virtual seed pre-load bootstrap | Master-password Argon2id component **alone**, *without the seed-derived virtual PRF*; independent recovery code-only seed slot | Avoid circular dependency: the same random seed may be recovered under either route; no seed regeneration |
| Hardware-backed provider seed | Actual two-factor normal or recovery recipe, not code-only | No software-only hardware-vault VMK bootstrap bypass |

**Important intentionally missing proof:** `Components` holds arbitrary 32-byte values supplied by *synthetic tests*. It does **not** prove that an actual recovery code was presented, that Argon2id corresponds to an approved password prompt, or that a FIDO2 assertion matches an enrolled credential. That proof belongs to trusted V03/V04/V06 ownership checks. Consequently an internal candidate round-trip is **not a real authentication test**.

The private validator fails closed for code-only hardware-vault routes, route/provider mismatch, unexpected password KDF metadata, strict-none recovery slots, Isolated software-only normal/recovery routes, unscoped Isolated physical PRF and absent credential/RP/salt/UP evidence in a descriptor. `uv_required` is authenticated as policy metadata, but whether UV must universally be true is **OPEN-15**; false must never arise via fallback after enrollment.

## 4. Independent review and security caveats

| Evidence available now | Evidence still required to activate |
| --- | --- |
| Deterministic Argon2id component; bounded parameter rejection | Independent KDF cost/entropy review, benchmark calibration, hostile input/DoS tests |
| Two-input normal and code-only candidate round trips | Independently generated portable known-answer vectors, factor-combiner analysis |
| Nonce freshness and wrong-input/tag failure | Multi-user/multi-key substitution security verdict, error/timing/oracle analysis |
| Candidate descriptor binding to vault, target, slot, factor, entry policy and credential/salt | Final canonical wire serializer, strict reader, AAD/slot commitment review and version/migration rules |
| Isolated/STRICT_NONE and hardware-vault route negative tests | Full effective route graph and runtime owner registry/revocation; real hardware PRF assertions per read |
| Original random virtual seed recoverable under two separately wrapped candidate paths | Trusted code prompt on **every new code-dependent slot** (Option A), full recovery coverage, atomic slot rotation and reopen; no production bootstrap active |
| Internal-only module, disabled CLI/native host | Independent OPEN-01/15 approval, external hardware checks and G1–G4 gates |

**Blast radius:** a shared Standard hardware PRF output combined with VERS is a shared ancestor to all affected default entries; the candidate derives slot-specific KEKs but does **not** eliminate compromise of the common ingredients. D-30 batching remains provisional. Isolated normal read still requires physical hardware *every operation*, not merely a physical-flavored descriptor.

**Rollback and migration:** This PR does not modify ciphertext file format, backup/restore or the existing S4 storage adapter. Any future schema change must use a separate, authorized migration and verify the target/slot root identities and recovery accessibility. Stale/rolled-back authenticated files remain a distinct S4 issue.

## 5. Review acceptance and next work

- **V02-B candidate PR acceptance:** code isolated from runtime, tests pass on supported CI, static scope and negative-case review, existing V02 tests still pass, no silent VLY2 compatibility claim, roadmap and evidence registers updated, no false security certification.
- **OPEN-01 review gate:** independent reviewer accepts/revises exact factor derivation, cryptographic commitment, public descriptor privacy, password costs, full multi-key misuse threat model and canonical independent vectors. Current request [here](../../tools/security_probes/CRYPTO_REVIEW_REQUEST.md).
- **OPEN-15 review gate:** real device capability and credential/RP/UP/UV/PRF-salt/freshness review and recorded per-operation hardware evidence, explicit D-30 batch/fanout outcome.
- **After approval (separate PR):** decide new versioned wire format, implement strict serializing/deserializing, trusted factor sources and route-graph checks, code-dependent recovery provisioning and atomic key-slot lifecycle; only then consider activating cryptography.

**Release gates:** G1 BLOCKED (OPEN-01, final wire and integration), G2 BLOCKED (OPEN-15, trusted authenticators), G3 BLOCKED (recovery and daemon authorization), G4 BLOCKED (full product verification). V02-B is not a finished password manager.
