# V02-G — Cryptographic Protocol vNext Review Candidate

**Status:** **REVIEW-ONLY / UNAPPROVED / NO PRODUCTION ACTIVATION** (2026-11-07). Proposed after [V02-F policy packet](../security/V02F-recovery-assurance-and-cryptographic-policy.md), merged [PR #14](https://github.com/BetrayedByEthanol/Pw_Manager/pull/14) at `5b6b554518a81c5b1a831bead88f2997a4933cf5`. Canonical owner-approved behavior remains [v0.4.5](../specification/v0.4.5.md). Source-of-truth for this **prototype** wire is [`src/v02/vnext_review.rs`](../../src/v02/vnext_review.rs), compiled **only under `#[cfg(test)]`**. It **parses and reproduces an opaque untrusted envelope**; it does **not** derive wrapping keys, authenticate HMAC/AEAD, check a device, perform Unicode normalization, create READY slots or migrate vaults.

**All OPEN-01, OPEN-15 and G1–G3 remain BLOCKED.** Final suite, cost/encoding policy, commitment primitive and hardware-scoping rules require explicit owner/external approval. A distinct magic value prevents accidental reinterpretation of current VLY2 48-byte slots and preserves V02-B/C frozen vectors.

## 1. Review scope and authority

- **Proposal, not wire ratification:** isolate a deterministic, bounded, strict, round-trippable descriptor and encrypted-key envelope for expert attacks and cross-language vectors. An accepted parser proves no confidentiality, committing-AEAD security, actual user verification or valid factor lineage.
- **Explicit version boundary:** magic `V3RV` ("V3 review"), format `u16be=1`, suite `u16be=1` (labels only, **not a cryptographic security claim**). Never silently map this record into `VLY2` and never emit a production `VLY3` from these bytes.
- **Review location:** an entry-DEK descriptor and code-scope ancestry can be privacy-sensitive and **MUST NOT be publicly enumerated** solely because a codec can encode them. The final protocol must explicitly divide pre-unlock public VMK/bootstrap envelopes from VMK-authenticated or separately sealed inner records. Root descriptor bytes may need public visibility to compute a KDF, but are untrusted until authenticated. Site names, usernames, origin, trusted registries, plaintext provider seed and recovery codes are not part of this slot frame.
- **Owner product invariants remain binding:** independent random VMK/VERS/DEKs; VMK exposes outer metadata only, no VMK-derived DEK; hardware-vault VMK never code-only; hardware-backed R1 uses two distinct code+existing-password and code+enrolled-hardware administrative slots; Isolated **all complete DEK routes** physical or recovery disabled `STRICT_NONE`, while normal reads always fresh physical; Option A requires actual code when sealing any new code-dependent slot. Standard weaker recovery is structurally possible but explicit owner consent `OPEN-REC-CONSENT` remains **OPEN**.

## 2. Exact proposed binary envelope: V3RV revision 1

All multibyte lengths/integers are **unsigned, big-endian**. UUIDs are 16 raw bytes in canonical UUID order. No padding, optional omission, unknown fields, redundant defaults, duplicate TLVs or trailing bytes are accepted. The design is fixed-position plus tagged optional fields, **not TLV**. One frame has a hard **test-only** cap of 2,048 bytes, including a descriptor cap of 1,024 bytes.

| Offset | Size | Field | Proposed validation |
| --- | ---: | --- | --- |
| 0 | 4 | `V3RV` magic | Exact ASCII; not `VLY2` |
| 4 | 2 | Format version | Exactly 1 |
| 6 | 2 | Cryptographic suite identifier | Exactly 1, **unapproved** |
| 8 | 2 | Descriptor byte length | 1–1,024, bounded before consuming |
| 10 | N | Canonical descriptor | Strict table in §3; policy-validated but **untrusted** |
| 10+N | 24 | XChaCha20 nonce | Nonzero in candidate; does not by itself prevent nonce reuse |
| 34+N | 2 | Ciphertext length | Exactly 48 (32-byte wrapped key + 16-byte AEAD tag), not an accepted final representation |
| 36+N | 48 | Opaque candidate ciphertext | **Not decrypted or authenticated by this parser** |
| 84+N | 32 | Opaque candidate "commitment" | **Not verified; not a proven committing AEAD** |
| 116+N | 0 | End of frame | Reject trailing bytes, truncation, unknown version/suite |

The frame's initial 10 bytes and descriptor are intended as versioned, unambiguous authenticated context. The nonce and ciphertext are included in a separately proposed commitment input (§4). A future finalized format may need an entirely different AEAD/commitment; **there is no promise of binary compatibility**.

### Descriptor byte order, immediately following the 10-byte frame prefix

| Order | Bytes | Field |
| --- | --- | --- |
| 1 | 16 + 16 | `vault_id`, `slot_id` (both nonnil) |
| 2 | 1 + 16 | `target` tag: 1 VMK, 2 VERS, 3 entry DEK, 4 provider seed; `target_id` must be nonnil **only** for entry DEK |
| 3 | 1 + 1 | `vault_mode`: 1 password/virtual, 2 password/physical; `route`: 1–9 current `FactorPolicy` discriminants |
| 4 | 1 [+3] | Entry-policy presence 0/1; if 1, `EntryMode`, `EntryTier`, `RecoveryPolicy` (all 1-byte defined tags); required for DEK only |
| 5 | 1 | Purpose: 1 normal, 2 recovery, must match route kind |
| 6 | 1 [+16] | Recovery scope tag 0 none, 1 vault owner, 2 group owner, 3 entry owner. Nonzero tag includes 16-byte owner ID |
| 7 | 1 [+16] | Ancestor-present tag 0/1; if 1, an ancestor slot UUID (not nil or self-reference). **Declared link only, NOT proof that the entire graph is valid** |
| 8 | 1 [+27] | Password component tag 0/1. If 1: `encoding_id u8` (1, **NFC/UTF-8 proposal only**), `kdf_id u8` (1, Argon2id v0x13 proposal), `salt[16]`, `memory_kib u32be`, `passes u32be`, `lanes u8` |
| 9 | 1 [+48 or variable] | Provider tag 0 none, 1 virtual (provider UUID[16] + purpose hash[32]), 2 physical (`credential_len u16be` + 1–128 bytes credential + RP-ID hash[32] + raw PRF salt[32] + scope[1] + UP flag[1] + UV flag[1]) |
| 10 | 0 | Exact end; no spare capacity / padding / ignored trailing fields |

**Structural policy validation** reuses `model::route_is_allowed`; hardware normal entry modes cannot gain a virtual route, `STRICT_NONE` forbids recovery but never weakens Isolated normal hardware, Isolated code-only/code+password DEK recovery fails, and hardware VMK code-only fails. For recovery routes, an authenticated *code-owner* scope must eventually agree with the effective root: VMK/VERS/seed -> vault UUID; SHARED entry -> vault UUID; GROUP -> nonnil group UUID; INDEPENDENT -> entry UUID. This candidate checks **only the advertised fields**, not ownership, derived factor proofs or the entire ancestor graph.

**Candidate parse-time Argon2 guard only:** `8,192 ≤ memory_kib ≤ 262,144`, `2 ≤ passes ≤ 8`, `1 ≤ lanes ≤ 4`, memory at least `8 × lanes`, nonzero 16-byte salt; these **do not represent production limits**. A production implementation also needs an owner-selected, **aggregate pre-auth resource budget** and must not scan 256 attacker-provided slots. KDF `encoding_id=1` records an **unapproved proposed** `UTF8_NFC_v1` representation; no current Rust production path normalizes passwords, and legacy raw byte KATs are unchanged.

The physical provider fields **bind a claimed credential/RP/PRF-salt/scope/UP/UV context** but can be attacker-chosen. A valid descriptor is not a verified authenticator. `prf_salt` is still free-form here; the required deterministic/unique per-entry hardware derivation and what qualifies as fresh UV are **OPEN-15**. `ancestor` links are declared and may be dangling/cyclic across slots; they are neither complete graph validation nor independent factor assurance.

## 3. Candidate factor order and review-only cryptographic transcript

**Review-only proposal, NOT implemented in the new codec:** each descriptor's complete normal/recovery route selects an ordered factor recipe, with each component explicitly typed and length-framed. Proposed 32-byte components:

| Route | Ordered component recipe | Warning |
| --- | --- | --- |
| Password-only VMK normal | Argon2id(master), software virtual PRF | Virtual is protocol parity, **not independent 2FA** |
| Hardware VMK normal | Argon2id(master), fresh registered physical PRF | No cached or virtual fallback |
| Password-only VMK / provider-seed code-only recovery | Recovery code only | Separate VMK and original seed envelopes required |
| Hardware VMK token replacement | Recovery code, Argon2id(existing master) | No lost-token PRF recovered |
| Hardware VMK master reset | Recovery code, registered physical PRF | Requires credential still enrolled |
| Password-only provider-seed normal bootstrap | Argon2id(master) only | Must work **before** VMK load |
| Default entry normal | VERS, entry-selected virtual or physical PRF | Physical on **every** normal read |
| Custom entry normal | Argon2id(entry password), entry-selected virtual or physical PRF | No implicit VMK |
| Standard entry recovery | The separately provisioned policy-valid code-only/code+password/code+physical recipe | F-1 weaker alternative consent **not approved** |
| Isolated entry recovery | Code + registered physical PRF or none (`STRICT_NONE`) | Hardware mandatory on every complete DEK route |

Proposed framing for each factor input: `role_tag u8 || len u16be || component[len]`, with a unique role tag for master-password Argon2, custom entry Argon2, recovery code, VERS, virtual PRF and physical PRF; factor-count prefix `u8`. No untyped concatenation, swapped order, concatenation ambiguity, or role confusion. A code belongs to one vault/group/entry scope, and any accepted shared ownership must appear explicitly in its authenticated root chain.

The **implemented review-only** `slot_context` is precisely:
```text
"Vaulty/V02-G/REVIEW-ONLY/slot-context/v1"
|| ASCII "V3RV" || u16be(1) || u16be(1)
|| u16be(descriptor_length) || descriptor_bytes
```

The **implemented review-only** `commitment_context` is precisely:
```text
"Vaulty/V02-G/REVIEW-ONLY/commitment-context/v1"
|| slot_context || nonce[24] || u16be(48) || ciphertext[48]
```

**Possible but UNAPPROVED** experimental schedule to submit for OPEN-01: `HKDF-Extract(salt=SHA256(slot_context), IKM=typed_factor_frame)`, separate HKDF Expand labels for wrap-key and commitment-key, XChaCha20-Poly1305 encrypt 32-byte random key with `slot_context` as AAD, plus a separate HMAC-SHA256 tag over `commitment_context`. This is only a *review hypothesis*, not an implemented vNext `seal`/`open` and **not a proof of multi-key commitment**. OPEN-01 must decide whether an established committing-AEAD primitive or different construction is required, define verification order, error-oracle resistance, nonce policy and validation before release. **Do not treat a MAC matching under one guessed key as rigorous key commitment.**

The legacy V02-B candidate retains its *different* `Vaulty/V02-B/REVIEW-ONLY/slot/v1` HKDF transcript, six frozen V02-C vectors and old `VLY2` 48-byte slot model. No implicit compatibility exists.

## 4. DEK-bound entry metadata and browser origin

The existing [V02-E test-only entry AAD](../../src/v02/entry_binding_candidate.rs) proposes a separate domain `Vaulty/V02-E/REVIEW-ONLY/entry-binding/vNext` and authenticates, under the entry DEK, the vault UUID, entry UUID, big-endian revision, exact normal mode/tier/recovery and **length-prefixed UTF-8 bytes of origin, username and title** in the order origin, username, title. This V02-G suite tests that changing origin/username/title changes the candidate AAD. VLY2 currently does **not** DEK-authenticate these fields and its existing AAD is unchanged.

**Still to review before wire freeze:** define whether `origin` means exact scheme/host/port serialized by a trusted daemon, how to canonicalize Internationalized Domain Names and default ports, credential-fill origin versus display URL, and whether these fields must be stored/hidden differently. A matching AEAD AAD alone does **not** authorize an untrusted browser frame. V08 must require a user gesture and independent daemon verification of exact origin/tab/frame/client/action; origin metadata cannot be populated authoritatively by a page. vNext entry ciphertext format, canonical origin representation, version and authorized migration/re-encryption remain OPEN-01/V04M work.

## 5. Negative evidence, threat matrix, and what is NOT covered

| Attack/property | Current synthetic evidence | Remaining reviewer-required work |
| --- | --- | --- |
| Unknown/wrong magic, version, suite, target, malformed flags, length, truncation or trailing bytes | Strict decoder rejects invalid syntax and explicitly rejects this frame as VLY2 | Cross-language deterministic byte vectors; fuzz and parser differential tests (V02-H) |
| Isolated weak recovery, wrong code scope, purpose mismatch, provider mismatch | Structural route matrix plus V02-G negative examples | Real key lineage, owner registry, revoked tokens, fresh hardware per-read, bypass closure |
| Valid but malicious descriptor/nonce/ciphertext mutation | Different *public transcript/commitment input* (not authenticated here) | Real vNext cryptographic authentication, multi-key attack model, independent OPEN-01 verdict |
| Oversized malicious Argon2 header or many slots | Per-descriptor candidate parse bounds only | Aggregate CPU/memory/time budget and selected-route limits, measured production parameters |
| Duplicate/cyclic/dangling ancestor IDs | Self-reference and nil rejected locally | **Full authenticated cross-slot graph** checks, uniqueness and cycle detection before READY/commit (V02-H/V04) |
| Entry-origin substitution under VMK-only writer | Future-version DEK-AAD diff test; V02-E normal transition guard | Finalized DEK-AAD and reencrypt/migration, trusted browser origin policy |
| AEAD key substitution / multi-key commitment | **NOT PROVEN** by a 32-byte draft HMAC field or mutation of synthetic ciphertext | Independent cryptographer defines key-commitment security notion and approves/rejects actual construction |
| Physical device salt/UV/fanout | Untrusted descriptor flags and synthetic components only | OPEN-15 physical enrolled credentials, stable PRFs, RP/UP/UV, freshness and batching evidence |
| Backward compatibility and backup rollback | `V3RV` never aliases `VLY2`, no new runtime migration | Authenticated ancestor validation, R8 backup factor-inventory and V04M explicit restore tests |

A parsing success **never** means VERIFIED/READY; no vNext key release, committed slot, recovery, code prompting, trusted owner attestation, or device operation exists in this milestone. No site credentials may be used.

## 6. V02-G acceptance and V02-H / OPEN-01 reviewer request

**V02-G internal acceptance only:** test-only module is unreachable in non-test application builds; zero new dependencies or modifications to frozen V02-C vectors; exact distinct frame and descriptor framing; canonical encoding/decoding and broad negative tests; no new production KDF default; explicit F-1/OPEN-REC-CONSENT, OPEN-KDF-PROFILE, OPEN-PASSWORD-ENC, OPEN-01 and OPEN-15 blockers; reviewer inventory pins source, tests and docs.

**V02-H:** produce independent-language byte and crypto vectors for the agreed *revised* vNext proposal; enforce effective root/ancestor graph invariants, malicious commitment and offline oracle attack cases, aggregate KDF work bounds, strict decode/fuzz with corpus mutation, address real-device transcript changes before final freeze, and pin dependency evidence. Each expert review may start earlier, but neither a green CI result nor an LLM review replaces the independent verdict.

**External OPEN-01 reviewer asks:**

1. Is the proposed tagged-factor HKDF combination secure for weak password inputs, recovery code-only and correlated/captured PRF values? What is the exact assumption for virtual PRF and VERS lifetime?
2. What multi-key commitment notion is needed for root, bootstrap, VERS and entry-DEK wrappers? Does the proposed HMAC after AEAD meet it? If not, replace and revector.
3. Does byte framing authenticate every security-relevant context before release; can modified, duplicated or replayed descriptors cause cross-vault/entry/target ambiguity or denial of service?
4. How should Unicode normalization, production Argon2 cost ceilings, resource budgets and failure timing be represented without downgrade, guessing-oracle or migration hazards?
5. Are origin/metadata binding and authorized recovery code/ancestor scopes sufficient for the four entry modes and S2 Isolated under all alternate routes?

**OPEN-15 separately:** pin which authenticator operation/credential/RP/salt/UV transcript is actually attested and how entry PRF salts are derived, whether hardware supports repeated per-read user presence/verification, and what shared-root batching does to blast radius. Source descriptor flags alone are not physical proof.

**No independent reviewers are named and no qualified security verdict has been obtained.** Record results in the [acceptance register](../roadmap/acceptance-register.md) and [decision register](../decisions/register.md), never as inferred sign-off.
