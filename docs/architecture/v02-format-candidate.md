# V02 — Candidate Vault Format & Cryptographic Foundation v0

**Status:** Merged experimental candidate in PR #8; testable Rust library `src/v02`, not approved for real credentials. **OPEN-01 and OPEN-15 remain blockers.** The deployed `pw_manager` executable remains inert, and the native host remains fail-closed. This document records the *candidate* encoding for review—not a frozen wire format, cryptographic proof, secure migration path, user-visible save API or an approved recovery route.

The [V02-A cryptographic protocol and key-slot review](v02a-crypto-keyslot-review.md) identifies missing factor/KDF/PRF/commitment fields and the unresolved independent reviewer gates. The current 48-byte `Slot` ciphertext expectation and pending descriptors are **not** a reviewed final slot format.

## Approved v0.4.5 invariants and D-ID mapping

- **D-02/D-16:** VMK is independently random and encrypts/authenticates only the outer metadata control body; no VMK-to-VERS, VMK-to-DEK or VMK-to-entry KEK derivation.
- **D-03/D-29/D-31:** every live entry payload uses its own independently random DEK and separate AEAD with AAD binding vault UUID, entry UUID, revision, normal entry mode, tier and recovery policy. ISOLATED requires a physical normal mode, and every described DEK route needs hardware; STRICT_NONE allows no recovery slot and never removes physical normal access.
- **D-07/D-26/D-32:** public VMK slot descriptors distinguish password-only versus hardware-backed modes. Hardware-backed code-only VMK/metadata recovery is structurally rejected. A hardware vault must describe BOTH code+existing-password and code+registered-hardware administrative recovery envelopes alongside a hardware normal path, but V04 must actually seal and verify these routes. No slot status is proof of auth, and a pending slot never grants access.
- **D-13/D-28:** single encrypted file, authenticated vault UUID, commit ID, generation, exact predecessor **encrypted-file hash**, entry revision/tombstones and duplicate ID checks. Last-seen-head and full ancestry/backup inventory implementation remain a separate integration step; hashes alone do not resist malicious rollback.
- **OPEN-02:** the public header has a **separate bounded pre-load provider-seed envelope section** to avoid circularity when a virtual provider is needed before VMK authorization. Password-only mode requires typed normal-password and recovery-code *pending* descriptors. No actual seed, password/recovery wraps or provider implementation exists in V02 v0. The seed must eventually be independently random and recover/reuse the same value across password resets.
- **R5/R6:** key lifetime and transaction approval are not enabled here. The library accepts a caller-supplied `Vmk` for cryptographic tests; trusted VMK authorization, scoped write transactions, expiry, OS lock and daemon-generated approval belong to V03/V07.
- **OPEN-01/15:** exact combined-factor KDF, key commitment, slot AAD transcript, enrollment UV semantics, effective route checking and hardware PRF remain **unapproved / unimplemented**, despite synthetic route probes existing in `tools/security_probes`.

## Candidate file layout (subject to independent review)

| Field | Placement | Size / constraints | Authenticated by |
| --- | --- | --- | --- |
| Magic `VLY2`, version `2`, zero reserved flags | public | 4+2+2 bytes, fail on unknown | entire header as outer AEAD AAD |
| Header length + ciphertext length | public | u32 little-endian each; bounded | outer AEAD AAD |
| Vault UUID, commit UUID, generation, predecessor hash | public | 16+16+8+32 bytes | outer AEAD AAD, repeated in body |
| Outer XChaCha20-Poly1305 nonce | public | fresh 24 bytes | outer AEAD AAD |
| Vault VMK normal/recovery slot descriptors | public | typed and bounded; at most 256 slots, header at most 64 KiB | outer AEAD AAD |
| Virtual-provider **pre-load bootstrap seed slot descriptors** | public header, opaque envelopes only | password-only header must describe both normal password and independent code recovery seed routes; no seed plaintext, **all states pending in v0** | outer AEAD AAD, future OPEN-01 approved slot AEAD |
| VMK-encrypted control body | encrypted | at most 16 MiB plaintext, 16-byte tag; strict exact file length | XChaCha20-Poly1305 with independently supplied VMK |
| VERS and virtual-seed slot descriptors | **inside encrypted body** | typed, bounded, never plaintext roots | VMK authenticated body; future slot AEAD |
| Entry index (IDs, title/username/origin, tier, mode, recovery, revision/tombstone) | **inside encrypted body** | at most 1024 entries, deterministic sorted IDs | VMK authenticated body |
| Entry ciphertext + scoped DEK slot descriptors | **inside encrypted body** | each ciphertext max 1 MiB, nonce 24B, tag 16B | separate per-entry DEK AEAD; record policy and IDs in entry AAD |
| Authorized client public identities / revocations | **inside encrypted body** | at most 128 entries; no trusted pairing implemented | VMK authenticated body |

Serialization is *strict*: exact lengths, little-endian integers, valid UTF-8, monotonic sorted/unique IDs, known enum discriminants, no trailing bytes, no silent legacy version coercion, bounded counts before allocations. Every outer header byte participates in domain-separated AEAD AAD. Inner AEAD domain binds vault ID, entry ID, revision, mode, tier and recovery policy; changing a policy without reencrypting fails decrypt. Candidate format labels and exact AAD encoding are not an approved construction until OPEN-01.

**Slot states:** PENDING, SEALED_UNVERIFIED, VERIFIED, DISABLED are only stored enums; parsing `VERIFIED` does not authorize a factor. Production APIs cannot transition through the hardware/recovery ceremonies yet. Current library supports structural `pending` slots to enable safe codec development while waiting for the approved combined-factor transcript.

## Version and migration rule

VLT1 and historical JSON inputs return **MIGRATION_REQUIRED**; unknown magic, version, flags, lengths and bad tags fail closed. Neither source is interpreted as a v2 file. V04M-1 will implement separate read-only legacy import with authorized decrypt, verified encrypted backup, independent destination keys, dry-run preview, destination commit, reopen verification and rollback. Do not reuse VLT1/JSON key wraps or import them as trusted active slots.

## Candidate successor and disk adapter

`prepare_successor` authenticates the previous file, mints a unique commit ID, increments generation, binds the entire predecessor encrypted-file hash and requires each removed entry to become a revisioned tombstone; modified entries need a higher revision. It produces **encrypted bytes only**, no disk change or daemon approval.

`storage::commit_candidate` under a single-writer lock authenticates both expected and proposed files and checks the candidate's lineage. It compares the active file under lock against the exact expected encrypted bytes. On divergence, it **refuses to replace active** and creates a durable encrypted conflict copy. Sidecar paths derive from the **entire** active filename: e.g. `vault.v2.lock`, `vault.v2.tmp-<uuid>`, `vault.v2.previous-<uuid>`, `vault.v2.conflict-<uuid>`. The writer rejects active filenames using those reserved sidecar suffixes and creates uniquely named, immutable encrypted predecessor snapshots with create-new semantics; an existing file is never removed if creation fails. `vault.v2` and `vault.previous` can therefore be distinct active files without clobbering each other's snapshots. On normal replacement it fsyncs temp and backup, renames atomically, fsyncs parent, and verifies the published file. Failure after rename is ambiguous: preserve both versions and explicitly reconcile.

**Commit invariant:** `prepare_successor` and the final locked `commit_candidate` **both** invoke the same cross-generation entry-transition validator, so a separately AEAD-sealed candidate cannot drop entries without tombstones, resurrect tombstones or bypass revision increments. The encoder also preflights the complete aggregate body length with checked arithmetic **before** creating the output buffer, stopping multiple individually valid 1 MiB records from exhausting memory beyond the 16 MiB body cap. Both rules have focused regression tests and resolved Codex P2 review threads. A subsequent P2 on bare relative vault paths was also fixed by normalizing empty parent paths and regression-testing successful commits and encrypted conflict copies; all four PR #8 review threads were resolved at merge.

**Limitations:** std filesystem path checks are not fully race-free against a malicious same-user process capable of swapping directories or symlinks between checks. No independent freshness oracle, no authenticated local last-seen-head integration, no verified cross-filesystem restore, no restart/OS-lock/transaction-state integration, no externally approved slot KEKs, no hardware/root bootstrap, no Windows disk adapter. These are explicit **G1 blockers**. Do not merge this as a claim of a production-compliant vault.

## Reproducible acceptance and negative tests

Run `cargo check --locked --all-targets` and `cargo test --locked --all-targets` in the repository. The v02 Rust library tests cover separately random roots, dual-layer AEAD roundtrip, header/entry policy tampering, wrong VMK/DEK, nonce freshness, forbidden hardware code-only and ISOLATED routes, STRICT_NONE, duplicate IDs/slot claims, legacy/version/truncation/fuzz-like rejection, revision/tombstone ancestry, stale-base encrypted conflict preservation, directory/symlink failures and pre/post-rename fault injection.

**Not certified:** real password/FIDO2/PRF derived factor routes, cross-language canonical conformance vectors, key substitution/commitment, complete hardware-vault recovery, fuzz coverage sufficient for a parser sign-off, restore under power failure, directory race protection, and independent external cryptographic review. No runtime feature or release gate is marked DONE merely because these synthetic tests pass.
