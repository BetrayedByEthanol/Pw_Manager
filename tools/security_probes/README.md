# Vaulty security probes — OPEN-18 route graph / OPEN-01 candidate KEK

**Status: executable reference prototype, not production code or cryptographic approval.**
These probes intentionally do not change Vaulty's v0.4 format or authorize real entry access.
Use only authenticated policy snapshots, never browser-supplied policy JSON.

## Run (Python 3.10+; checker/verification/tests require only standard library)

```sh
python route_graph.py fixtures/routes.json --entry sensitive --state loaded
python route_graph.py fixtures/routes.json --entry strict --state cold
python route_graph.py fixtures/routes.json --entry strict-bug --state loaded # exits 1
python kek_vectors.py fixtures/kek_vectors.json
python -m unittest -v test_probes
```

To regenerate **synthetic** fixtures: `pip install argon2-cffi && python make_vectors.py`.
Optional `cryptography` and `argon2-cffi` packages let tests independently check the
HKDF output and the password-derived Argon2id examples; they are not runtime dependencies
for the route graph, frozen vectors or core tests.

## Route graph policy JSON (`vaulty-route-v1`)

The `factors` map gives stable IDs, kinds (`master_password`, `entry_password`,
`physical_fido2`, `virtual_prf`, `recovery_code`, `loaded_session`), statuses
(`active`, `revoked`, `suspended`, `disabled`) and optional `available` booleans.
The `keys` map holds OR-ed wrapping slots; a slot's `requires` array is an **AND** of
`factor:ID` or `key:ID` prerequisites. Slots have `normal`, `recovery` or `resident`
kind; optional `states` restrict use to `cold`/`loaded`. A `resident` slot can only
be used after load. Entire ancestor chains are traversed, not merely the final DEK slot.

An `entries` item declares DEK ID, policy (`ENTRY_DEFAULT_VIRTUAL`,
`ENTRY_DEFAULT_PHYSICAL`, `ENTRY_PASSWORD_VIRTUAL`, `ENTRY_PASSWORD_PHYSICAL`),
recovery policy (`SHARED`, `GROUP`, `INDEPENDENT`, `STRICT_NONE`) and expected
`first_key` (VERS root) or `entry_password_factor`. VMK is a mandatory *outer*
prerequisite in `cold` evaluation, never an entry-KEK ancestor. In `loaded` mode
there is no VMK requirement. A recovered VMK does **not** recover an entry DEK.

The checker returns all complete, explicitly provisioned routes for configured/usable
conditions, their factor IDs/kinds and slot provenance, plus separate `entry_recovery`
and `outer_recovery` flags so a code-only VMK recovery is not confused with
a bypass of a strict entry. `available:false` removes a
factor from *currently usable* routes but not from *configured* assurance. Revoked or
suspended factors/slots never grant routes. The analyzer rejects malformed/cyclic graphs,
unknown references, invalid normal factor combinations, VMK ancestry in entry KEKs,
`STRICT_NONE` recovery through the DEK **or any ancestor**, and route explosion; it
never silently reports a partial graph as a safe result.

### Weakest-route interpretation

First, `minimal_configured`/`minimal_usable` report every complete route whose
factor set is **not** a strict superset of another complete route; this
objective partial order preserves incomparable alternatives. `weakest_*` is
a separate **policy-friction heuristic**, not an entropy/attack-success metric:
(1) routes avoiding a fresh physical authenticator rank weaker; (2) among them,
those demanding fewer distinct independent-factor *IDs* rank weaker. All tied paths
are returned. A high-entropy 256-bit recovery code is not cryptographically
weaker than a password merely because both are labeled one factor; passwords that
users reuse may not be independent. `virtual_prf` and `loaded_session` are never
counted as independent security factors. The UI must display the full set, not only
its representative minimum, and distinguish `cold` from `loaded` exposure.

A `STRICT_NONE` entry may legitimately allow **VMK recovery to open the outer file**:
strictness is about alternative routes to that entry's DEK and its ancestors, not
about forbidding all vault-level recovery. A hardware label is not hardware-mandatory
when a complete entry-DEK route bypasses the physical device, even if other routes
use it. Sample `sensitive` demonstrates this bypass; `strict-bug` is deliberately
invalid to exercise detection.

### Boundaries

This is static policy analysis, not runtime verification. It does **not** validate
FIDO2 assertions, authenticator attestation, real user presence, password entropy,
recovery code custody, loaded-process compromise, freshness of authenticators, secure
storage of policy data, authentication prompts, side channels or hardware loss.
The consuming system must bind factor IDs to authenticated trust registry entries
and enforce operation-level policies. The checker exits with code 1 on configured
structural/policy issues, 2 on parse/graph errors. A currently unavailable factor
is reported separately; availability alone is not a downgrade.

## Candidate KEK transcript (`VAULTY-OPEN-01-CANDIDATE-v1`)

All strings UTF-8 and all transcript fields are **2-byte big-endian length-prefixed**.
The five context fields, in order, are `vault_id`, `target_id`, `slot_id`, `purpose`,
`policy`. A 32-byte `first_component` is a VERS value or an Argon2id password output;
`prf_component` is a 32-byte authenticated virtual or physical PRF value.

```text
P = ASCII("VAULTY-KEK-v0.4-CANDIDATE") || 0x00
C = frame(vault_id) || frame(target_id) || frame(slot_id)
    || frame(purpose) || frame(policy)
salt = SHA256(P || "SALT" || 0x00 || C)
IKM_two = P || "TWO-FACTOR" || 0x00 || frame(first_component) || frame(prf_component)
IKM_code = P || "CODE-ONLY" || 0x00 || frame(32-byte recovery code)
PRK = HKDF-Extract-SHA256(salt, IKM_selected)
info = P || "EXPAND" || 0x00 || frame(mode) || C
KEK = HKDF-Expand-SHA256(PRK, info, 32 bytes)
```

`mode` is exactly `two_factor` or `recovery_code_only`; a code-only route
**does not** insert a dummy PRF. Purpose is context-bound (`wrap-vmk` vs
`wrap-entry-dek`), as are vault, target, slot and protection policy.
Two password-input examples use Argon2id v=19/m=8192KiB/t=2/p=1 *for vector
reproducibility only*, NOT as recommended production hardening parameters.
The fixture contains public synthetic secrets, input encodings, salt, PRK, info and
frozen KEK output; it must not hold live keys/passwords. The tests use RFC 5869
case 1 and, where installed, independent HKDF/Argon2id library verification.

**OPEN-01 remains a release blocker**: this unreviewed factor combiner is a
reproducible candidate, not a specification freeze. Key-committing AEAD and slot
commitment, PRF output scoping/batching, Argon2id parameter selection, downgrade
resistance, and bootstrap/recovery cycle analysis need separate cryptographic
review before Rust production implementation. Successful test-vector matching proves
cross-implementation determinism, not the security of the composed protocol.

Sources: RFC 5869 (HKDF), RFC 9106 (Argon2). No source code from those RFCs is copied.

## v0.4 extension — INDEPENDENT and blast_radius

`INDEPENDENT` recovery requires a **dedicated recovery-code factor** with
`{"kind":"recovery_code","scope":"entry","entry_id":"<exact entry ID>"}`,
and a **direct recovery slot on that entry's DEK**, requiring that code as a
factor. Inherited recovery through VERS/provider ancestors or a vault/group
code violates independent recovery even if a correct direct slot also exists.
An entry-owned recovery code must never decrypt a different entry's DEK.

`python route_graph.py fixtures/routes.json --blast-radius` computes a static
configured fanout for each factor/root/DEK: dependent entries, entries exposed
with *no additional factors*, and minimal additional factor sets after that
single material is compromised. This reports potential impact, not likely
compromise or actual unauthorized decryption. In particular `key:VERS`
impacts several default entries but still requires the other PRF/factors. It
must never be interpreted as evidence that a particular FIDO2 PRF salt leaks
all values for that device. VMK is not a DEK dependency.

The test suite now includes 20 shared JSON conformance cases, including
invalid independent/shared/ancestor recovery configurations, and exact loaded
blast-radius expectations. A standalone Rust reference port and its own Cargo
crate run the **same** conformance JSON; see `rust/README.md`.

## v0.4 extension — candidate commitment-key expansion

The same HKDF-Extract PRK derives a **distinct** 32-byte commit key with:

```text
commit_info = P || "COMMIT-KEY" || 0x00 || frame(mode) || C
commit_key  = HKDF-Expand-SHA256(PRK, commit_info, 32)
commit_input = P || "COMMIT-TAG" || 0x00 || C
             || frame(nonce_24) || frame(AAD) || frame(wrapped_ciphertext)
commit_tag  = HMAC-SHA256(commit_key, commit_input)
```

The nine frozen KEK/commitment vectors are interoperability evidence only.
The commit tag is **not claimed as a reviewed committing AEAD**: actual
cryptographic requirements, key commitment, salt protocol, and error oracles
still need independent scrutiny. See `CRYPTO_REVIEW_REQUEST.md`.


## Owner-approved S1–S4 conformance addition (v0.4.1)

S1: Every entry's own `ENTRY_*_VIRTUAL` / `ENTRY_*_PHYSICAL` setting selects
its normal cryptographic provider; `normal_provider` and
`fresh_physical_operation_required_per_normal_read` reflect that setting.
A physical entry requires a **fresh** PRF operation for every read regardless
of Standard/Isolated tier; this reference checker models the required factor
but **does not prove** live device interaction or memory zeroization.
No silent hardware→virtual fallback is allowed. A mixed-policy loaded vault
may service virtual entries using its resident provider.

S2: The optional entry attribute `isolation_tier` is `STANDARD` by default,
or `ISOLATED` for a physical entry. Every complete entry-DEK route for an
Isolated entry, including `INDEPENDENT`, inherited/SHARED and other recovery,
**must contain an authorized cryptographic physical FIDO2 factor**.
Missing hardware on any route emits `ISOLATED_HAS_NON_HARDWARE_ACCESS_ROUTE`.
Trying to configure a virtual entry as Isolated is a schema error. A code-only
VMK route cannot substitute for the entry-DEK physical requirement.

S3: INDEPENDENT schema, direct entry-owned recovery-slot checks, and conformance
remain active; its setup/creation UI is deferred. Existing INDEPENDENT records
must not be silently converted.

S4: Ancestry and local accidental-rollback detection are *storage requirements*,
not functionality of this read-only route checker. Later production acceptance
must test vault UUID, authenticated commit parent-hash chain, stable entry
revisions, tombstones, stale-save and conflict handling, restored old files,
and limits of a separately stored non-authoritative local last-seen-head marker.
No hostile-rollback resistance is claimed.

The additional six shared conformance cases in `fixtures/conformance.json`
cover Isolated + code-only bypass, valid hardware-bound INDEPENDENT recovery,
SHARED hardware-bound recovery, STRICT_NONE and cold-vs-loaded behavior.
Both Python and Rust consume exactly these JSON records.
