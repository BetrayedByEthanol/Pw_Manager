# V02-F — Recovery Assurance & Cryptographic Policy Decision Contract

**Status:** PRE-APPROVAL DESIGN / REVIEW INPUT — **NO NEW OWNER APPROVAL OR PRODUCTION CRYPTOGRAPHY** (2026-11-07). Follows [merged V02-E PR #13](https://github.com/BetrayedByEthanol/Pw_Manager/pull/13), merge `122479b439210964af39dae7e7d5ae025217394b`. This is a proposed decision package for V02-G/H and V04/V06, **subordinate to the approved [v0.4.5 specification](../specification/v0.4.5.md)** and the [decision register](../decisions/register.md).

**Not a release gate resolution.** OPEN-01 (independent combiner/commitment) **BLOCKED**; OPEN-15 (real FIDO2 device/UV/scope/freshness) **BLOCKED**; G1/G2/G3 **BLOCKED**; no active key slots or real credential storage. Existing V02-B/C frozen transcripts and VLY2 bytes MUST NOT change due to this document. An AI-assisted review and synthetic tests are not an independent cryptographic assessment.

## 1. Authority and decision matrix

| Topic | Already approved in v0.4.5 | Proposal for review, NOT owner-approved | Required authority / downstream |
| --- | --- | --- | --- |
| F-1 / `OPEN-REC-CONSENT` Standard weaker recovery | Standard entry may have separate policy-valid recovery routes; **no implicit VMK→VERS/DEK access**; S2 Isolated complete routes always physical | Per-entry explicit selection + informed opt-in when a recovery route drops the normal factor; **no preselected weak route and no silently chosen STRICT_NONE** | **Owner decision** on consent/default/receipt before V04 provisioning |
| R1 / Option A | Password-only code-only VMK; hardware-vault VMK has two distinct code+password/code+registered-physical routes; fresh code on every newly sealed code-dependent envelope | Structured preview and coverage/receipt schema; no second approval required for unchanged R1 and Option A | V04 implementation + verification, OPEN-01/15 for cryptographic/hardware claims |
| F-2 Argon2id | Argon2id candidate exists; **8 MiB, t=2, p=1 is a test-floor, not production minimum** | Benchmark 64 MiB/t=3 using p=1 and p=4 against representative devices; measure other profiles, choose bounds and per-operation budgets only after evidence | Benchmarks + owner performance decision + **OPEN-01** |
| Password bytes | No frozen production text-to-KDF rule | **Propose NFC normalization → UTF-8**, explicit versioned identifier, no trim/casefold/truncation; keep old paths unchanged | Owner interoperability decision + **OPEN-01** for final KDF transcript |
| F-3 recovery-code/PRF scope | SHARED/GROUP/INDEPENDENT/STRICT_NONE policy; Isolated per-read hardware and per-route hardware; D-30 batching provisional | Typed scope ownership; prohibit accepting a group/entry recovery code as an unrelated root; propose deterministic domain-separated PRF salt context for isolated/entry purposes | V04/V06 implementation and **OPEN-15** for device derivation/fanout, OPEN-01 for transcript |
| F-4 hardware UV | Enrolled credential/RP/salt/UV mode pinned; no fallback/downgrade | Do **not** assume all hardware universally supports/uses UV=true; test UV=true and any proposed UP-only mode as separate, explicit security profiles | **OPEN-15** real devices and explicit owner profile decision |
| F-6/F-9 new wire and entry binding | Existing VLY2 not final key-slot format; entry origin/user/title not fully DEK-authenticated | Require separate version, strict canonical descriptor, authenticated origin identity and authorized conversion/rewrap | V02-G/H + **OPEN-01** before final wire; V04M migration, V08 fill threat tests |
| F-7/F-8 trusted factors/secret lifetime | Candidate `Components` is untrusted bytes; partial `Zeroizing` improvements only | Private verified-factor provenance, owner/credential registry checks, memory and failure-path audit | V03/V04/V06 + OPEN-15 + OPEN-01; not satisfied by documentation |

No proposal in the third column is silently upgraded to APPROVED by merging V02-F. Design refinements that affect an approved R1/S2 rule require an explicit owner decision and a new decision-register entry.

## 2. Normal access vs recovery: an assurance-report contract

The daemon's future report MUST represent two *different root classes* and distinguish **normal** access from **recovery** paths for each:

- **VMK/outer metadata:** every complete normal and administrative recovery route to the VMK, including pre-load seed/bootstrap dependencies. VMK recovery alone does not imply VERS, provider-seed or DEK recovery. The outer body exposes titles, usernames, origins and registries.
- **VERS / provider seed:** independent key-material availability and complete normal/recovery ancestry; never infer these from a VMK slot. For password-only recovery the **original** virtual seed must have its own provisioned code-dependent bootstrap route, otherwise normal virtual-entry access may be lost.
- **Each entry DEK/secret:** all normal and separately provisioned recovery routes including inherited SHARED/GROUP ancestors, nested wrapping slots, code scope, and current credential registry state. Custom entry password and physical provider are not replaced by the VMK.
- **Assurance identity:** show the weakest **configured** complete path and weakest **currently usable** complete path independently. A LOADED session, virtual adapter, cached PRF, a mere descriptor flag, a PIN prompt or a recovery UI label MUST NOT count as an independent hardware possession factor.
- **State and provenance:** `READY/PENDING/MISSING/DEGRADED/UNVERIFIED/STRICT_NONE` are not inferred from serialized labels. READY needs verified, durable envelope creation, authenticated registry membership, active factor proof, and a valid complete route. Pending or merely sealed paths cannot be advertised as recoverable. Unknown origin/owner/group scope, dangling ancestor, revoked/suspended token, or a missing fresh physical proof must fail closed.
- **Historical copies:** a currently strong route does not erase earlier code-only backups. R8 reports known older encrypted copies and the factors capable of opening each; purge warnings must not claim copies already outside local control have been eliminated.

**Illustrative report shape (UX/contract sketch only, not a protocol or trusted JSON parser):**

```json
{
  "root": "entry-dek:<entry-uuid>",
  "normal": {
    "configured": ["entry-default-physical:VERS+registered-physical"],
    "usable": ["entry-default-physical:VERS+fresh-physical-if-verified"],
    "weakest": "hardware-gated"
  },
  "recovery": {
    "configured": ["independently-provisioned:recovery-code-only"],
    "usable": [],
    "weakest": "recovery-code-only",
    "coverage": "UNVERIFIED"
  },
  "overall_weakest_configured": "recovery-code-only",
  "explicit_weaker_route_consent": "NOT_RECORDED",
  "activation": "BLOCKED"
}
```

Labels are explanatory and cannot replace a complete graph. The example intentionally shows an unapproved recovery route: **it must not be activated or called READY**. The provider may be declared physical while not yet proven by a real enrolled authenticator.

### Recovery route examples and mandatory outcomes

| Scenario | Allowed structural policy | Must not claim |
| --- | --- | --- |
| Password-only VMK + code-only recovery | Yes, **VMK only**; seed bootstrap and entry-DEK routes separately provisioned | "Every Standard entry opens with the VMK code" |
| Hardware VMK + code only | **Forbidden**, including emergency/opt-in | "Hardware-backed" when a normal software-only VMK path exists |
| Hardware VMK + code+existing password / code+registered hardware | Both separately required R1 admin routes, **PENDING until actually provisioned** | Missing-token PRF or every DEK recovered by VMK |
| Password-only Standard entry normal physical/custom + independent code-only DEK recovery | Structurally permitted, **weak**; explicit weaker-route consent **PROPOSED** before sealing | Unconditionally hardware-mandatory overall assurance |
| Standard entry in a hardware vault + code+password or code+physical DEK recovery | Structurally permitted only when separately sealed; disclose entry effect, code custody and token omissions | Code-only hardware-vault VMK/metadata access |
| Isolated normal physical + STRICT_NONE | Allowed **only with fresh physical normal access**; recovery disabled | That STRICT_NONE permits virtual normal access |
| Isolated normal physical + code+registered physical DEK recovery | Structurally allowed with genuine enrolled hardware on **every complete recovery route** | Code-only, code+password or virtual DEK bypass |
| Shared root rotated or group coverage added | Require affected-entry graph recalculation; newly created **code-dependent** envelopes require their actual code (Option A) | Auto-approval of weaker descendant routes or implicit inherited READY |
| All hardware and password lost in hardware-backed vault | No authorized recovery under R1 | Recovery via code-only escrow or software fallback |

### Proposed per-entry consent ceremony (F-1; **not approved**)

1. On entry creation, migration, or a change to any *effective* normal/recovery ancestor, preview **normal** versus **recovery** factor recipes and the weakest overall path for each affected DEK. Explicitly distinguish VMK metadata from entry secret reachability.
2. Present concrete choices: retain a recovery path with hardware/entry factor, elect a permitted weaker recovery path **with warning**, or intentionally opt for `STRICT_NONE`. Do not auto-select the weaker option **or** silently force `STRICT_NONE`. If no compliant choice is authorized, leave the operation uncommitted.
3. The trusted daemon must generate an immutable human-readable summary for owner confirmation, listing affected entries, dropped factors, old/new paths, code-scope reuse/blast radius, data-loss consequences, historical backups and prerequisites. Browser content cannot provide this summary.
4. **Proposed consent receipt**, stored in the VMK-authenticated control body: intent ID, vault/entry or group scope, base generation/commit, exact proposed route-set digest, affected entries, security downgrade disclosure version, authorized owner/client identity and decision/time; bind receipt to the transaction and require fresh approval on any subsequent route change. Neither this record nor UI assent is proof that the recovery code/PRF was actually used.
5. During provisioning, apply approved **Option A**: each new/replaced code-dependent envelope requires the actual code and all other applicable factors (including the new token's verified PRF). Preserve old valid slots until a verified atomic commit/reopen; abort rather than advertise `READY` when code, device or owner proof is missing.
6. At runtime, reject approval/receipts from untrusted page or descriptor input; no owner decision is inferred from `RecoveryPolicy::Shared` or a `VERIFIED` bit. The public route policy remains a *structural* predicate, not consent.

**Open owner question `OPEN-REC-CONSENT`:** approve, amend or reject this explicit per-entry opt-in requirement and the no-preselection UX before V04 implements it. V02-F records a recommendation, **not consent or a new approved recovery policy**.

## 3. KDF/password policy: benchmark plan (F-2)

### Candidate configurations, not production security decisions

| Profile | Memory | Passes | Lanes | Role |
| --- | ---: | ---: | ---: | --- |
| Existing frozen V02-B/C fixture | 8 MiB | 2 | 1 | **Tests only**; must not become application defaults |
| OWASP 2026 reference baseline | 19 MiB | 2 | 1 | External baseline comparison; not necessarily sufficient for an offline encrypted vault |
| RFC 9106 second recommendation | 64 MiB | 3 | 4 | External memory-constrained reference |
| Vaulty candidate comparison A | 64 MiB | 3 | 1 | Same memory/passes with fewer lanes; benchmark and review |
| Vaulty candidate comparison B | 64 MiB | 3 | 4 | Compare with RFC profile and device capabilities |
| Higher-memory calibration point | 256 MiB | 3 | 1 / 4 | If feasible; **not** a header-controlled default or unbounded open route |

Sources: [RFC 9106 §4 and §7.4](https://www.rfc-editor.org/rfc/rfc9106.html) and [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html). These external references discuss recommended parameter profiles; Vaulty needs a measured local encrypted-vault unlocking/DoS design, not a copied default. Values are intentionally **not** written into the V02-B/C transcript or an accepted public header.

**Measurement contract:** on each supported OS and representative low-end, baseline and high-end host, run release-mode measurements with pinned Rust/libargon2 version and controlled memory pressure. Record CPU/RAM, parallelism, Argon2id version 0x13, profile, salt/password inputs **synthetic only**, median/p95/p99 *latency*, peak resident memory, concurrent attempts, swap/OOM behavior, and timeouts/cancellation. Compare a one-slot normal unlock, one alternate recovery ceremony, permitted multi-slot batch and hostile maximum-slot header. Benchmark short and long Unicode passwords separately without persisting raw values. Publish hardware class and environment, not personal secrets.

**Mandatory production work-budget requirements proposed for V02-G/H, subject to expert assessment:**

- Only permit strictly bounded/syntactically valid descriptors **before** Argon2 work; reject unsupported algorithms, invalid salt lengths, duplicate slot IDs, absent route/owner scope, unknown versions or unapproved KDF parameters. An unauthenticated header must not dictate unlimited work.
- The future trusted controller chooses a **small explicit list of owner-selected authorized routes**, not a scan of all `MAX_SLOTS=256` alternatives. Bound Argon2 *evaluations* per one user ceremony, cumulative memory, aggregate CPU time, concurrent derivations, and total request lifetime; fail closed without uncontrolled retry. Parameter maxima alone do not bound total work.
- Reuse a password derivation **only** within one authorized operation for identical bytes/salt/Argon2id params and bound root purpose; no cross-session derived-secret cache, no soft fallback to a weaker KDF, and clear cached values on success/error/cancel/lock.
- Every new password-derived slot needs a CSPRNG salt (at least 128 bits) and enforced per-context uniqueness. Exact salt derivation, reuse across shared-root routes, KDF parameters and cost encoding must be authenticated after verification; supply chain and library zeroization require OPEN-01 attention.
- Never process KDF work for all `MAX_SLOTS` just because they appear in the file; per-slot algorithm agility or different cost is a **new reviewed wire version**, not implicit negotiation. A candidate with excessive pre-auth KDF cost rejects safely and does not downgrade.
- Establish thresholds *from measured data* with owner acceptance criteria and independent reviewer threat-model input; **no numeric production minimum or concurrency budget is approved by V02-F**.

**Release blockers:** production lower/upper Argon2 bounds, threshold for concurrent/aggregate work, memory-limited device behavior, and password length upper bounds must be decided and tested before an approved vNext protocol.

### Password representation (proposed `UTF8_NFC_v1`, NOT frozen)

**Recommendation for new-version password-bearing slots:** accept the full Unicode scalar-value sequence from a trusted prompt, normalize using **Unicode NFC**, encode as UTF-8 bytes, and pass the complete byte string to Argon2id. Do not trim leading/trailing spaces, normalize line endings silently, lowercase/case-fold, apply compatibility NFKC/NFKD mappings, truncate at NUL or at a fixed character/byte count, or log/display the derived bytes. Reject invalid Unicode or values above a separately calibrated UTF-8 byte limit **before** hashing. Store an authenticated `password_encoding_id` and any Unicode normalization-version policy in the new descriptor; never autodetect between algorithms based on a failed password.

This is consistent with the **July 2025** [NIST SP 800-63B-4 password verifier guidance](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/) recommending NFC prior to hashing. NIST's verifier guidance is **informative** here: Vaulty uses password-derived encryption keys, not necessarily a network authentication verifier. NFC is preferable here to NFKC as an initial proposal because compatibility folding conflates more distinct character sequences. **This choice needs explicit owner and cryptographic review before freeze.**

**Test matrix for V02-G/H:** empty/ASCII/embedded space/trailing space/Unicode composed and decomposed canonical equivalents; compatibility-equivalent-but-canonically-distinct characters; multi-script, emoji/combining sequences, embedded NUL (either explicitly valid or uniformly reject as an input rule), max accepted byte length and overflow, invalid UTF-8 API input, multiple platform input methods; salt/KDF transcript byte-stability and wrong-encoding failure.

**Migration:** never silently apply NFC to V02-B synthetic raw password vectors or to old VLT1/VLY2 data. An explicit source-version unlock using its original representation is prerequisite to owner-approved re-encryption into a new slot. If old decoding is unknown or impossible, fail with migration instructions and leave the source untouched.

## 4. Recovery-code scope and material ownership (F-3; V02-G input)

The code inventory must bind each 256-bit generated code to its **intended root and ownership**: vault-level SHARED, authenticated group schema, or dedicated entry-scoped INDEPENDENT. A code presented for one entry/group **cannot** be accepted as authority for another root. One known code may appear in several separately sealed slots only if the approved scope and effective-route report make that blast radius explicit. Do not invent a new factor from `LOADED`, VMK or a virtual provider; never label a code as physical.

**Proposed key-schedule context (NOT final bytes):** domain-separate the recovery code's role from master password and FIDO2 PRF; bind vault UUID, root target type/ID, recovery scope type and owner scope ID, route kind, slot UUID, suite and version, and prescribed component order into a single *strictly framed* transcript. For SHARED/GROUP ancestry, spell out how the same code and ancestor material propagates through dependent VERS/DEK routes. The authenticator's raw PRF input salt and the KDF's internal salt are **distinct domains**, never accidentally reused or accepted as interchangeable. Decide whether the PRF salt is random or deterministically derived only after OPEN-15 verifies hardware capabilities, repeatability, per-entry uniqueness and legitimate token replacement.

**Owner + source-of-proof:** policy descriptions never prove actual code possession; a trusted prompt must produce code bytes freshly under Option A. A factor supplied by a browser cannot set its own scope or assert registration. Isolated normal and recovery routes remain hardware mandatory regardless of how recovery codes are scoped; `STRICT_NONE` prohibits recovery only.

## 5. V02-G wire/cryptography review contract (NOT a frozen format)

V02-G must propose one **new explicitly versioned envelope**, not add candidate commitment bytes into a VLY2 48-byte `Slot`. Before OPEN-01 final review, specify exact canonical bytes and strict decode/round-trip rules for:

1. **Format and algorithms:** magic/format/suite and descriptor version; length framing, integer endian, domain labels, optional-field absence, canonical ordering, unknown/duplicate/trailing bytes; public-vs-authenticated visibility and bounded parsing.
2. **Key identity and routes:** vault/slot/root IDs, target/entry mode/tier/recovery, normal/recovery purpose, effective ancestor references, registered scope and dedicated code ownership; ensure root identity cannot be re-targeted.
3. **Password components:** explicit encoding identifier, Argon2id version/salt/memory/passes/lanes and bounded work; no silent KDF or password-encoding downgrade.
4. **Hardware/virtual components:** typed provider binding, actual enrollment credential/RP/PRF scope, UP/UV mode, reviewed PRF salt and device-proven evidence source; virtual provider is software parity, not second factor.
5. **Key commitment:** formal threat model and exact multi-key/key-substitution notion; AEAD nonce/ciphertext/tag, independently assessed committing binding and MAC verification order; record external OPEN-01 verdict **before** production use. Probe P6 alone is not such a proof.
6. **Entry payload authorization:** DEK-authenticate the origin/username (and any other fill-authoritative metadata), bind vault/entry/revision/policy and exact origin bytes or a separately justified canonical origin representation; prohibit VMK-only origin redirection.
7. **Recovery and migration:** Option A new-code slot ceremony and coverage states; versioned source unlock, durable encrypted preflight backup/R8 factor inventory, authorized rewrap, destination re-open/verify, rollback and coexistence rules. No automatic VLY2 interpretation or silent recovery downgrade.

**V02-H evidence** must include independent new-version vectors and mutation/negative/fuzz cases, version downgrade rejections, cross-vault/entry/slot/provider swaps, root/ancestor graph analysis, offline password-oracle study, scope/UV mismatch tests and multi-key attack attempts. A working local verifier and all green tests remain **candidate evidence**, not OPEN-01/15 clearance.

## 6. Decision request and acceptance

| ID | Proposed disposition at V02-F merge | Owner/expert action needed |
| --- | --- | --- |
| `OPEN-REC-CONSENT` | **OPEN** | Owner approve or modify explicit informed opt-in, no preselection and reusable scope change re-approval (F-1) |
| `OPEN-KDF-PROFILE` | **OPEN** | Measure Argon2 profile, select floor/ceiling/work budget, resource and memory attack assumptions (F-2) |
| `OPEN-PASSWORD-ENC` | **OPEN** | Owner choose NFC/UTF-8 `UTF8_NFC_v1` or an alternative, including byte limit and migration rule |
| `OPEN-01` | **BLOCKED** | Independent expert review of KDF, combiner, key-commitment, recovery scope, and final vNext wire/encoding |
| `OPEN-15` | **BLOCKED** | Real FIDO2 PRF per-entry salt/scope, device support, UP/UV and batching/fanout verdict |
| `G1/G2/G3` | **BLOCKED** | Require code, physical hardware and runtime/crypto evidence separately; no implied approval |

**V02-F acceptance:** policy scenarios distinguish VMK vs VERS vs entry DEK; every proposed change says who decides it; production KDF and normalization are visibly **UNAPPROVED**; R1/S2/Option A remain intact; release gates blocked; frozen V02-B/C cryptography and VLY2 wire unchanged; reviewer/roadmap/feature/decision/acceptance docs linked. The next buildable package is **V02-G — Cryptographic Protocol vNext Review Candidate**, not production key activation.
