# V02-I — FIDO2 PRF Isolation & Hardware Assurance Policy

**Status:** **REVIEW-ONLY PROPOSAL / NO NEW OWNER APPROVAL / NO HARDWARE TESTS OR PRODUCTION AUTHENTICATION** (2026-11-08). Baseline: [merged round-two findings PR #17](https://github.com/BetrayedByEthanol/Pw_Manager/pull/17), commit `a3f177722d0105de167b848d78df807ee108803a`. This packet addresses F-3/F-4/F-7 and W1 but does not close them. Its inputs are [approved v0.4.5 S1/S2/R1/Option A](../specification/v0.4.5.md), [V02-F decision proposals](V02F-recovery-assurance-and-cryptographic-policy.md) and [round-two disposition](V02H-round-two-review-disposition.md). **OPEN-01, OPEN-15, G1/G2/G3 BLOCKED. No real credential handling.**

The `src/v02/v02i_prf_review.rs` module is compiled **only under `#[cfg(test)]`** and computes *public proposed PRF input bytes and a candidate CTAP salt*, not a physical PRF result, trusted assertion, slot KEK, encrypted DEK, verified route or READY state. The [independently written Python reference](../../tools/v02_verifier/reference_v02i_prf.py) and [frozen six-vector fixture](../../tools/v02_verifier/fixtures/v02i_prf_vectors.txt) compare deterministic public bytes only. **This does not authenticate FIDO2 hardware or prove cryptographic isolation.**

## 1. Existing requirements vs review proposals

| Requirement | Approved and binding now | V02-I proposal / unresolved authority |
| --- | --- | --- |
| S1: physical entry normal read | Each **normal read** requires a fresh registered physical PRF; never cache a physical result across operations or silently use virtual provider | Trusted native FIDO2 / authenticated client-origin provenance and physical operation each read must be implemented V03/V06; **no such runtime adapter exists** |
| S2: Isolated entry | All complete entry-DEK access routes, including recovery, require real physical hardware; recovery may be hardware-mandatory or `STRICT_NONE`; normal is always physical | Distinct PRF input per entry, slot, credential and purpose, including GROUP/SHARED recovery ancestors; full authenticated graph and OPEN-15 review before READY |
| R1 / Option A | Hardware-vault VMK administrative code+password and code+registered-hardware routes; code-only VMK only in password-only vault; any new code-dependent envelope requires recovery code | New-token enrollment does not recreate another token's PRF or provision unvisited entries. No new `CodeOnly` Isolated route |
| D-30 (provisional) | Batched token rewrap **not approved** | Browser/CTAP two-input support can reduce interactions *if tested*, but no promise a physical key covers every entry or that multiple credentials can be evaluated with one touch |
| F-3 | PRF input salt is security-relevant, currently free-form and may be duplicated | Test-only deterministic, versioned per-slot salt preimage; precise transcript and backend interoperability require OPEN-01/15 |
| F-4 | Credential, RP, requested UV/UP policy pinned in slot context; fail closed on mismatch | **Propose UV-required default**; optional separately labeled **UP-only touch** profile **requires owner approval + real-device support**. No implicit upgrade/downgrade |
| F-7 | Factor bytes in V02-B and provider descriptors in V3RV are synthetic/untrusted | Trustworthy device-bound factor API and registry verification needed in V03/V06; typed bytes/flags alone cannot assert hardware provenance |
| F-1 | Standard weaker entry recovery remains explicit owner choice | No weaker Standard recovery or Isolated downgrade is newly approved by this packet |

### Hardware assurance profiles (OPEN-HW-ASSURANCE — owner decision OPEN)

- **Candidate `UV_REQUIRED` (recommended default, NOT selected/approved):** request and verify both user presence where required and user verification, bind the exact enrolled credential and RP, and reject missing UV, wrong credential, browser/client mismatch or changed PRF output. Whether PIN/biometric is actually prompted is device/OS dependent; never equate “PIN input requested” with cryptographically verified UV.
- **Candidate `UP_ONLY_TOUCH` (proposed optional, NOT approved):** requires real presence but no PIN/biometric user verification. It offers **weaker local assurance**, is a distinct profile/key transcript and cannot silently replace UV-required. At the CTAP `hmac-secret` level the no-UV branch can return a *different* secret. If allowed, require the owner to see that downgrade and freshly rewrap affected slots. **Do not offer it through WebAuthn `prf` if only UV-backed results are supported.**
- **Unsupported / no physical proof:** fail closed, don't substitute cached PRF, virtual provider, user-controlled strings, a weak recovery route, or an unauthenticated `uv=true` field. A registered credential can be listed as enrolled while its per-entry slot is `PENDING`; it is not usable until sealed with that token and validated.

These are candidate assurance labels, not an authorization state machine or selected default. `OPEN-15` must test enrolled authenticators, transport paths, signed assertion verification, PIN/UV/UP bits, RP and PRF lifecycle before the owner decides.

## 2. Test-only per-entry PRF evaluation input (not a final wire version)

For each **normal/recovery physical slot**, propose one public, deterministic, domain-separated PRF evaluation input:

```text
raw_input = ASCII "Vaulty/V02-I/REVIEW-ONLY/prf-input/v1"
            || u16be(1)
            || vault_uuid[16] || slot_uuid[16]
            || target_tag[u8] || target_uuid[16]
            || purpose_tag[u8] || tier_tag[u8]
            || factor_scope_tag[u8] || factor_scope_owner_uuid[16]
            || credential_len[u16be] || credential_id[1..128]
            || rp_id_sha256[32] || assurance_tag[u8]
```

Tags: `target` follows existing VLY2/V3RV `SlotTarget` values (1 VMK, 2 VERS, 3 entry DEK, 4 provider seed); `purpose` 1 normal / 2 recovery; `tier` 0 for non-entry, 1 Standard, 2 Isolated; `factor_scope` 1 Vault or 3 Entry; `assurance` 1 UV-required or 2 UP-only proposal. All fields have exact fixed or length-prefixed sizes; IDs and RP hash must be valid, credential must not be empty. Non-entry roots require vault scope and nil target ID; **every entry DEK**, including Isolated SHARED/GROUP/INDEPENDENT recovery, requires the entry's own target ID and `factor_scope=Entry`. The **factor PRF input scope is NOT the recovery-code/group owner scope**. Group codes may be shared under the approved recovery policy while each final entry hardware PRF remains separately scoped.

A new slot UUID and separately enrolled credential get a distinct input, even for the same entry. This construction is **a candidate test context, not an approved unique-secret theorem**. It cannot stop an attacker who already knows the correct PRF result and other factors, and it does not prevent copied old sealed snapshots; full registered owner/credential/slot/ancestor validation is still required before READY. If two descriptors share the *identical verified credential* and exact raw context, they will request the same PRF output: future trusted code must reject duplicate active slot identity, illegal reuse, and conflicting registry assignments. No raw or hashed salt is automatically secret.

### WebAuthn `prf` versus direct CTAP `hmac-secret` — **do not double-hash**

The [W3C WebAuthn PRF extension](https://www.w3.org/TR/webauthn-3/#prf-extension) maps an RP-provided `eval.first` to a CTAP salt by computing `SHA-256(UTF8("WebAuthn PRF") || 0x00 || eval.first)`. When implemented on top of `hmac-secret`, WebAuthn exposes the **UV-backed per-credential PRF**. [Yubico libfido2](https://developers.yubico.com/libfido2/Manuals/fido_assert_set_sig.html) distinguishes the UP and UV options and notes that CTAP PRF results vary with verification.

**The proposed interoperability mapping is exactly:**

```text
WebAuthn PRF client request: eval.first = raw_input
Native CTAP hmac-secret request: salt32 = SHA256("WebAuthn PRF" || 0x00 || raw_input)
```

Never pass `salt32` as `eval.first` (that would add a second hash), nor pass `raw_input` directly as a CTAP 32-byte salt. **Native and WebAuthn outputs have not been proven equivalent on any real token**; the WebAuthn extension can be implemented without CTAP, and a browser may not give the daemon sufficient trusted provenance. OPEN-15 must verify platform/client/credential/UV compatibility; any approved backend change requires confirmed equivalence or an authorized rewrap. For `UP_ONLY_TOUCH`, do not assume the WebAuthn PRF extension offers the no-UV CTAP branch.

**Caveat:** hashing an input to a CTAP salt is not a factor-combiner, nonce generator, password KDF, hardware attestation, signature verification, or secret-key derivation proof. Source test vectors cover only `raw_input` and `salt32`; they deliberately contain **no token PRF outputs or site credentials**. V02-B/C KATs and V3RV wire remain unchanged.

## 3. Two trusted physical keys: enrollment, coverage and replacement

Vault creation may register a **primary** and an **offline backup** token as trusted credentials. **Registering a vault-level token does NOT automatically create a per-entry DEK slot or grant it access to existing/new Isolated entries.** Each entry must report which credentials have *actual independently provisioned* complete normal and recovery routes.

| Scenario | Allowed pre-approval design | Coverage/result |
| --- | --- | --- |
| Owner creates Isolated entry with **primary present**, backup at home | Authorize entry creation with currently available registered key and freshly seal **primary-specific** DEK route; never need the absent backup just to create the entry | Primary provisioned (pending verification); backup **NOT ENROLLED FOR THIS ENTRY / PENDING**. Report no backup recovery until independently sealed |
| Owner later wants backup to unlock that entry | Use an authorized existing complete route to obtain the DEK + fresh VMK write authorization; present backup for its own credential-specific PRF and independently seal a new slot | Backup route becomes READY **only after authenticated commit/reopen and verified device-bound envelope**; no magic PRF cloning |
| Owner creates an entry and wants **both** trusted keys available | Enroll/verify both devices separately, provision **one physical route per credential**, record actual keys/slot scopes | A registration list is not a recovery coverage list; both cannot be marked READY until independently provisioned |
| Owner adds/replaces a physical key after the other is lost | First obtain an existing valid entry DEK access route; alternatively use a separately provisioned, S2-compliant code+registered-physical recovery route. New code-dependent recovery slots require code under **Option A** | No claim that VMK recovery or new vault token enrollment recreates lost entry PRFs; absent sufficient route, the entry stays locked |
| Owner disables/removes a trusted key | Calculate affected-entry effective routes, warn about inaccessible entries and historic backups; authorize exact change, revoke key from active registry, rewrap/rotate as appropriate | No silent deletion of the last Isolated access route; no claims of erasing old backups or hardware PRF outputs |
| Owner chooses to convert an **Isolated** entry into **Standard** for convenience | Explicit downgrade with fresh authorized entry-factor access + VMK write, trusted owner preview, generation-bound transaction, new entry DEK/record re-encryption and authorized factor-slot replacement; preserve backup warnings | May select a virtual normal path **only after changing the tier to Standard**. Never make Isolated normal route virtual or silently weaken recovery |
| Owner requests one touch to provision all entries / keys | D-30 batching remains provisional. Same token may process 1–2 PRF evaluation inputs in supported calls; it does not make absent tokens available or clone independent credential secrets | Per-entry salt and per-key route/authorization remain distinct. Test actual UV/touch behavior and bounded operation before enabling |

The **future UI must show entry → configured credential labels/IDs → normal and recovery route status** (READY/PENDING/MISSING/DEGRADED/UNVERIFIED/STRICT_NONE), not just “two trusted vault keys.” Labels are untrusted hints until registry and envelope checks. Reports distinguish *configured durable coverage* from *currently usable routes*: a key safely stored at home may be covered/READY while currently unavailable; an unprovisioned backup is PENDING, not READY. A user can intentionally choose one-key protection but must understand that losing the only key and lacking a hardware-mandatory recovery route can make an Isolated secret unrecoverable.

### Safe enrollment and atomic rewrap requirements (future V04/V06)

1. Verify trusted owner action, source vault/entry authentication, exact affected route graph and base commit; write operation requires fresh VMK authorization, source entry DEK authorization cannot be inferred from VMK.
2. Require physical presence and authenticated registered credential/RP/UV profile for each newly provisioned route, collect a fresh PRF result, and verify stable derivation twice at enrollment when policy requires it; no future slot claims an absent device was operated.
3. For each newly created code-dependent slot, request actual recovery code at creation (**Option A**) plus all other factors. Do not cache PRF outputs as a substitute for physical possession on later reads.
4. Bind separate slot/credential/purpose/salt context, owner-approved assurance and recovery scope in authenticated vNext metadata; reject duplicates, stale registration, revoked keys, wrong PRF output and cross-entry/group ancestry before completing a slot.
5. Freeze owner-approved transaction and affected-entry summary; preserve old valid routes until atomic commit and verified reopen. If any authorization or slot verification fails, leave old routes intact and mark new/affected routes PENDING/DEGRADED as appropriate.
6. Revocation/rotation must inventory all dependent entry DEKs and historical encrypted backups. Removing token registration cannot erase copied historic ciphertext or revoke previously seen PRF outputs. Never conflate a registry bit with cryptographic slot cancellation.

## 4. OPEN-15 real-device matrix (NOT EXECUTED)

Extend the [existing P01–P09 device preflight](V02D-independent-review-handoff.md) with explicit traceable receipts. Hardware testing must be performed by a qualified reviewer on each supported device/firmware/driver/OS/transport combination:

| ID | Required proof / negative control | Gate |
| --- | --- | --- |
| I-P01 | Enroll two real independent hardware credentials, bind exact credential ID/public key/RP; verify two stable UV PRF evaluations per slot, never print/store raw PRF outputs | OPEN-15 |
| I-P02 | Same token, two Isolated entries with distinct salts: outputs differ; each entry decrypts **only** its separately provisioned test envelope | OPEN-15 / OPEN-01 |
| I-P03 | Two tokens on same entry: each requires its own credential-scoped salt/envelope; wrong/missing/removed backup fails; an absent token cannot create READY | OPEN-15 |
| I-P04 | Reject wrong RP, wrong credential, spoofed client assertion, revoked/suspended registry credential and stale replay; signed UP/UV verification where supported | OPEN-15 / V07 |
| I-P05 | Compare WebAuthn `eval.first=raw_input` vs native CTAP `salt32=SHA256(prefix||raw_input)` with same credential and UV; explicitly prove/deny interoperability, test UP-only separate branch if supported | OPEN-15 |
| I-P06 | PIN/biometric/UV true/false: test missing UV, UP absence, touch-only, failed PIN, timeout, device removal, lost user presence; no unsafe fallback | OPEN-15 |
| I-P07 | Provision backup slot only when backup present, verify atomic reopen, retire primary, recover with provisioned backup; test Option A for new code-dependent routes | OPEN-15 / V04 |
| I-P08 | Two-input batch, per-entry salt separation, 1 vs 2 simultaneous PRF evaluations, timeout/user-touch fanout and D-30 power/UX claims; no cross-entry reusable root | OPEN-15 |
| I-P09 | Suspend/lock/reconnect, fresh per-entry READ_OPERATION, no retained hardware PRF/KEK across calls; report configured READY vs currently unavailable distinctly | OPEN-15 / V03 |

**Evidence template:** named tester, timestamp, device/firmware model (no private IDs), OS/browser/libfido2/driver versions, transport, RP, credential registration evidence (safely redacted), tested profile and exact slot-context digest, challenge/verified assertion result, per-test PASS/FAIL/SKIP with reason, mismatch/error conditions, zeroization/cleanup notes, source commit and external reviewer scope/verdict. Do not publish PIN, recovery code, raw PRF outputs, DEKs, private credential material or plaintext secrets.

## 5. Owner decisions vs implementation/review blockers

| Decision | Current status | Needed before release |
| --- | --- | --- |
| `OPEN-HW-ASSURANCE` | **OPEN owner decision**: UV-required default recommendation; whether explicit UP-only profile is offered | Owner selects allowed assurance profiles after OPEN-15 evidence; no implicit auto-downgrade |
| `OPEN-PRF-SALT` | **PROVISIONAL protocol candidate**, no approval | OPEN-01/15 jointly assess per-entry slot/credential/purpose scoping, preimage, WebAuthn vs CTAP mapping, collision/reuse/backup lifecycle; version-lock only afterward |
| `D-30` | **PROVISIONAL** | Owner + OPEN-15 decide bounded batch/fanout after hardware evidence |
| `OPEN-REC-CONSENT` | **OPEN** | Weaker Standard recovery remains an owner choice; preserve two qualifications of round-two findings |
| `OPEN-01` / `OPEN-15` | **BLOCKED** | Named cryptographer verdict on final authenticated vNext transcript/key commitment; separate real-device PRF/UV/scope proof |
| `G1/G2/G3` | **BLOCKED** | No slot/runtime READY, registered hardware or complete recovery implementation exists |

**V02-I acceptance:** documentation and test-only candidate source with six independent-language **public PRF-input/salt** fixtures, UV-vs-UP transport negatives, two-token/Isolated distinctions, owner matrix, OPEN-15 physical test plan, source hash inventory and clear UNAPPROVED/BLOCKED statuses. **No production key slots, no hardware access, no FIDO2 assertion verification, no changed VLY2/V3RV encoding and no owner security-policy approval**.

**Next work after merging V02-I:** obtain actual OPEN-15 device evidence and owner UV/UP/PRF salt choices, then revise the authenticated vNext protocol for OPEN-01; in parallel, implement measured Argon2id per-operation budgets under a separate milestone.
