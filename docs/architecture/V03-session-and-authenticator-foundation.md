# V03 — Session States & Authenticator Adapters Foundation v0

**Status:** REVIEW-GATED SOURCE CANDIDATE. The Rust library models session state and
authenticator *requirements*, but cannot load a real vault or release a
credential. No code path in the normal compiled library constructs `LOADED`:
the sole loader is `#[cfg(test)]`, exercised with synthetic V02 file material.
The actual executable remains fail-closed; V02 is still an unapproved
candidate format. No independent OPEN-01/15 verdict or G1–G3 signoff follows
from this work.

## Scope and guarantees

- `src/v03.rs` exposes `Session`, `Phase` and finite `SessionLimits`.
  `inspect_public_file` calls the bounded V02 framing parser, retains only
  an **unauthenticated** public header, and reports `authenticated=false`.
  This cannot unlock the VMK, activate a token or establish trusted rollback.
- `CLOSED` and `LOCKED` contain no loaded vault body, VERS shares, software
  provider seed or pending operation. `OPEN` only contains the unauthenticated
  public header. The synthetic `LOADED` model owns authenticated V02
  metadata/opaque entry ciphertext, fresh-masked XOR shares of a synthetic
  VERS and a Zeroizing synthetic virtual-provider seed. It never holds a
  plaintext VMK, KEK, DEK or physical PRF output.
- Every secret reconstruction in `MaskedVers::with_transient` uses a
  `Zeroizing<[u8; 32]>` local buffer. Both shares are refreshed using a
  CSPRNG mask **before** the callback runs, including during panic unwinding.
  This is **memory-handling friction only**, not cryptographic secrecy
  against process-memory compromise. In particular, the virtual provider
  is not independent hardware possession or two-factor authentication.
- Read intent records the exact entry's `FirstFactor` and
  `ProviderRequirement`, with separate default-VERS/custom-password and
  virtual/physical branches. An ISOLATED entry's normal access requires
  physical hardware even under `STRICT_NONE`; virtual never silently
  substitutes. Every read has a new random operation UUID; `authorized=false`
  and there is **no DEK unwrap, PRF execution, plaintext delivery or usable
  trusted adapter in V03 v0**. `refuse_unimplemented` always denies, zeroizes
  transient reconstruction and cancels the pending intent. There is no
  cached previous physical verification.
- A write intent pins the authenticated synthetic base vault/commit ID and
  generation plus bounded TTL (1–300 s) and change cap (1–64). No staging,
  trust in arbitrary client summaries, owner approval, VMK unlock, ciphertext
  creation or atomic disk commit is yet wired; it always fails closed at
  completion. R6 must be implemented separately with a genuine owner
  approval and authenticated-head comparison.
- `SessionLimits` requires nonzero idle and absolute lifetimes, idle <
  absolute, and a maximum configured absolute time of 24 hours. Renewing
  activity may extend **idle only**. All read/write attempts enforce the
  clock checks, while the future trusted daemon must also call `poll` from
  its own timer. Expired operation intents are cancelled, not authorized.
- Lock, suspend, hibernate, listener disconnect/failure and explicit close
  drop loaded metadata and secret buffers; resume cannot auto-reopen.
  **No production listener has been connected**: the model deliberately
  starts with an unavailable lifecycle monitor and has no public method to
  mark it healthy. The simulated monitor registration helper is test-only.
  No Linux logind/systemd delay-inhibitor, Windows power handler, trusted
  secure prompt, mlock, ptrace protection or core-dump policy is claimed.
- `Session` intentionally does not implement `Clone` or `Debug`.
  Error strings are fixed categories, not copies of path/client/device data.
  The design cannot guarantee scrubbing of allocator copies, temporary
  CPU registers or shared-process memory; secret-owner Zeroizing buffers
  are best-effort.

## Behavior/acceptance matrix

| Requirement | V03 v0 evidence | Still missing |
| --- | --- | --- |
| R5: state transitions | PUBLIC inspection, explicit close/lock, test-only LOAD; offline tests | Real trusted OPEN→LOADED factor proof; rollback reconciliation and last-seen head |
| R5: LOADED memory | Synthetic two-share masking and remask, Zeroizing seed; tests | Production bootstrap and secure OS/process memory hardening |
| S1/S2: four entry modes | Mode/tier-specific **unprivileged intents**; no physical→virtual fallback; tests | Trusted physical/virtual authenticator integration, DEK unwrap and actual per-entry authorization |
| R5: timeout/event fail closed | Finite idle/absolute clock checks, OS event handlers, failure locking | Real event subscribers, independent tick delivery, failure injection and suspend integration |
| R6: writes | Bounded unique write intent with authenticated synthetic base reference | Staging and digest/summary freeze, owner UI, fresh VMK, disk conflict check, atomic commit |
| V07: client access | No trusted client/access token | Secure daemon, authenticated E2E and approved local pairing |
| OPEN-15 / OPEN-01 / G1–G3 | **BLOCKED** | Independent cryptography/device review and runtime proof |

## Developer verification (offline and synthetic only)

~~~sh
cargo test --lib -- v03
cargo check --lib
cargo check --manifest-path tools/v02_verifier/Cargo.toml --locked --all-targets
cargo test --manifest-path tools/v02_verifier/Cargo.toml --locked --all-targets
python3 tools/v02_verifier/review_bundle.py --write /tmp/v03-source-inventory.json
python3 tools/v02_verifier/review_bundle.py --check /tmp/v03-source-inventory.json
~~~

`cargo test --lib -- v03` tests the isolated source with synthetic V02
files and uses **no YubiKey**. The default `src/main.rs` binary must continue
to exit unsuccessfully and must not enable the legacy CLI.

## Explicit handoff to V03 follow-ups / V04–V07

1. Define a non-forgeable, trusted daemon-only VMK authorization and local
   authenticated-ancestry/rollback gate before replacing the test-only LOAD
   helper. Never permit a public `load(vers, vmk)` convenience path.
2. Implement and externally review virtual-provider bootstrap slots,
   authenticated physical credential/RP/UP/UV/PRF inputs and per-entry
   recovery/normal route proofs; no adapter may turn a caller boolean into
   permission. V04/V06 must enforce absent/revoked devices.
3. Wire Linux logind screen-lock, suspend/hibernate, listener health and an
   independent timer; fail-closed when the monitor is absent or unreliable.
   Add process-memory/core-dump, lock-on-crash and OS integration testing.
4. Build trusted local prompts and R6 staging/owner approval/commit under
   exclusive lock and authenticated base-head comparison. Protect plaintext
   and transients across cancellation and panics.
5. Preserve **OPEN-01, OPEN-15, OPEN-HW-ASSURANCE,
   OPEN-PRF-SALT, OPEN-REC-CONSENT and G1–G3** as unresolved. EV-023 and
   EV-025 are local hardware self-reports, not production authorization.
