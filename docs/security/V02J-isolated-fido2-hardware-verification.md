# V02-J — Isolated FIDO2 Hardware Integration & Verification Foundation

**Status (2026-11-08): LOCAL LAB HARNESS / NOT EXECUTED ON HARDWARE / NO OWNER SECURITY-PROFILE APPROVAL / NO OPEN-15 VERDICT.** Baseline is merged [V02-I PR #18](https://github.com/BetrayedByEthanol/Pw_Manager/pull/18) at `54a20268ceff1e764f229a069e1b65651672bf11`. This extends the [V02-I PRF salt and two-key policy](V02I-fido2-prf-isolation-and-hardware-assurance.md) with a **separate, opt-in Linux/libfido2 laboratory tool**, not a Vaulty authenticator implementation. Existing [S1/S2/R1/Option A](../specification/v0.4.5.md) remain binding; owner `OPEN-HW-ASSURANCE`/`OPEN-PRF-SALT` remain undecided and `OPEN-01`/`OPEN-15` and G1–G3 remain **BLOCKED**.

## 1. Deliverables and explicit trust boundary

| Artifact | What it provides | What it does NOT provide |
| --- | --- | --- |
| [`tools/hardware/fido2_v02j.py`](../../tools/hardware/fido2_v02j.py) | Explicit local test session, primary/backup **test credential** registration using `fido2-cred -M -h -v` and `-V -h -v`, and repeatable **signed native CTAP** assertions with `fido2-assert -G -h -p -v` then independent `-V -h -p -v`. Compare PRF outputs from two fresh assertions and a second synthetic entry. | A trusted Vaulty registry, enrollment of real vault secrets, attestation-chain validation, vNext AEAD/DEK unwrap, automated hardware matrix completion, remote browser origin checks or release authorization |
| [Offline regression tests](../../tools/hardware/test_fido2_v02j.py) | Synthetic isolated test session, missing backup and scope negatives, CI hardware refusal, challenge/RP/output parsing, public-key signature-verification invocation, no-PRF receipts and best-effort mutable-buffer wiping | Any real device interaction; a simulation cannot establish UP/UV or PRF stability on a token |
| [V02-I reference](../../tools/v02_verifier/reference_v02i_prf.py) | Exact proposed public `raw_input` and native salt `SHA256("WebAuthn PRF" || 0x00 || raw_input)` for a specific test vault, entry, slot, credential, purpose and UV profile | Production salt approval, WebAuthn-native actual-output equivalence or independent cryptographic commitment |
| [Local observation receipt](#5-reviewer-evidence-and-receipt-interpretation) | Minimal whitelisted JSON: requested profile, signed assertion verifier outcome, boolean same-entry stability and optional distinct-entry result | Raw PRF, PIN, key or password; **not a PASS for all I-P01–09, not READY and not an independent OPEN-15 approval** |

**Fail-closed boundaries:** No import from the application/daemon runtime; no FIDO2 subprocess in CI; no auto-selected device; no hardware operation without `--hardware-test` and interactive terminal; no real vault file or credential; no runtime VLY2/V3RV format or key schedule changes. Test session/evidence paths must be outside the repo, private regular files (mode 0600), and cannot be symlinks. A test credential ID/public key is public cryptographically but potentially linkable and must be handled as private lab metadata.

The harness relies on the installed, OS-provided `fido2-cred`/`fido2-assert` executables. Pin and record their exact **libfido2 version/package** separately in the review receipt. No new Rust or Python FIDO2 dependency is introduced into the shipping app. CLI output from assertion acquisition contains a **raw hardware PRF secret**; the harness captures it in process memory and intentionally never prints, stores or hashes it into a receipt. Python and third-party CLI intermediates can leave immutable copies: **this does not guarantee zeroization** and is acceptable only for a dedicated synthetic lab credential, not a production Vaulty secret. Mutable copies are overwritten on success and failure. Do not run under tracing, debug, terminal recording or a core-dump-enabled sensitive environment.

### Standards and CLI interfaces

- W3C [WebAuthn PRF extension](https://www.w3.org/TR/webauthn-3/#prf-extension): browser `eval.first` is hashed with `"WebAuthn PRF" || 0x00` for CTAP hmac-secret; WebAuthn `prf` exposes the UV-backed result when CTAP is the backend.
- Yubico [libfido2 assertion CLI](https://developers.yubico.com/libfido2/Manuals/fido2-assert.html): acquisition `-G -h -p -v` and verifier `-V -h -p -v` check a signed assertion including the requested UP/UV and extension-data bits, using a saved public key.
- Yubico [libfido2 credential CLI](https://developers.yubico.com/libfido2/Manuals/fido2-cred.html): creation `-M -h -v` and attestation verification `-V -h -v`. **Its attestation certificate chain is not automatically trusted/validated** by this command; the device make/model provenance remains a reviewer task.

The native CTAP `-t uv=false` request in an **explicitly experimental** touch-only run does **not** prove that UV was absent. The signed UP bit can be checked but a stronger UV statement requires independent signed authenticator-data inspection. The owner has **not** approved touch-only as a usable Vaulty route.

## 2. Local operator runbook (Linux, two test tokens)

Install the distribution's `fido2-tools` package, connect the primary **test** token, and make sure the current login has appropriate `/dev/hidrawN` permissions. Use a unique **operator-controlled** test RP ID; for browser comparisons it must match an RP ID allowed for the local secure origin. No production account, vault password, production RP ID or recovery code should be reused.

```sh
# Local operator console only. These commands are NOT run in GitHub/Forgejo CI.
install -d -m 700 "$HOME/.local/state/vaulty-v02j"
python3 tools/hardware/fido2_v02j.py preflight
fido2-token -L                        # manually identify the correct HID device

python3 tools/hardware/fido2_v02j.py init \
  --session "$HOME/.local/state/vaulty-v02j/lab.json" \
  --rp-id vaulty-review.localhost

python3 tools/hardware/fido2_v02j.py register \
  --session "$HOME/.local/state/vaulty-v02j/lab.json" \
  --role primary --device /dev/hidraw0 --hardware-test

python3 tools/hardware/fido2_v02j.py probe \
  --session "$HOME/.local/state/vaulty-v02j/lab.json" \
  --role primary --entry alpha --compare-entry beta \
  --device /dev/hidraw0 --hardware-test \
  --receipt "$HOME/.local/state/vaulty-v02j/primary-observed.json"

# Physically replace the primary with the distinct backup key and adjust
# /dev/hidrawN after fido2-token -L. No key can be registered while absent.
python3 tools/hardware/fido2_v02j.py register \
  --session "$HOME/.local/state/vaulty-v02j/lab.json" \
  --role backup --device /dev/hidraw1 --hardware-test
python3 tools/hardware/fido2_v02j.py probe \
  --session "$HOME/.local/state/vaulty-v02j/lab.json" \
  --role backup --entry alpha \
  --device /dev/hidraw1 --hardware-test \
  --receipt "$HOME/.local/state/vaulty-v02j/backup-observed.json"
```

The RP ID is **illustrative**, the actual HID numbering varies, and each `probe` creates **fresh signed assertions** and may prompt for PIN/biometric + touch multiple times. The libfido2 CLI and device must support the hmac-secret extension. Failed device/timeout/PIN/extension verification is a **failure or unexecuted test**, never a silently accepted alternate software/virtual factor. An absent backup is **not assigned any per-entry READY slot** by the session file; creating two test credentials is not vault enrollment.

### Optional, unapproved touch-only experiment

```sh
python3 tools/hardware/fido2_v02j.py probe \
  --session "$HOME/.local/state/vaulty-v02j/lab.json" \
  --role primary --entry alpha \
  --device /dev/hidraw0 --hardware-test \
  --assurance touch-only --acknowledge-unapproved-touch-only \
  --receipt "$HOME/.local/state/vaulty-v02j/touch-observed.json"
```

The UP-only path uses native CTAP only. The flag `uv_absence_verified=false` is **always** recorded. Do not compare its PRF output to the UV-backed value as if it were the same authorization route; real no-UV behavior remains an OPEN-15 reviewer question. There is no automatic WebAuthn PRF evaluation or browser comparison in this foundation.

## 3. Hardware matrix mapping (no automatic approvals)

| I-P | Available V02-J foundation | Necessary manual/future evidence before a full PASS |
| --- | --- | --- |
| I-P01 | Register two *separate* locally operated public test credentials and UV-verified repeat PRF assertions | Named tester verifies devices are physically different, hardware/firmware versions, attestation/root trust, UV controls and stable result; **tool does not prove independent physical devices** |
| I-P02 | Compare primary credential PRF for two synthetic Isolated entries with different V02-I salts | Full encrypted **test-only** entry-DEK envelope interoperability remains unavailable until authenticated vNext candidate is approved; no real DEK used |
| I-P03 | Explicit missing-backup rejection; manual registration and primary/backup probes | Real wrong-device/no-device negative, source/backup slot provisioning and revoked token behavior are future work |
| I-P04 | Signed assertion verification under saved test public key + RP and fresh challenge, `-p/-v` on UV route | Negative replay/spoofed client/RP and trusted credential registry/revocation test; no browser trust path exists |
| I-P05 | Uses V02-I native CTAP salt transformation | **No WebAuthn/browser `prf` output comparison** in V02-J; needs independent browser-local test fixture and same credential/RP UV equivalence |
| I-P06 | Requests UV+UP and verifies signed assertion flags; experimental touch-only requires extra acknowledgement | PIN failures, UV-absent signed flags, fallback, timeouts, removal and negative branches must be run/documented by operator |
| I-P07 | Separate synthetic primary/backup credential enrollment | Real atomic encrypted slot rewrap/restore, Option A code prompt and verified reopen unavailable; V04/V06 not implemented |
| I-P08 | Two separate entry evaluations use distinct salts | **No 2-input batch** is implemented; D-30 still provisional, measure device touch/prompt behavior separately |
| I-P09 | Each `probe` requests fresh signed assertions; no persistent PRF field in session | App suspend/lock/reconnect, key lifetime and true configured READY versus currently usable coverage still V03/V04/V06 |

**None of I-P01–09 is automatically PASS just because a `probe` returns successfully.** A qualified reviewer must conduct and record negative controls and issue an independent OPEN-15 verdict scoped to actual hardware, firmware, OS and supported transport.

## 4. CI/safety acceptance without physical devices

```sh
python3 -m unittest discover -s tools/hardware -p 'test_fido2_v02j.py' -v
python3 tools/hardware/fido2_v02j.py preflight
python3 tools/v02_verifier/reference_v02i_prf.py --verify
cargo test --manifest-path tools/v02_verifier/Cargo.toml --locked --all-targets
python3 tools/v02_verifier/review_bundle.py --write /tmp/v02j-review.json
python3 tools/v02_verifier/review_bundle.py --check /tmp/v02j-review.json
```

CI must not have HID devices and must not access physical key material. Python tests mock libfido2 rather than emulate a hardware-backed authenticator: a fake signed assertion fixture is a **test of the harness controls**, not evidence of signature security. Maintain strict allowlist, negative paths, private session files, and no secrets in stdout, JSON receipts or source-pinned manifests.

## 5. Reviewer evidence and receipt interpretation

For each `probe`, a freshly created private receipt is JSON with `schema=RECEIPT_SCHEMA`, `device_execution=OBSERVED`, `full_i_p01_to_i_p09_matrix=NOT_EXECUTED`, `operation=signed_native_ctap_test_assertions`, booleans `repeat_prf_stable` and optionally `different_entry_prf_distinct`. A `signature_and_requested_flags_checked=true` flag means **libfido2's local verifier command returned success under its supplied public key**, not that this repository independently validated attestation or browser origin. `entry_route_ready=false`, `open_01_approved=false` and `open_15_approved=false` are invariant. No raw or hashed PRF output, PIN, challenge, credential ID or private key is copied into a receipt; the **local session** does contain public credential IDs and keys.

External OPEN-15 review receipt must separately record: signed test report author, exact reviewed git hash/source inventory, libfido2 version/package and device model/firmware, OS+transport, RP origin configuration, independently verified registration/attestation policy, signed UP/UV results and negative controls, per-entry salt test outcomes, browser-native interoperability results, each I-P01..09 `PASS/FAIL/SKIP` with evidence, backup replacement and secure failure case, residual issues and qualified assessor verdict. Only a named expert can move `OPEN-15` after examining sufficient evidence. An offline CI pass and local `OBSERVED` JSON never do.

## 6. Open questions and recommended continuation

**V02-J merge criteria (internal only):** audited opt-in Linux harness and tests; no unattended hardware accesses; signed assertion verification and input-bound requests; best-effort cleanup and non-secret receipts; fixed public V02-I salt transcript; documented I-P01..09 execution gaps; source-pinned evidence and green root/V02/security CI; no test device, production crypto or security-profile approval claimed.

**Not closed:** F-3/F-4/F-7, `OPEN-HW-ASSURANCE`, `OPEN-PRF-SALT`, D-30, `OPEN-REC-CONSENT`, OPEN-01/OPEN-15, G1–G3. An offline backup can be physically enrolled but **will not** acquire an existing Isolated entry's DEK merely by registration. The eventual V03/V04/V06 implementation must connect the trusted credential registry, actual per-entry slot sealing/atomic rewrap and authenticated authorization, then an independent hardware reviewer can test the full matrix.

**Next:** run the native hardware subset on operator-controlled primary and backup FIDO2 keys; separately implement a browser WebAuthn PRF lab comparison, full signed negative/replay/credential registry test and app lifecycle tests before asking the owner to approve UV/UP or key-salt policy. Concurrently complete production Argon2 work budgeting and vNext key commitment review. **Do not enable Vaulty real-credential storage based on this foundation.**
