# V02-K — Physical FIDO2 Verification & Evidence Intake (Rust operator runner)

**Status (2026-11-08): V02-K PR #20 MERGED; operator local native CTAP observations RECEIVED, not independently verified; NO physical device has been used in GitHub/Forgejo CI.** V02-K extends [merged V02-J PR #19](https://github.com/BetrayedByEthanol/Pw_Manager/pull/19), merge `9e7edb83f29b36078ca85b2eb3e4a1a0db03b1bb`. The source lives in [Rust V02 verifier binary](../../tools/v02_verifier/src/bin/vaulty_v02k.rs), with [Rust regression tests](../../tools/v02_verifier/src/bin/vaulty_v02k/tests.rs). It calls the [V02-J local test-only Python/libfido2 CLI](../../tools/hardware/fido2_v02j.py) for *actual* device operations. Rust does not read token PRF outputs, PINs or private credentials.

**Nothing in this milestone provisions or unlocks an actual Vaulty vault, approves production UV/touch-only behavior, completes WebAuthn/browser interoperability, or closes OPEN-01, OPEN-15 or G1–G3.** The operator-provided report is a reproducible *self-reported local observation* for further review, never a qualified independent cryptographic or hardware verdict.

**Owner evidence intake:** [EV-023 report and scope](V02K-local-hardware-evidence-received-2026-11-08.md), submitted 2026-11-08, records two reported YubiKey 5 NFC USB-A devices (firmware 5.7.4), both local probe stages `OBSERVED`, and a still-incomplete I-P matrix. Unsigned operator observations are not independent OPEN-15 certification.

## 1. Prerequisites

- Linux with two suitable FIDO2 test-capable authenticators (primary and backup); the tool creates **fresh TEST credentials** on the physical keys, not Vaulty entries.
- Rust/Cargo, Git, Python 3 and the distribution's `fido2-tools` commands `fido2-token`, `fido2-cred`, `fido2-assert`. Do not run as root, under `sudo`, under CI, or through terminal screen recording/debug tracing.
- Linux `/dev/hidrawN` permissions permitting access as the current user. The HID numbering can change on unplugging/replugging. Do not grant permanent world-writable permissions to devices.
- No real Vaulty secrets, master/recovery passwords, existing passkey PINs in logs, or production RP/origin. `vaulty-review.localhost` is a synthetic test RP for **native CTAP only**, not a browser origin claim.
- Work from a clean checked-out Git revision. The generated local report is pinned to the exact `git rev-parse HEAD`. All test-session files are written outside the clone.

For Ubuntu/Pop!_OS, install local prerequisites (package selection may vary with the OS version):

```bash
sudo apt-get update
sudo apt-get install -y git python3 cargo rustc fido2-tools
```

## 2. Clone and execute

Before V02-K is merged, check out its PR branch. After merge, use `main` instead.

```bash
git clone https://github.com/BetrayedByEthanol/Pw_Manager.git
cd Pw_Manager
git checkout feat/v02k-physical-fido2-evidence-intake

# No hardware access:
cargo run --locked --manifest-path tools/v02_verifier/Cargo.toml --bin vaulty_v02k -- preflight

# Discover connected hardware paths; check again after swapping a key:
fido2-token -L
```

Use the actual device paths from `fido2-token -L` below, **not the illustrative numbers**. If both keys appear at the same path when swapped, supply that same path for both flags; the runner pauses explicitly before each key.

```bash
cargo run --locked --manifest-path tools/v02_verifier/Cargo.toml --bin vaulty_v02k -- run \
  --primary-device /dev/hidraw0 \
  --backup-device /dev/hidraw1 \
  --rp-id vaulty-review.localhost \
  --hardware-test
```

The runner checks a clean Git tree, requires an interactive terminal, refuses CI, checks the device is a character device, then creates a mode-0700 directory under `$HOME/.local/state/vaulty-v02k/`. It creates a synthetic two-entry test session, prompts **PRIMARY** and **BACKUP** separately, and performs per-key registration plus fresh signed native assertions. For each key it requests the same entry twice and a second entry once to compare PRF outputs **in memory**. Each stage may require multiple PIN, UV and touch interactions. **Do not enter a PIN into the ChatGPT conversation.**

The native harness uses V02-I's proposed domain-separated PRF inputs. Its `fido2-cred` registration and `fido2-assert` signed verifier results are local observations, not evidence of attestation-chain trust or complete credential registry policy. The runner never performs touch-only testing by default; only the proposed UV-required native path is requested.

### On success or partial failure

The Rust runner writes:

```text
$HOME/.local/state/vaulty-v02k/run-<timestamp>-<pid>/
  session.json          PRIVATE: synthetic credential IDs / public keys
  primary.json          PRIVATE: local per-key observation
  backup.json           PRIVATE: local per-key observation (if reached)
  evidence-v02k.json    REDACTED: share this one file
```

The private JSON files may be absent if execution stopped earlier. No source file, test session, PIN or PRF secret should be uploaded or committed. `evidence-v02k.json` is created with mode 0600 and deliberately omits the RP ID, device paths, credentials, challenges, salts and PRF outputs. Its local booleans are operator observations and can be affected by a buggy CLI/device; independent verification is still required.

Send **only the contents of** `evidence-v02k.json`, or upload that file by itself. Do **not** send the entire directory or `session.json`. If the run errors, share the **non-sensitive error line** and, if created, the redacted evidence. This lets a reviewer distinguish unsupported PIN/UV, missing extension, wrong device, failed signature or temporary Linux permissions from genuine per-entry isolation issues without leaking factors.

You can display the redacted file via your file manager or:

```bash
cat "$HOME"/.local/state/vaulty-v02k/run-*/evidence-v02k.json
```

For multiple runs, select **only the newest run's** report; the wildcard may show more than one. Avoid sharing unredacted console logs from libfido2 commands.

## 3. What the report proves—and does not

| Item | Report meaning | OPEN-15 reviewer still needs |
| --- | --- | --- |
| `primary` / `backup`: `OBSERVED` | V02-J returned signed native CTAP assertion checks and boolean PRF stable/different-entry results for that test credential | Actual hardware/device identity and attestation, independent signed-flag/PRF verification; device firmware/runtime versions |
| `OBSERVED_MISMATCH` | At least one repeated-value or distinct-entry comparison did not match expectation | Investigate scope/salt/UV/client/driver before approving any policy |
| `INCOMPLETE` | A stage failed, operator aborted, or token path unavailable | No implied pass or authorization; rerun after investigating |
| I-P01–I-P04, I-P06 `PARTIAL` | Only portions of the native two-key/salt/signature/UV-request matrix were locally exercised | Full named independent reviewer execution with negative cases |
| I-P05 `NOT_EXECUTED` | No actual browser WebAuthn `prf` vs native CTAP comparison | Same credential/UV/RP browser-native transcript and result parity |
| I-P07–I-P09 `NOT_EXECUTED` | No atomic Vaulty recovery/rewrap, multi-salt batching, or app lock/suspend checks | Application operations and production-gated evidence |

Even when both keys return `OBSERVED`, the report keeps `full_i_p01_to_i_p09_matrix=NOT_COMPLETE`, `open_01=BLOCKED`, `open_15=BLOCKED`, `entry_route_ready=false`. **This is not a PASS for the complete matrix, not a trusted Vaulty enrollment, and not permission to store real passwords.**

## 4. Offline reproduction, source and receipt trust limitations

```bash
cargo check --locked --manifest-path tools/v02_verifier/Cargo.toml --all-targets
cargo test --locked --manifest-path tools/v02_verifier/Cargo.toml --all-targets
cargo run --locked --manifest-path tools/v02_verifier/Cargo.toml --bin vaulty_v02k -- preflight
python3 -m unittest discover -s tools/hardware -p 'test_*.py' -v
```

Rust tests exercise argument/terminal gating, malformed/duplicate/secret-bearing receipts, failed observation status and deliberately incomplete I-P01–09 output. CI executes only those **offline** checks. The Rust evidence parser accepts exactly the canonical fixed V02-J receipt fields and gate values. This is not independent validation of an authentic token signature: the local V02-J Python tool invokes the libfido2 signed assertion verifier and can still contain a bug, and a local JSON receipt is not cryptographically signed.

For repeatability, the source-review inventory includes both Rust files and this runbook at an exact commit. The GitHub workflow runs the Rust tests, V02-C/H/I synthetic vectors and existing V02-J mocked tests. Do not upload the private test directory to a public issue or PR.

**Next step after EV-023 intake:** obtain independent OPEN-15 review of the owner-submitted observations, run controlled WebAuthn/browser-vs-native PRF parity I-P05 and signed negative tests I-P04/I-P06; schedule I-P07–I-P09 once production-adjacent runtime/rewrap features can be tested. Do not upload private local session files or infer an approved security profile. `OPEN-HW-ASSURANCE`, `OPEN-PRF-SALT`, OPEN-01/15 and G1–G3 remain open/blocked.
