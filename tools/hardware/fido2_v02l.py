#!/usr/bin/env python3
"""V02-L-A/B test-only native FIDO2 negative verification.

No Vaulty password/entry/DEK, production credential or passkey operation.
Requires an existing V02-J/K *private synthetic* session for live tests.
Only V02-J libfido2 acquisition sees a hardware PRF result. No result,
credential ID, public key, RP, challenge, PIN or HID path appears in the
shareable receipt. These local observations do not close OPEN-15/01.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile

# Support Python -I without admitting current-working-directory imports.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import fido2_v02j as j

SCHEMA = "vaulty-v02l-redacted-negative-evidence-v1"
REJECTED = "LOCAL_VERIFIER_REJECTED"
ACCEPTED = "UNEXPECTEDLY_ACCEPTED"
UNCERTAIN = "INDETERMINATE"
EXACT_VERIFIER_FAILURE = "FIDO2 tool reported failure (PIN/touch/device or invalid assertion)"
# This probe only protects test inputs; the real daemon must independently
# implement authorization, replay cache, registry and generation-bound policy.
CASES = ("wrong_challenge", "wrong_rp", "tampered_authenticator_data",
         "tampered_signature", "wrong_public_key")
FLAGS = 0x05  # signed authenticator-data UP (0x01) + UV (0x04)


def _source_head() -> str:
    root = Path(__file__).resolve().parents[2]
    try:
        head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                              capture_output=True, check=True, timeout=10)
        dirty = subprocess.run(["git", "-C", str(root), "status", "--porcelain"],
                               capture_output=True, check=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        raise j.ProbeError("clean Git checkout required for source-pinned evidence") from None
    sha = head.stdout.decode("ascii", "strict").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or dirty.stdout:
        raise j.ProbeError("clean Git checkout required for source-pinned evidence")
    return sha


def _live_gate(device: str | None, *, require_device: bool) -> None:
    if os.geteuid() == 0:
        raise j.ProbeError("do not execute live hardware probes as root")
    if (os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS")
            or os.environ.get("FORGEJO_ACTIONS")):
        raise j.ProbeError("hardware tests forbidden in CI")
    if not sys.platform.startswith("linux") or not sys.stdin.isatty() or not sys.stdout.isatty():
        raise j.ProbeError("Linux interactive operator console required")
    if device is None or not j.DEVICE.fullmatch(device):
        raise j.ProbeError("explicit /dev/hidrawN path required")
    if require_device:
        try:
            info = os.stat(device, follow_symlinks=False)
        except OSError:
            raise j.ProbeError("selected device missing") from None
        if not stat.S_ISCHR(info.st_mode) or Path(device).is_symlink():
            raise j.ProbeError("selected device is not a direct character device")
    else:
        if os.path.lexists(device):
            raise j.ProbeError("path still present: no absent-device precheck recorded")
    j._tool("fido2-assert")
    j._tool("fido2-cred")


def _confirm(label: str) -> None:
    print("TEST-ONLY: no Vaulty credentials; enter the correct PIN only if prompted.")
    print("This does not test wrong PIN attempts or PIN retry exhaustion.")
    print("Confirm the connected test token is the selected device.")
    response = input("Type TEST to authorize this hardware operation: ")
    if response != "TEST":
        raise j.ProbeError("operator declined hardware test")


def _decode_cbor_authenticator_data(encoded: bytes) -> bytes:
    """Decode the *single*, definite CBOR byte string emitted by fido2-assert.

    libfido2's fido_assert_authdata_ptr() contains the CBOR byte-string
    wrapper; the -G CLI prints its base64 representation (37 bytes => 58 25
    followed by the 37 raw WebAuthn bytes). The -V CLI wants that ORIGINAL
    CBOR encoding. Never feed decoded bytes to the signature verifier.
    Reject raw bytes, indefinite strings, nonminimal length, and trailing
    encoded objects rather than guessing their meaning.
    """
    if not encoded or encoded[0] >> 5 != 2:
        raise j.ProbeError("expected CBOR byte-string authenticator data")
    additional = encoded[0] & 0x1f
    if additional < 24:
        offset, size = 1, additional
    elif additional == 24:
        if len(encoded) < 2:
            raise j.ProbeError("truncated CBOR byte-string length")
        offset, size = 2, encoded[1]
        if size < 24:
            raise j.ProbeError("noncanonical CBOR byte-string length")
    elif additional == 25:
        if len(encoded) < 3:
            raise j.ProbeError("truncated CBOR byte-string length")
        offset, size = 3, int.from_bytes(encoded[1:3], "big")
        if size < 256:
            raise j.ProbeError("noncanonical CBOR byte-string length")
    else:
        # Current V02-J _unb64 input bound is <=1024 decoded bytes. Longer,
        # indefinite and reserved/unsupported length encodings fail closed.
        raise j.ProbeError("unsupported CBOR byte-string length")
    if size < 37:
        raise j.ProbeError("authenticator data too short")
    if len(encoded) != offset + size:
        raise j.ProbeError("CBOR byte-string length mismatch or trailing data")
    return encoded[offset:]


def _require_signed_flags(cbor_authdata: bytes, rp_id: str) -> None:
    # Parse fields for early fail-closed checks, but do not trust them until
    # the ORIGINAL CBOR string is verified under the registered public key.
    data = _decode_cbor_authenticator_data(cbor_authdata)
    if data[:32] != hashlib.sha256(rp_id.encode("utf-8")).digest():
        raise j.ProbeError("signed RP hash mismatch")
    if data[32] & FLAGS != FLAGS:
        raise j.ProbeError("missing UP or UV in authenticator data")


def _mutate_b64(value: str, *, offset: int) -> str:
    buf = bytearray(j._unb64(value))
    if offset >= len(buf):
        raise j.ProbeError("malformed signed assertion test field")
    buf[offset] ^= 0x01
    try:
        return j._b64(buf)
    finally:
        j.wipe(buf)


def _verify(public_key_file: Path, fields: list[str]) -> None:
    # -V with public ES256 key, signed challenge/RP/authenticator data/signature.
    # Strict UP/UV policy is demanded for every *accepted* verifier operation.
    j._run([j._tool("fido2-assert"), "-V", "-h", "-p", "-v",
            str(public_key_file), "es256"],
           data=("\n".join(fields) + "\n").encode("ascii"), timeout=15)


def _expect_rejection(public_key_file: Path, fields: list[str]) -> str:
    try:
        _verify(public_key_file, fields)
    except j.ProbeError as exc:
        # A timeout, missing executable, I/O error, etc. is not a verified
        # negative. We only classify the local verifier's nonzero exit.
        return REJECTED if str(exc) == EXACT_VERIFIER_FAILURE else UNCERTAIN
    except (OSError, UnicodeError):
        return UNCERTAIN
    return ACCEPTED


def _receipt(source: str, mode: str) -> dict:
    return {
        "schema": SCHEMA,
        "source_git_commit": source,
        "review_only": True,
        "local_self_report_only": True,
        "mode": mode,
        "status": "INCOMPLETE",
        "cases": {},
        "physical_key_uniqueness_verified": False,
        "production_runtime_replay_protection_tested": False,
        "actual_invalid_pin_attempted": False,
        "actual_uv_absent_signed_assertion_tested": False,
        "browser_webauthn_tested": False,
        "entry_route_ready": False,
        "i_p04": "PARTIAL",
        "i_p06": "PARTIAL",
        "open_15": "BLOCKED",
        "open_01": "BLOCKED",
        "release_gates": "G1-G3 BLOCKED",
    }


def _session(path: str) -> dict:
    session = j._read_session(Path(path))
    if not session.get("credentials") or session.get("schema") != j.SCHEMA:
        raise j.ProbeError("use an existing private V02-J/K test session")
    return session


def _credential(s: dict, role: str) -> dict:
    credential = s["credentials"].get(role)
    if (not isinstance(credential, dict)
            or credential.get("test_only") is not True
            or credential.get("attestation_chain_verified") is not False
            or credential.get("rp_id") != s["rp_id"]):
        raise j.ProbeError("missing/untrusted synthetic credential for role")
    if not j._unb64(credential.get("credential_id_b64", "")):
        raise j.ProbeError("empty synthetic credential")
    if "-----BEGIN PUBLIC KEY-----" not in credential.get("public_key_pem", ""):
        raise j.ProbeError("missing synthetic public key")
    return credential


def verifier_negatives(session: dict, role: str, device: str) -> dict:
    """One real UV-backed assertion, positive verification, and local -V mutants.

    No server replay cache or real missing-UV assertion is claimed. RP/flags
    byte checks alone cannot establish a token signature without -V.
    """
    credential = _credential(session, role)
    other = _credential(session, "backup" if role == "primary" else "primary")
    if credential["public_key_pem"] == other["public_key_pem"]:
        raise j.ProbeError("test public keys must be independently distinct")
    challenge = secrets.token_bytes(32)
    _, salt = j._context(session, role, "alpha", purpose=1, assurance=1)
    request = ("\n".join((j._b64(challenge), session["rp_id"],
                          credential["credential_id_b64"], j._b64(salt))) + "\n").encode("ascii")
    with tempfile.TemporaryDirectory(prefix="vaulty-v02l-public-") as tmp:
        req_path = j._private_input(tmp, "request.txt", request)
        raw = j._run([j._tool("fido2-assert"), "-G", "-h", "-p", "-v",
                      "-t", "uv=true", "-i", str(req_path), device],
                     interactive=True)
        # V02-J's parser consumes the PRF but returns no value outside this scope.
        secret = j._assertion_result(raw, challenge=challenge, rp_id=session["rp_id"])
        try:
            signed = j._lines(raw, 5)[:4]  # Never persist/print the fifth PRF line.
            _require_signed_flags(j._unb64(signed[2]), session["rp_id"])
            key = j._private_input(tmp, "registered-test-public.pem",
                                   credential["public_key_pem"].encode("ascii"))
            other_key = j._private_input(tmp, "other-test-public.pem",
                                         other["public_key_pem"].encode("ascii"))
            _verify(key, signed)  # This must succeed before any negative counts.
            mutations = {
                "wrong_challenge": [j._b64(secrets.token_bytes(32)), *signed[1:]],
                "wrong_rp": [signed[0], "invalid.localhost", *signed[2:]],
                "tampered_authenticator_data": [signed[0], signed[1],
                                                 _mutate_b64(signed[2], offset=34), signed[3]],
                "tampered_signature": [*signed[:3],
                                       _mutate_b64(signed[3], offset=0)],
                "wrong_public_key": signed,
            }
            results = {}
            for case, altered in mutations.items():
                results[case] = _expect_rejection(other_key if case == "wrong_public_key" else key,
                                                  altered)
            return {"positive_signed_up_uv": "OBSERVED", **results}
        finally:
            j.wipe(secret)


def wrong_device_probe(session: dict, target_role: str, control_role: str,
                       device: str) -> dict:
    """Run two successful controls around one unauthorized-credential attempt.

    A generic -G rejection is unclassified and is never proof of a specific
    cryptographic reason or that the operator plugged two distinct devices.
    """
    if target_role == control_role or set((target_role, control_role)) != set(j.ROLES):
        raise j.ProbeError("target and control must be different registered roles")
    for role in (target_role, control_role):
        _credential(session, role)

    def control() -> None:
        value = j._measure(session, control_role, "alpha", device, "uv")
        j.wipe(value)
    control()
    result = UNCERTAIN
    try:
        wrong_value = j._measure(session, target_role, "alpha", device, "uv")
    except j.ProbeError as exc:
        result = ("LOCAL_DEVICE_REJECTION_UNCLASSIFIED"
                  if str(exc) == EXACT_VERIFIER_FAILURE else UNCERTAIN)
    else:
        j.wipe(wrong_value)
        result = ACCEPTED
    # The control must still work *after* the failed attempt; no result on
    # transport failures, bad PIN, different device or unplug mid-test.
    control()
    return {"control_before": "OBSERVED", "target_credential_on_other_key": result,
            "control_after": "OBSERVED"}


def run_live(args: argparse.Namespace) -> int:
    if not args.hardware_test:
        raise j.ProbeError("explicit --hardware-test required")
    _live_gate(args.device, require_device=args.mode != "unavailable")
    source = _source_head()
    session = None if args.mode == "unavailable" else _session(args.session)
    if session is not None:
        _credential(session, args.role)
    _confirm(args.mode)
    receipt_path = j._safe_path(args.receipt)
    report = _receipt(source, args.mode)
    j._private_write(receipt_path, report, new=True)
    try:
        if args.mode == "verifier":
            results = verifier_negatives(session, args.role, args.device)
        elif args.mode == "wrong-device":
            results = wrong_device_probe(session, args.role, args.control_role, args.device)
        elif args.mode == "unavailable":
            # Never call a device command: absence is a preflight guard only,
            # not a signed factor-verification test of the future daemon.
            results = {"missing_path_precheck": "LOCAL_PRECHECK_REJECTED"}
        else:
            raise j.ProbeError("unsupported test mode")
        report["cases"] = results
        report["status"] = (
            "LOCAL_NEGATIVE_OBSERVATIONS_CAPTURED"
            if args.mode == "verifier" and results["positive_signed_up_uv"] == "OBSERVED"
               and all(results.get(k) == REJECTED for k in CASES)
            else "LOCAL_DEVICE_REJECTION_OBSERVED"
            if args.mode == "wrong-device"
               and results.get("target_credential_on_other_key") == "LOCAL_DEVICE_REJECTION_UNCLASSIFIED"
            else "LOCAL_ABSENCE_PRECHECK_OBSERVED" if args.mode == "unavailable"
            else "LOCAL_MISMATCH_OR_INDETERMINATE"
        )
        j._private_write(receipt_path, report)
        return 0 if report["status"] in (
            "LOCAL_NEGATIVE_OBSERVATIONS_CAPTURED",
            "LOCAL_DEVICE_REJECTION_OBSERVED",
            "LOCAL_ABSENCE_PRECHECK_OBSERVED",
        ) else 2
    except (j.ProbeError, OSError):
        # A partial shareable report remains INCOMPLETE. Failure diagnostics
        # are generic to avoid exposing HID paths or CLI stdout/stderr.
        return 2
    finally:
        print("Share only the V02-L redacted receipt. Do not share private sessions, "
              "PRF, PINs, signed raw assertions or device paths.")
        print("No READY entry, OPEN-15/01 approval or G1–G3 release is implied.")


def parse(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    sub.add_parser("preflight", help="No hardware commands")
    for mode in ("verifier", "wrong-device", "unavailable"):
        p = sub.add_parser(mode, help="Explicit operator-only physical negative test")
        if mode != "unavailable":
            p.add_argument("--session", required=True)
            p.add_argument("--role", required=True, choices=j.ROLES)
        if mode == "wrong-device":
            p.add_argument("--control-role", required=True, choices=j.ROLES)
        p.add_argument("--device", required=True)
        p.add_argument("--receipt", required=True)
        p.add_argument("--hardware-test", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse(argv)
    if args.mode == "preflight":
        print(json.dumps({
            "review_only": True,
            "hardware_tests_executed": False,
            "fido2_assert_installed": bool(j.shutil.which("fido2-assert")),
            "fido2_cred_installed": bool(j.shutil.which("fido2-cred")),
            "open_15_approved": False,
        }, sort_keys=True))
        return 0
    try:
        result = run_live(args)
        if result:
            print("V02-L local test blocked, failed or inconclusive; receipt incomplete or mismatch.",
                  file=sys.stderr)
        else:
            print("V02-L local test observations recorded (NOT independent verification).")
        return result
    except (j.ProbeError, OSError, EOFError, KeyboardInterrupt):
        print("V02-L test blocked/cancelled: check opt-in, test session, terminal and device. "
              "No hardware security approval.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
