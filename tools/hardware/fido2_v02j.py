#!/usr/bin/env python3
"""V02-J isolated, opt-in libfido2 hardware *verification harness*.

NOT Vaulty runtime authentication. Never use actual vault credentials.
No token commands in CI and no automatic device selection. Real operations
require explicit --hardware-test on the local operator machine.

Only test credential IDs/public keys and synthetic UUIDs persist. Physical
hmac-secret outputs remain in Python process memory briefly for comparison,
are never printed, logged or written to disk. Python and external CLI buffers
cannot guarantee comprehensive zeroization: NOT production secret handling.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import secrets
import shutil
import subprocess
import sys
import tempfile
import uuid

# Avoid adding Python FIDO2 packages to the production dependency graph.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "v02_verifier"))
import reference_v02i_prf as prf  # noqa: E402

SCHEMA = "vaulty-v02j-local-hardware-session-v1"
RECEIPT_SCHEMA = "vaulty-v02j-observation-v1"
TEST_IDS = tuple(f"I-P{i:02d}" for i in range(1, 10))
ROLES = ("primary", "backup")
ENTRIES = ("alpha", "beta")
DEVICE = re.compile(r"^/dev/hidraw\d+$")
RP = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
MAX_CLI_OUTPUT = 8192


class ProbeError(ValueError):
    """Non-sensitive failure only. Never attach tool stdout/stderr."""


def _safe_path(path: str | Path) -> Path:
    # Refuse any symlink in *all* ancestors, not just the immediate parent,
    # and reject lexical and resolved repository containment. This function
    # protects public-but-linkable synthetic credential metadata, not secrets.
    out = Path(path).expanduser().absolute()
    repository = Path(__file__).resolve().parents[2]
    try:
        resolved = out.resolve(strict=False)
    except (OSError, RuntimeError):
        raise ProbeError("cannot safely resolve session/evidence path") from None
    for candidate in (out, resolved):
        if candidate == repository or repository in candidate.parents:
            raise ProbeError("session and evidence must live outside the repository")
    if out.is_symlink():
        raise ProbeError("refusing symlink session/evidence")
    parent = out.parent
    if not parent.is_dir():
        raise ProbeError("private session parent directory must exist")
    for ancestor in (parent, *parent.parents):
        if ancestor.is_symlink():
            raise ProbeError("symlinked directory ancestors are forbidden")
        try:
            info = ancestor.stat(follow_symlinks=False)
        except OSError:
            raise ProbeError("invalid parent directory") from None
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid()):
            raise ProbeError("untrusted parent directory")
        # /tmp may be root-owned and sticky. Other group/world-writable
        # ancestors are unsafe even when the final path is private.
        if info.st_mode & 0o022:
            if not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
                raise ProbeError("writable ancestor without trusted sticky root owner")
    info = parent.stat(follow_symlinks=False)
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ProbeError("immediate session parent must be owned by user and mode 0700")
    if out.exists():
        info = out.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ProbeError("existing file must be user-owned regular mode 0600")
    return out


def _private_write(path: Path, data: dict, *, new: bool = False) -> None:
    encoded = (json.dumps(data, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(encoded) > 16384:
        raise ProbeError("session/receipt too large")
    _safe_path(path)
    if new:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return
    # Atomic update; temporary file also private; never follow existing links.
    fd, tmp = tempfile.mkstemp(prefix=".vaulty-v02j-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def _read_session(path: Path) -> dict:
    path = _safe_path(path)
    # An attacker cannot replace the final file with a symlink between a
    # path check and a read: open the descriptor O_NOFOLLOW and fstat it.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077 or info.st_size > 16384):
                raise ProbeError("unsafe or oversized test session")
            raw = stream.read(16385)
            if len(raw) > 16384:
                raise ProbeError("oversized test session")
        s = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ProbeError("cannot read private test session") from None
    if not isinstance(s, dict) or s.get("schema") != SCHEMA or s.get("review_only") is not True:
        raise ProbeError("wrong/malformed synthetic test session")
    if set(s.get("entries", {})) != set(ENTRIES) or not isinstance(s.get("credentials"), dict):
        raise ProbeError("invalid session shape")
    return s


def initialize(rp_id: str) -> dict:
    if not RP.fullmatch(rp_id) or len(rp_id) > 253 or ".." in rp_id or "." not in rp_id:
        raise ProbeError("use a valid, operator-controlled test RP ID")
    # The caller controls RP registration and browser origin for local tests.
    return {
        "schema": SCHEMA, "review_only": True, "rp_id": rp_id,
        "vault_id": str(uuid.uuid4()),
        "entries": {name: {
            "id": str(uuid.uuid4()),
            "slots": {role: str(uuid.uuid4()) for role in ROLES},
        } for name in ENTRIES},
        "credentials": {},
    }


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    if len(value) > 1024:
        raise ProbeError("oversized base64 field")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error):
        raise ProbeError("malformed tool or test profile data") from None


def _run(args: list[str], *, data: bytes | None = None,
         timeout: int = 90, interactive: bool = False) -> bytes:
    # No shell. stderr is never included in an exception/receipt. Device
    # acquisition with -i request file can inherit stdin for PIN prompts.
    # stderr is inherited only for interactive prompts (never -d debug).
    try:
        call = subprocess.run(
            args, input=data, stdout=subprocess.PIPE,
            stderr=None if interactive else subprocess.DEVNULL,
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ProbeError("FIDO2 tool unavailable, timed out or device removed") from None
    if call.returncode != 0:
        raise ProbeError("FIDO2 tool reported failure (PIN/touch/device or invalid assertion)")
    if len(call.stdout) > MAX_CLI_OUTPUT:
        raise ProbeError("excessive FIDO2 output; discard result")
    return call.stdout


def _tool(name: str) -> str:
    binary = shutil.which(name)
    if binary is None:
        raise ProbeError(f"required libfido2 command not installed: {name}")
    return binary


def _hardware_gate(device: str) -> None:
    if os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS") or os.environ.get("FORGEJO_ACTIONS"):
        raise ProbeError("physical FIDO2 operation refused in CI")
    if not DEVICE.fullmatch(device) or not Path(device).exists():
        raise ProbeError("explicit existing Linux /dev/hidrawN device required")
    if not sys.stdin.isatty():
        raise ProbeError("real hardware operations require an interactive terminal")
    _tool("fido2-assert")
    _tool("fido2-cred")


def _lines(raw: bytes, count: int) -> list[str]:
    if b"\x00" in raw or len(raw) > MAX_CLI_OUTPUT:
        raise ProbeError("malformed FIDO2 output")
    try:
        lines = raw.decode("utf-8").strip().splitlines()
    except UnicodeDecodeError:
        raise ProbeError("malformed FIDO2 output") from None
    if len(lines) != count:
        raise ProbeError("unexpected FIDO2 line count")
    return lines


def _private_input(directory: str, name: str, value: bytes) -> Path:
    # Only public challenge/RP/credential ID/salt are written here.
    path = Path(directory) / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(value)
    return path


def register_credential(session: dict, role: str, device: str) -> dict:
    """Create a *new test-only* nonresident credential and verify its public
    attestation record; this does NOT validate the manufacturer's trust chain.
    """
    if role not in ROLES or role in session["credentials"]:
        raise ProbeError("unknown or already registered role")
    challenge = secrets.token_bytes(32)
    user_id = secrets.token_bytes(32)
    request = ("\n".join((_b64(challenge), session["rp_id"],
                          f"vaulty-v02j-{role}", _b64(user_id))) + "\n").encode("ascii")
    # No private keys, passwords or PRF values ever go to a file.
    with tempfile.TemporaryDirectory(prefix="vaulty-v02j-public-") as directory:
        request_file = _private_input(directory, "make-credential.txt", request)
        made = _run([_tool("fido2-cred"), "-M", "-h", "-v",
                     "-i", str(request_file), device, "es256"],
                    interactive=True)
    # libfido2 verification explicitly checks UV and the extension bit.
    verified = _run([_tool("fido2-cred"), "-V", "-h", "-v", "es256"], data=made)
    # -V output format: credential-id line + PEM encoded public key.
    try:
        txt = verified.decode("ascii")
        first, pub = txt.split("\n", 1)
        identifier = _unb64(first)
    except (ValueError, UnicodeDecodeError):
        raise ProbeError("invalid verified test credential format") from None
    if not 1 <= len(identifier) <= 128 or "-----BEGIN PUBLIC KEY-----" not in pub or "-----END PUBLIC KEY-----" not in pub:
        raise ProbeError("invalid verified credential ID / public key")
    if any(existing.get("credential_id_b64") == first for existing in session["credentials"].values()):
        raise ProbeError("duplicate registered test credential identity")
    out = copy.deepcopy(session)
    out["credentials"][role] = {
        "credential_id_b64": first,
        "public_key_pem": pub,
        "rp_id": session["rp_id"],
        "test_only": True,
        "attestation_chain_verified": False,
    }
    return out


def _context(session: dict, role: str, entry: str, *, purpose: int,
             assurance: int) -> tuple[bytes, bytes]:
    if role not in ROLES or entry not in ENTRIES:
        raise ProbeError("unknown test role or entry")
    cred = session["credentials"].get(role)
    if cred is None or cred.get("test_only") is not True or cred.get("rp_id") != session["rp_id"]:
        raise ProbeError("credential not separately registered in this test session")
    ent = session["entries"][entry]
    credential = _unb64(cred["credential_id_b64"])
    rp_hash = hashlib.sha256(session["rp_id"].encode("utf-8")).digest()
    try:
        desc = {
            "vault": uuid.UUID(session["vault_id"]).bytes,
            "slot": uuid.UUID(ent["slots"][role]).bytes,
            "target": 3, "target_id": uuid.UUID(ent["id"]).bytes,
            "purpose": purpose, "tier": 2,
            "scope": 3, "owner": uuid.UUID(ent["id"]).bytes,
            "credential": credential, "rp": rp_hash,
            "assurance": assurance,
        }
        raw = prf.encode_context(desc)
        return raw, prf.ctap_salt(desc)
    except (ValueError, KeyError, TypeError) as exc:
        raise ProbeError("invalid test-only PRF scope") from None


def _assertion_result(data: bytes, *, challenge: bytes, rp_id: str) -> bytearray:
    # This harness only handles nonresident credentials; no optional user-id
    # or largeBlobKey output is requested, so five lines are mandatory.
    fields = _lines(data, 5)
    if not hmac.compare_digest(_unb64(fields[0]), challenge) or fields[1] != rp_id:
        raise ProbeError("challenge/RP mismatch in FIDO2 response")
    if not _unb64(fields[2]) or not _unb64(fields[3]):
        raise ProbeError("missing authenticator data/signature")
    secret = _unb64(fields[4])
    if len(secret) != 32:
        raise ProbeError("hmac-secret result is not 32 bytes")
    return bytearray(secret)


def _measure(session: dict, role: str, entry: str, device: str,
             assurance: str) -> bytearray:
    if assurance not in ("uv", "touch-only"):
        raise ProbeError("unsupported test-only assurance profile")
    mode = 1 if assurance == "uv" else 2
    _raw, salt = _context(session, role, entry, purpose=1, assurance=mode)
    challenge = secrets.token_bytes(32)
    cred = session["credentials"][role]
    request = ("\n".join((_b64(challenge), session["rp_id"],
                          cred["credential_id_b64"], _b64(salt))) + "\n").encode("ascii")
    # UV branch requires -v both when obtaining and when verifying the
    # signed assertion. UP-only is *experimental*; -p proves presence but
    # does NOT establish that UV=false, even if requested.
    flags = ["-h", "-p"]
    if assurance == "uv":
        flags += ["-v", "-t", "uv=true"]
    else:
        flags += ["-t", "uv=false", "-t", "pin=false"]
    secret: bytearray | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="vaulty-v02j-public-") as directory:
            request_path = _private_input(directory, "assertion-request.txt", request)
            generated = _run([_tool("fido2-assert"), "-G", *flags,
                              "-i", str(request_path), device], interactive=True)
            secret = _assertion_result(generated, challenge=challenge,
                                       rp_id=session["rp_id"])
            key_path = _private_input(directory, "public.pem",
                                      cred["public_key_pem"].encode("ascii"))
            fields = _lines(generated, 5)
            verify = ("\n".join(fields[:4]) + "\n").encode("ascii")
            opts = ["-V", "-h", "-p"] + (["-v"] if assurance == "uv" else [])
            _run([_tool("fido2-assert"), *opts, str(key_path), "es256"],
                 data=verify)
        # Transfer ownership of the mutable value to probe() only after the
        # verifier returned success AND all temporary-file cleanup finished.
        result = secret
        secret = None
        return result
    except BaseException:
        if secret is not None:
            wipe(secret)
        raise

def wipe(buffer: bytearray) -> None:
    for i in range(len(buffer)):
        buffer[i] = 0


def probe(session: dict, role: str, entry: str, device: str,
          *, compare_entry: str | None = None, assurance: str = "uv") -> dict:
    """Two independent signed assertions with the same UV salt are required.
    A third compares a different entry. Never persist/output PRF values.
    """
    if compare_entry is not None and (compare_entry == entry or compare_entry not in ENTRIES):
        raise ProbeError("comparison entry must be a different synthetic entry")
    values: list[bytearray] = []
    try:
        values.append(_measure(session, role, entry, device, assurance))
        values.append(_measure(session, role, entry, device, assurance))
        same = hmac.compare_digest(values[0], values[1])
        different = None
        if compare_entry is not None:
            values.append(_measure(session, role, compare_entry, device, assurance))
            different = not hmac.compare_digest(values[0], values[2])
        return {
            "schema": RECEIPT_SCHEMA,
            "review_only": True,
            "device_execution": "OBSERVED",
            "full_i_p01_to_i_p09_matrix": "NOT_EXECUTED",
            "operation": "signed_native_ctap_test_assertions",
            "signature_and_requested_flags_checked": True,
            "assurance_requested": assurance,
            "uv_absence_verified": False,  # -t uv=false is a request, not proof
            "repeat_prf_stable": same,
            "different_entry_prf_distinct": different,
            "entry_route_ready": False,
            "open_15_approved": False,
            "open_01_approved": False,
        }
    finally:
        for value in values:
            wipe(value)


def _args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="operation", required=True)
    init = sub.add_parser("init", help="Create synthetic two-entry / two-key test session")
    init.add_argument("--session", required=True)
    init.add_argument("--rp-id", required=True)
    sub.add_parser("preflight", help="Report local libfido2 availability without accessing tokens")
    for name in ("register", "probe"):
        subp = sub.add_parser(name, help="Explicit local physical device operation (test-only)")
        subp.add_argument("--session", required=True)
        subp.add_argument("--role", required=True, choices=ROLES)
        subp.add_argument("--device", required=True)
        subp.add_argument("--hardware-test", action="store_true", required=True)
        if name == "probe":
            subp.add_argument("--entry", required=True, choices=ENTRIES)
            subp.add_argument("--compare-entry", choices=ENTRIES)
            subp.add_argument("--assurance", choices=("uv", "touch-only"), default="uv")
            subp.add_argument("--acknowledge-unapproved-touch-only", action="store_true")
            subp.add_argument("--receipt", required=True)
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    a = _args(argv)
    try:
        if a.operation == "preflight":
            print(json.dumps({
                "review_only": True, "hardware_tests_executed": False,
                "fido2_cred_installed": bool(shutil.which("fido2-cred")),
                "fido2_assert_installed": bool(shutil.which("fido2-assert")),
                "fido2_token_installed": bool(shutil.which("fido2-token")),
                "open_15_approved": False,
            }, sort_keys=True))
            return 0
        path = _safe_path(a.session)
        if a.operation == "init":
            _private_write(path, initialize(a.rp_id), new=True)
            print("Created private synthetic session (no hardware operations).")
            return 0
        if not a.hardware_test:
            raise ProbeError("missing explicit --hardware-test")
        _hardware_gate(a.device)
        s = _read_session(path)
        if a.operation == "register":
            amended = register_credential(s, a.role, a.device)
            _private_write(path, amended)
            print("Test credential created; registration is NOT trusted vault enrollment.")
            return 0
        if a.assurance == "touch-only" and not a.acknowledge_unapproved_touch_only:
            raise ProbeError("UP-only is an unapproved experimental profile; acknowledge explicitly")
        result = probe(s, a.role, a.entry, a.device,
                       compare_entry=a.compare_entry, assurance=a.assurance)
        dest = _safe_path(a.receipt)
        _private_write(dest, result, new=True)
        print("Signed test assertion observations recorded (no PRF values, no OPEN-15 approval).")
        return 0
    except ProbeError as exc:
        print(f"V02-J test-only operation blocked/failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
