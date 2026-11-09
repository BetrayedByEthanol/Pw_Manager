#!/usr/bin/env python3
"""V03-D — operator-only, redacted Linux lifecycle observation intake.

This is local review evidence, NOT a production daemon / release approval.
The subprocess uses the separately isolated Rust zbus review runner with a
CLOSED V03 session. It never accesses vault files, PINs, PRF outputs, or keys.
A screen lock or sleep must be initiated by the operator separately; this
script deliberately never triggers OS suspend or restarts logind.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import sys
import time
from typing import Callable

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "tools/lifecycle/v03c_rust/Cargo.toml"
SCHEMA = "vaulty-v03d-redacted-linux-lifecycle-evidence-v1"
READY = "V03-C: OBSERVER_READY; no session or credential authorized"
FINISHED = "V03-C: OBSERVED_ONLY; no session or credential authorized"
EXIT = re.compile(r"^V03-C: FAIL_CLOSED: ([A-Z][A-Z0-9_]{0,63}); no session or credential authorized$", re.M)
SAFE_REASONS = frozenset({
    "SESSION_LOCK", "SESSION_UNLOCK", "SLEEP_START", "SLEEP_END",
    "SHUTDOWN_START", "SHUTDOWN_END", "SESSION_REMOVED",
    "LOGIND_OWNER_CHANGED", "BUS_DISCONNECTED", "MALFORMED_SIGNAL",
    "SNAPSHOT_REJECTED", "SESSION_MISMATCH", "WATCHDOG_EXPIRED",
})
EXPECTED = {
    "baseline": None,
    "lock": frozenset({"SESSION_LOCK"}),
    "suspend": frozenset({"SLEEP_START"}),
    "disconnect": frozenset({"BUS_DISCONNECTED", "LOGIND_OWNER_CHANGED"}),
}


class Refused(Exception):
    pass


def classify(mode: str, code: int, stdout: str, stderr: str) -> tuple[str, str]:
    """Only a completed READY handshake permits an observation receipt.

    The exact two-line success protocol is required for baseline. Terminal
    event tests require the READY line and a single expected failure category
    with exit code 2. No extra stdout/stderr content is evidence.
    """
    lines = stdout.splitlines()
    if not lines or lines[0] != READY:
        return "INCOMPLETE", "READINESS_NOT_OBSERVED"
    if mode == "baseline" and code == 0 and lines == [READY, FINISHED] and not stderr.strip():
        return "LOCAL_IDLE_OBSERVATION_REPORTED", "NONE"
    match = EXIT.fullmatch(stderr.strip())
    reason = (match.group(1) if match and match.group(1) in SAFE_REASONS
              else "UNCLASSIFIED")
    if (mode != "baseline" and code == 2 and lines == [READY]
            and reason in EXPECTED[mode]):
        return "LOCAL_TERMINAL_EVENT_REPORTED", reason
    return "INCOMPLETE", reason


def await_observer_ready(
    process: subprocess.Popen[bytes], deadline_seconds: float,
) -> tuple[bool, bytes, str]:
    """Wait for a flushed, exact, length-bounded readiness line.

    The Rust runner may fail its startup snapshot/inhibitor before this line;
    no operator action is requested on that path. Only stdout is consumed
    here; the runner's stderr is one fixed result line after termination.
    """
    assert process.stdout is not None
    deadline = time.monotonic() + deadline_seconds
    buffered = bytearray()
    while time.monotonic() < deadline:
        available, _, _ = select.select(
            [process.stdout], [], [], max(0.0, deadline - time.monotonic()),
        )
        if not available:
            return False, b"", "READINESS_TIMEOUT"
        chunk = os.read(process.stdout.fileno(), 256)
        if not chunk:
            return False, b"", "READINESS_NOT_OBSERVED"
        buffered.extend(chunk)
        if len(buffered) > 512:
            return False, b"", "READINESS_PROTOCOL_INVALID"
        if b"\n" in buffered:
            first, remainder = bytes(buffered).split(b"\n", 1)
            if first != READY.encode("ascii"):
                return False, b"", "READINESS_PROTOCOL_INVALID"
            return True, remainder, "NONE"
    return False, b"", "READINESS_TIMEOUT"


def run_observation(
    command: list[str], mode: str, seconds: int, *,
    readiness_timeout: float = 25.0,
    on_ready: Callable[[], None] | None = None,
) -> tuple[str, str, int, bool, bool]:
    """Run reviewed binary and prompt *only after* its READY handshake.

    All pre-ready failures and timeouts stay INCOMPLETE. No raw subprocess
    output is printed, stored in receipts, or interpreted as hardware proof.
    Tests may inject a synthetic subprocess command, never real keys.
    """
    process = subprocess.Popen(
        command, cwd=ROOT, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
    )
    ready = False
    prompted = False
    try:
        ready, prefix, problem = await_observer_ready(process, readiness_timeout)
        if not ready:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)
            return "INCOMPLETE", problem, process.returncode or -1, False, False

        # A subprocess that already stopped after READY cannot wait for the
        # operator. It must not produce a credited terminal event receipt.
        if process.poll() is not None:
            process.communicate(timeout=5)
            return "INCOMPLETE", "OBSERVER_EXITED_BEFORE_ACTION", process.returncode or -1, True, False

        if on_ready is not None:
            on_ready()
            prompted = mode != "baseline"

        remaining_stdout, stderr = process.communicate(timeout=seconds + 10)
        stdout = READY + "\n" + (prefix + remaining_stdout).decode("ascii", errors="replace")
        status, reason = classify(
            mode, process.returncode, stdout, stderr.decode("ascii", errors="replace"),
        )
        return status, reason, process.returncode, True, prompted
    except subprocess.TimeoutExpired:
        return "INCOMPLETE", "PROCESS_TIMEOUT", -1, ready, prompted
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)


def git_source() -> str:
    command = ["git", "-C", str(ROOT)]
    sha = subprocess.run(command + ["rev-parse", "HEAD"], check=True,
                         capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(command + ["status", "--porcelain"],
                           check=True, capture_output=True, text=True).stdout
    if dirty:
        raise Refused("GIT_NOT_CLEAN")
    if not re.fullmatch(r"[a-f0-9]{40}", sha):
        raise Refused("INVALID_SOURCE_SHA")
    return sha


def build_binary() -> Path:
    subprocess.run(["cargo", "build", "--manifest-path", str(MANIFEST),
                    "--locked", "--quiet"], cwd=ROOT, check=True, timeout=300)
    meta = subprocess.run(
        ["cargo", "metadata", "--manifest-path", str(MANIFEST),
         "--locked", "--no-deps", "--format-version", "1"],
        cwd=ROOT, check=True, capture_output=True, text=True, timeout=30,
    )
    target = Path(json.loads(meta.stdout)["target_directory"])
    binary = target / "debug/vaulty-v03c-logind-review"
    if not binary.is_file():
        raise Refused("REVIEW_BINARY_MISSING")
    return binary


def private_parent(path: Path) -> None:
    if path.is_symlink() or path.exists():
        raise Refused("RECEIPT_EXISTS")
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink():
        raise Refused("EVIDENCE_DIRECTORY_MISSING_OR_SYMLINK")
    info = parent.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise Refused("EVIDENCE_DIRECTORY_NOT_PRIVATE")


def write_new(path: Path, payload: dict) -> None:
    private_parent(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as dest:
        json.dump(payload, dest, sort_keys=True, indent=2)
        dest.write("\n")
        dest.flush()
        os.fsync(dest.fileno())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=EXPECTED, required=True)
    parser.add_argument("--seconds", type=int, default=30)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--hardware-test", action="store_true",
                        help="Explicit approval for a local Linux desktop observation")
    args = parser.parse_args()
    if not args.hardware_test:
        parser.error("explicit --hardware-test is required")
    if not (5 <= args.seconds <= 60) or sys.platform != "linux" or os.geteuid() == 0:
        parser.error("non-root Linux and 5..60 seconds required")
    try:
        private_parent(args.receipt)
        sha = git_source()
        print("TEST-ONLY, NO CREDENTIALS: this captures local self-reported "
              "Linux lifecycle events, NOT a secure vault unlock.", flush=True)
        print("No automatic OS power action will occur.", flush=True)
        confirmation = input("Type TEST to authorize this local observation: ")
        if confirmation != "TEST":
            raise Refused("OPERATOR_DECLINED")
        binary = build_binary()
        print("Starting observer and awaiting validated logind readiness. "
              "Do not lock or suspend yet.", flush=True)

        def notify_ready() -> None:
            # This marker is deliberately only emitted *after* the Rust
            # stdout handshake, once it has installed event subscriptions,
            # acquired its inhibitor and completed the initial snapshot.
            print("RUNNING_OBSERVATION", flush=True)
            if args.mode != "baseline":
                print("Observer ready: trigger the selected action using "
                      "your desktop controls now.", flush=True)

        status, reason, code, ready, prompted = run_observation(
            [str(binary), "--observe-only", "--seconds", str(args.seconds)],
            args.mode, args.seconds, on_ready=notify_ready,
        )
        receipt = {
            "schema": SCHEMA,
            "mode": args.mode,
            "source_git_commit": sha,
            "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "status": status,
            "redacted_event": reason,
            "observer_exit_code": code,
            "observer_ready_handshake": ready,
            "operator_action_prompted_after_ready": prompted,
            "local_self_report_only": True,
            "real_vault_loaded_or_unlocked": False,
            "inhibitor_fd_lifecycle_independently_verified": False,
            "pre_suspend_secret_wipe_verified": False,
            "production_daemon_tested": False,
            "open_01": "BLOCKED",
            "open_15": "BLOCKED",
            "release_gates": "G1-G3 BLOCKED",
        }
        write_new(args.receipt, receipt)
        print(f"V03-D: {status}: {reason}. Redacted receipt created; "
              "OPEN-01/15 and G1-G3 remain BLOCKED.")
        return 0 if status != "INCOMPLETE" else 2
    except (Refused, OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError) as exc:
        # No raw paths/OS identifiers; only a fixed safe classification.
        reason = str(exc) if isinstance(exc, Refused) else "LOCAL_SETUP_FAILED"
        print(f"V03-D: {reason}; no hardware security approval.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("V03-D: OPERATOR_INTERRUPTED; no evidence approval.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
