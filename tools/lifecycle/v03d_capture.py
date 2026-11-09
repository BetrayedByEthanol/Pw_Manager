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
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "tools/lifecycle/v03c_rust/Cargo.toml"
SCHEMA = "vaulty-v03d-redacted-linux-lifecycle-evidence-v1"
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
    """Result classification is narrow and only uses fixed runner categories."""
    if mode == "baseline" and code == 0 and (
        stdout.strip() == "V03-C: OBSERVED_ONLY; no session or credential authorized"
    ):
        return "LOCAL_IDLE_OBSERVATION_REPORTED", "NONE"
    m = EXIT.search(stderr)
    reason = m.group(1) if m and m.group(1) in SAFE_REASONS else "UNCLASSIFIED"
    if (mode != "baseline" and code == 2
        and reason in EXPECTED[mode]):
        return "LOCAL_TERMINAL_EVENT_REPORTED", reason
    return "INCOMPLETE", reason


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
        print("Observer executable prepared. Once started, initiate the "
              "selected event manually using your desktop controls. "
              "Baseline mode requires no action.", flush=True)
        print("RUNNING_OBSERVATION", flush=True)
        try:
            run = subprocess.run(
                [str(binary), "--observe-only", "--seconds", str(args.seconds)],
                cwd=ROOT, capture_output=True, text=True,
                timeout=args.seconds + 20, check=False,
            )
            status, reason = classify(args.mode, run.returncode,
                                      run.stdout, run.stderr)
            code = run.returncode
        except subprocess.TimeoutExpired:
            status, reason, code = "INCOMPLETE", "PROCESS_TIMEOUT", -1
        receipt = {
            "schema": SCHEMA,
            "mode": args.mode,
            "source_git_commit": sha,
            "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "status": status,
            "redacted_event": reason,
            "observer_exit_code": code,
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
