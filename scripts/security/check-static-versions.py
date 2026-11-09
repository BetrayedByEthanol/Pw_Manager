#!/usr/bin/env python3
"""Verify installed SEC-01A candidate tool versions, fail on absence/mismatch."""
import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATIC = json.loads((ROOT / ".security/sec01a-static.json").read_text(encoding="utf-8"))
VERSIONS = STATIC["tools"]


def output(argv):
    binary = shutil.which(argv[0])
    if not binary:
        raise RuntimeError(f"missing executable {argv[0]!r}")
    proc = subprocess.run(argv, capture_output=True, text=True, check=False, timeout=30)
    if proc.returncode:
        raise RuntimeError(f"{argv[0]!r} exited {proc.returncode}: {(proc.stderr or proc.stdout).strip()[:250]}")
    return (proc.stdout + proc.stderr).strip()


def check(requested=None):
    checks = [
        ("rustc", ["rustc", "--version"], r"rustc\s+(\d+\.\d+\.\d+)", VERSIONS["rustc"]),
        ("clippy", ["cargo", "clippy", "--version"], r"clippy\s+([\d.]+)", None),
        ("cargo-deny", ["cargo-deny", "--version"], r"cargo-deny\s+(\d+\.\d+\.\d+)", VERSIONS["cargo-deny"]),
        ("gitleaks", ["gitleaks", "version"], r"(\d+\.\d+\.\d+)", VERSIONS["gitleaks"]),
        ("semgrep", ["semgrep", "--version"], r"(\d+\.\d+\.\d+)", VERSIONS["semgrep"]),
        ("node", ["node", "--version"], r"v(\d+)\.", str(VERSIONS["node_major"])),
        ("eslint", ["eslint", "--version"], r"v(\d+\.\d+\.\d+)", VERSIONS["eslint"]),
        ("web-ext", ["web-ext", "--version"], r"(\d+\.\d+\.\d+)", VERSIONS["web-ext"]),
    ]
    errors = []
    known = {item[0] for item in checks}
    if requested is not None and not requested <= known:
        print(f"SEC01A_UNKNOWN_TOOL: {sorted(requested - known)}", file=sys.stderr)
        return 64
    for name, argv, pattern, expected in checks:
        if requested is not None and name not in requested:
            continue
        try:
            result = output(argv)
            match = re.search(pattern, result)
            if not match:
                raise RuntimeError(f"unrecognized version response: {result[:200]}")
            actual = match.group(1)
            if expected is not None and actual != expected:
                raise RuntimeError(f"version {actual}, expected {expected}")
            print(f"SEC01A_TOOL_OK: {name} {actual}")
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            errors.append(f"SEC01A_TOOL_NOT_READY: {name}: {exc}")
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 78
    print("SEC01A_TOOL_VERSIONS_MATCH: presence/version only; does not prove binary provenance")
    return 0


if __name__ == "__main__":
    sys.exit(check())
