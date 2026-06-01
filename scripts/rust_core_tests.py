#!/usr/bin/env python3
"""Run Rust stream-core baseline tests in a bounded, local-only way."""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Cargo tests for the Rust stream-core baseline")
    parser.add_argument(
        "--required",
        action="store_true",
        help="fail if cargo is unavailable (default: warn and pass)",
    )
    args = parser.parse_args()

    cargo = shutil.which("cargo")
    if cargo is None:
        message = "cargo not found; skipping Rust baseline tests"
        if args.required:
            print(message)
            return 2
        print(f"WARN: {message}")
        return 0

    checks = [
        [cargo, "fmt", "--check"],
        [cargo, "clippy", "--all-targets", "--", "-D", "warnings"],
        [cargo, "test", "--quiet"],
    ]
    for command in checks:
        proc = subprocess.run(
            command,
            cwd=str(ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if proc.stdout:
            print(proc.stdout.strip())
        if proc.returncode != 0:
            return proc.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
