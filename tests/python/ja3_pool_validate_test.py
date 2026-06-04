#!/usr/bin/env python3
"""Tests for JA3 pool artifact validation."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_ja3_pool_validate_passes() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "ja3_pool_validate.py")],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def main() -> int:
    test_ja3_pool_validate_passes()
    print("PASS test_ja3_pool_validate_passes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
