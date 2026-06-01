#!/usr/bin/env python3
"""Stable entry point for the full config-src build pipeline."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    script = Path(__file__).resolve().parent / "config_src_build.py"
    proc = subprocess.run([sys.executable, str(script), *sys.argv[1:]], check=False)
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
