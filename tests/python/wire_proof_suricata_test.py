#!/usr/bin/env python3
"""Tests for Suricata/PCAP wire-proof lab harness structure."""
from __future__ import annotations

import _path  # noqa: F401

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_wire_proof_structure_passes() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "wire_proof_suricata.py"), "--scenario", "structure"],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    assert data["scenario"] == "suricata-wire-proof-structure"
    assert data["status"] == "pass"


def main() -> int:
    test_wire_proof_structure_passes()
    print("PASS test_wire_proof_structure_passes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
