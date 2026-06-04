#!/usr/bin/env python3
"""Tests for eBPF containment supervisor lifecycle (simulate mode)."""
from __future__ import annotations

import _path  # noqa: F401

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from core.ebpf_containment import mark_supervisor_alive, mark_supervisor_dead  # noqa: E402


def test_supervisor_lifecycle_simulate() -> None:
    alive = mark_supervisor_alive(simulate=True)
    assert alive.get("supervisor_alive") is True
    dead = mark_supervisor_dead(simulate=True)
    assert dead.get("supervisor_alive") is False


def main() -> int:
    test_supervisor_lifecycle_simulate()
    print("PASS test_supervisor_lifecycle_simulate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
