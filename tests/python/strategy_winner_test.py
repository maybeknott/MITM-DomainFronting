#!/usr/bin/env python3
"""Tests for persistent strategy winner cache."""
from __future__ import annotations

import _path  # noqa: F401

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from core.strategy_winner import clear_winner, load_winner, remember_winner  # noqa: E402


def test_remember_and_load_winner() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "winner.json"
        remember_winner("balanced", reason="probe_ok", failure_labels=(), path=path)
        loaded = load_winner(path)
        assert loaded is not None
        assert loaded.profile_id == "balanced"
        clear_winner(path)
        assert load_winner(path) is None


def main() -> int:
    test_remember_and_load_winner()
    print("PASS test_remember_and_load_winner")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
