#!/usr/bin/env python3
"""Tests for startup preflight gate."""
from __future__ import annotations

import _path  # noqa: F401

from core.preflight_gate import blocker_messages, evaluate_startup_gate


def test_evaluate_startup_gate_blocks_xray_pin() -> None:
    snapshot = {
        "selected_config_exists": True,
        "config_min_xray_version": "1.8.0",
        "xray_version": "1.7.0",
        "xray_local": True,
        "key_permission_status": "restricted",
        "listener_exposure": "loopback",
    }
    level, blockers = evaluate_startup_gate(snapshot)
    assert level == "fail"
    assert "xray_pin" in blockers


def test_evaluate_startup_gate_passes_clean_snapshot() -> None:
    snapshot = {
        "selected_config_exists": True,
        "config_min_xray_version": "1.8.0",
        "xray_version": "1.8.4",
        "xray_local": True,
        "key_permission_status": "restricted",
        "listener_exposure": "loopback",
        "readiness_overall": "pass",
    }
    level, blockers = evaluate_startup_gate(snapshot)
    assert level == "pass"
    assert blockers == []


def test_blocker_messages_known_ids() -> None:
    msgs = blocker_messages(["xray_pin", "preflight_fail"])
    assert len(msgs) == 2
    assert "pin" in msgs[0].lower()


def main() -> int:
    test_evaluate_startup_gate_blocks_xray_pin()
    print("PASS test_evaluate_startup_gate_blocks_xray_pin")
    test_evaluate_startup_gate_passes_clean_snapshot()
    print("PASS test_evaluate_startup_gate_passes_clean_snapshot")
    test_blocker_messages_known_ids()
    print("PASS test_blocker_messages_known_ids")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
