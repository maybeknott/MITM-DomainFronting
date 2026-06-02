#!/usr/bin/env python3
"""Regression checks for health-aware profile recommendation policy."""
from __future__ import annotations

from pathlib import Path

import _path  # noqa: F401

from health_probe import build_policy_recommendation


def test_all_pass_recommends_balanced() -> None:
    result = build_policy_recommendation(
        {
            "local_ports": [{"status": "pass", "detail": "listening-loopback"}],
            "certificate": [{"status": "pass"}],
            "dns": [{"status": "pass"}],
            "trust_store": {"status": "pass"},
            "geodata": {"status": "pass"},
            "providers": [{"status": "pass"}],
            "xray_runtime": {"status": "pass"},
        },
        "pass",
        Path("."),
    )
    assert result["auto_switch"] is False
    assert result["suggested_profile"] == "balanced"
    assert not result["actions"]


def test_dns_warning_recommends_compatibility() -> None:
    result = build_policy_recommendation(
        {
            "local_ports": [{"status": "pass", "detail": "listening-loopback"}],
            "certificate": [{"status": "pass"}],
            "dns": [{"status": "warn"}],
            "trust_store": {"status": "pass"},
            "geodata": {"status": "pass"},
            "providers": [{"status": "pass"}],
        },
        "warn",
        Path("."),
    )
    assert result["auto_switch"] is False
    assert result["suggested_profile"] == "compatibility"
    assert any("dns_lab_harness.py" in action for action in result["actions"])


def test_trust_mismatch_does_not_auto_switch() -> None:
    result = build_policy_recommendation(
        {
            "local_ports": [{"status": "pass", "detail": "listening-loopback"}],
            "certificate": [{"status": "pass"}],
            "dns": [{"status": "pass"}],
            "trust_store": {"status": "mismatch"},
            "geodata": {"status": "pass"},
            "providers": [{"status": "pass"}],
        },
        "warn",
        Path("."),
    )
    assert result["auto_switch"] is False
    assert result["suggested_profile"] == "balanced"
    assert any("trust store" in action.lower() for action in result["actions"])


def test_listener_exposure_keeps_auto_switch_disabled() -> None:
    result = build_policy_recommendation(
        {
            "local_ports": [{"status": "pass", "detail": "listening-loopback"}],
            "runtime_listener_exposure": [{"status": "fail", "detail": "possible non-loopback listener"}],
            "certificate": [{"status": "pass"}],
            "dns": [{"status": "pass"}],
            "trust_store": {"status": "pass"},
            "geodata": {"status": "pass"},
            "providers": [{"status": "pass"}],
        },
        "fail",
        Path("."),
    )
    assert result["auto_switch"] is False
    assert result["suggested_profile"] == "compatibility"
    assert any("127.0.0.1" in action for action in result["actions"])


def main() -> int:
    tests = [
        test_all_pass_recommends_balanced,
        test_dns_warning_recommends_compatibility,
        test_trust_mismatch_does_not_auto_switch,
        test_listener_exposure_keeps_auto_switch_disabled,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
