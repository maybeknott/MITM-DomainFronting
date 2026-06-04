#!/usr/bin/env python3
"""Regression tests for staged failure classifier behavior."""
from __future__ import annotations

import _path  # noqa: F401

from core.failure_classifier import ProbeResult, derive_strategy_labels, run_staged_probe


def test_probe_result_to_dict_shape() -> None:
    result = ProbeResult(phase_classification="healthy", confidence_score=1.0, http_status=200)
    data = result.to_dict()
    assert data["phase_classification"] == "healthy"
    assert data["confidence_score"] == 1.0
    telemetry = data["telemetry"]
    assert "dns_resolution_ms" in telemetry
    assert telemetry["http_status"] == 200


def test_invalid_tld_returns_dns_failure() -> None:
    result = run_staged_probe("definitely-not-real-probe-target.invalid", timeout=1.0)
    assert result.phase_classification in {"dns_resolution_failed", "dns_timeout"}
    assert result.confidence_score >= 0.9


def test_derive_strategy_labels_maps_dns_phase() -> None:
    labels = derive_strategy_labels(phase="dns_timeout")
    assert labels == ("dns_leak",)


def test_derive_strategy_labels_accepts_leak_hints() -> None:
    labels = derive_strategy_labels(phase="healthy", leak_hints=["webrtc_leak", "bogus"])
    assert labels == ("webrtc_leak",)


def main() -> int:
    tests = [
        test_probe_result_to_dict_shape,
        test_invalid_tld_returns_dns_failure,
        test_derive_strategy_labels_maps_dns_phase,
        test_derive_strategy_labels_accepts_leak_hints,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
