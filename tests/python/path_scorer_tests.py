#!/usr/bin/env python3
"""Regression tests for advisory path scorer."""
from __future__ import annotations

import _path  # noqa: F401

from path_scorer import aggregate_provider_rankings, build_advisory


def test_healthy_scores_high() -> None:
    advisory = build_advisory(
        {
            "phase_diagnostics": {
                "phase_classification": "healthy",
                "confidence_score": 1.0,
                "provider_family": "google",
                "target": "www.google.com",
                "telemetry": {
                    "tcp_connect_ms": 70,
                    "tls_server_hello_ms": 90,
                },
            }
        },
        source="unit",
    )
    assert advisory["status"] == "HEALTHY"
    assert advisory["computed_score"] > 70.0
    assert advisory["advisory_action"] == "NO_CHANGE"


def test_tls_drop_is_quarantined() -> None:
    advisory = build_advisory(
        {
            "phase_diagnostics": {
                "phase_classification": "tls_silent_drop",
                "confidence_score": 0.9,
                "provider_family": "fastly",
                "target": "target",
                "telemetry": {},
            }
        },
        source="unit",
    )
    assert advisory["status"] == "QUARANTINED"
    assert advisory["advisory_action"] == "ROTATE_PROFILE"


def test_unknown_phase_is_suspect() -> None:
    advisory = build_advisory(
        {
            "phase_classification": "mystery",
            "confidence_score": 0.5,
            "provider_family": "unknown",
            "target": "target",
            "telemetry": {},
        },
        source="unit",
    )
    assert advisory["status"] == "SUSPECT"
    assert advisory["advisory_action"] == "MANUAL_REVIEW"


def test_provider_ranking_prefers_higher_weighted_average() -> None:
    advisories = [
        {
            "provider_family": "google",
            "target": "a.example",
            "phase_classification": "healthy",
            "status": "HEALTHY",
            "computed_score": 90.0,
            "confidence_weighted_score": 90.0,
            "advisory_action": "NO_CHANGE",
        },
        {
            "provider_family": "google",
            "target": "b.example",
            "phase_classification": "healthy",
            "status": "HEALTHY",
            "computed_score": 85.0,
            "confidence_weighted_score": 85.0,
            "advisory_action": "NO_CHANGE",
        },
        {
            "provider_family": "fastly",
            "target": "c.example",
            "phase_classification": "tls_silent_drop",
            "status": "QUARANTINED",
            "computed_score": 8.0,
            "confidence_weighted_score": 7.2,
            "advisory_action": "ROTATE_PROFILE",
        },
    ]
    ranking = aggregate_provider_rankings(advisories)
    assert len(ranking) == 2
    assert ranking[0]["provider_family"] == "google"
    assert ranking[0]["rank"] == 1
    assert ranking[1]["provider_family"] == "fastly"
    assert ranking[1]["rank"] == 2
    assert ranking[0]["dominant_status"] == "HEALTHY"


def main() -> int:
    tests = [
        test_healthy_scores_high,
        test_tls_drop_is_quarantined,
        test_unknown_phase_is_suspect,
        test_provider_ranking_prefers_higher_weighted_average,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
