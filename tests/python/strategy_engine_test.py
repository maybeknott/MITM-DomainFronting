#!/usr/bin/env python3
"""Unit tests for strategy_engine pool indexing and label routing."""
from __future__ import annotations

import _path  # noqa: F401

from core.strategy_engine import ProfileCandidate, StrategyInput, choose_profile, pool_index
from core.strategy_profiles import recommend_profile


def test_pool_index_requires_power_of_two() -> None:
    assert pool_index(0, 4) == 0
    assert pool_index(5, 4) == 1
    assert pool_index(7, 8) == 7


def test_dns_leak_prefers_fakedns_profile() -> None:
    candidates = (
        ProfileCandidate("plain", "plain.json", "balanced", (), priority=100),
        ProfileCandidate("strict", "strict.json", "balanced", ("fakedns",), priority=90),
    )
    decision = choose_profile(
        candidates,
        StrategyInput(failure_labels=("dns_leak",), operator_intent="balanced", session_counter=0),
    )
    assert decision.selected_profile_id == "strict"
    assert "dns_leak->fakedns" in decision.reason


def test_recommend_profile_avoids_blocked_ids() -> None:
    decision = recommend_profile(
        failure_labels=("webrtc_leak",),
        operator_intent="balanced",
        session_counter=1,
        avoid_profiles=("strict", "balanced", "compatibility", "debug"),
    )
    raise AssertionError("expected ValueError")


def main() -> int:
    tests = [
        test_pool_index_requires_power_of_two,
        test_dns_leak_prefers_fakedns_profile,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    try:
        test_recommend_profile_avoids_blocked_ids()
    except ValueError:
        print("PASS test_recommend_profile_avoids_blocked_ids")
    else:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
