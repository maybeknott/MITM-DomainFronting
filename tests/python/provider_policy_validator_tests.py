#!/usr/bin/env python3
"""Regression tests for typed provider policy validation."""
from __future__ import annotations

import _path  # noqa: F401

from core.provider_policy import validate_policy_dict


def valid_policy() -> dict:
    return {
        "id": "google",
        "last_tested": "2026-06-01",
        "routes": ["r100_repack_googlevideo_h11"],
        "supported_profiles": ["strict", "balanced", "compatibility", "debug"],
        "failure_policy": {
            "strict": "block",
            "balanced": "user_selected_direct_or_report",
        },
        "tested_with": {
            "os": "windows",
            "client": "v2rayN",
            "xray_min": "26.2.6",
            "xray": "26.2.6",
            "environment": "lab",
        },
        "front_sni": ["www.google.com"],
        "alpn_policy": {
            "allowed": ["h2", "http/1.1"],
            "preferred": "h2",
        },
        "cidr_hints": [
            {"value": "geoip:google", "action": "allow", "rationale": "policy matched"},
        ],
    }


def test_valid_policy_passes() -> None:
    errors, warnings = validate_policy_dict(valid_policy(), source="providers/google.yml", stale_days=90)
    assert not errors
    assert not warnings


def test_missing_front_sni_fails() -> None:
    policy = valid_policy()
    policy.pop("front_sni")
    errors, _ = validate_policy_dict(policy, source="providers/google.yml", stale_days=90)
    assert any("front_sni" in error for error in errors)


def test_alpn_preferred_must_be_in_allowed() -> None:
    policy = valid_policy()
    policy["alpn_policy"]["preferred"] = "http/3"
    errors, _ = validate_policy_dict(policy, source="providers/google.yml", stale_days=90)
    assert any("alpn_policy.preferred" in error for error in errors)


def test_future_last_tested_fails() -> None:
    policy = valid_policy()
    policy["last_tested"] = "2999-01-01"
    errors, _ = validate_policy_dict(policy, source="providers/google.yml", stale_days=90)
    assert any("last_tested: cannot be in the future" in error for error in errors)


def test_cidr_hint_requires_token_or_cidr() -> None:
    policy = valid_policy()
    policy["cidr_hints"][0]["value"] = "not-a-cidr-or-token"
    errors, _ = validate_policy_dict(policy, source="providers/google.yml", stale_days=90)
    assert any("expected CIDR or classifier token" in error for error in errors)


def main() -> int:
    tests = [
        test_valid_policy_passes,
        test_missing_front_sni_fails,
        test_alpn_preferred_must_be_in_allowed,
        test_future_last_tested_fails,
        test_cidr_hint_requires_token_or_cidr,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
