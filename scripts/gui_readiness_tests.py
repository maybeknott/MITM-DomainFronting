#!/usr/bin/env python3
"""Regression tests for the GUI readiness bridge."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from core.gui_readiness import (  # noqa: E402
    FALLBACK_ACTION,
    GuiReadinessCache,
    primary_action_spec,
    readiness_snapshot_fields,
)
from core.readiness import ProjectState  # noqa: E402


def assert_equal(name: str, left: object, right: object) -> None:
    if left != right:
        raise AssertionError(f"{name}: expected {right!r}, got {left!r}")


def sample_state(**overrides: object) -> ProjectState:
    state = ProjectState(
        generated_at="2026-06-03T00:00:00+00:00",
        root=".",
        overall="pass",
        next_action="Ready",
        next_action_detail="Core setup is ready.",
        config_ok=True,
        config_path="Xray-config/MITM-DomainFronting.json",
        config_remarks="MITM-DomainFronting_v23_Hardened",
        config_min_xray_version="26.2.6",
        profiles_present=True,
        profiles_synced=True,
        xray_available=True,
        listener_status="open",
        listener_exposure="loopback",
        cert_exists=True,
        key_exists=True,
        cert_key_match="match",
        key_permission_status="restricted",
        trust_status="pass",
        trust_windows_user="pass",
        trust_windows_machine="pass",
        playwright_ok=True,
        cloakbrowser_ok=True,
    )
    for key, value in overrides.items():
        state = replace(state, **{key: value})
    return state


def test_primary_action_specs() -> None:
    exposed = primary_action_spec("Fix Exposed Listener")
    assert_equal("exposed button", exposed.button, "Open Health")
    assert_equal("exposed target", exposed.target, "health_tab")
    assert_equal("exposed tone", exposed.tone, "red")

    ready = primary_action_spec("Ready")
    assert_equal("ready button", ready.button, "Run Page Check")
    assert_equal("ready target", ready.target, "page_check")

    unknown = primary_action_spec("Something New")
    assert_equal("unknown fallback", unknown, FALLBACK_ACTION)


def test_readiness_snapshot_fields() -> None:
    state = sample_state(next_action="Trust Certificate", next_action_detail="Trust is not matched.")
    fields = readiness_snapshot_fields(state)
    assert_equal("overall", fields["readiness_overall"], "pass")
    assert_equal("action", fields["readiness_next_action"], "Trust Certificate")
    assert_equal("detail", fields["readiness_next_action_detail"], "Trust is not matched.")
    assert_equal("remarks", fields["config_remarks"], "MITM-DomainFronting_v23_Hardened")
    assert_equal("trust", fields["trust_status"], "pass")
    assert_equal("browser", fields["playwright_ok"], True)


def test_readiness_snapshot_fallback_fields() -> None:
    fields = readiness_snapshot_fields(None, "boom")
    assert_equal("fallback overall", fields["readiness_overall"], "warn")
    assert_equal("fallback action", fields["readiness_next_action"], "Run Check Setup")
    assert_equal("fallback error", fields["readiness_error"], "boom")
    assert_equal("fallback detail", fields["readiness_next_action_detail"], "boom")


def test_cache_returns_fresh_state_without_rebuild() -> None:
    config = Path("not-created-for-test.json")
    state = sample_state()
    cache = GuiReadinessCache(root=Path("."), cert_path=Path("missing.crt"), key_path=Path("missing.key"), refresh_seconds=3600.0)
    cache.state = state
    cache.cache_key = str(config)
    cache.cache_at = 10**9
    cached = cache.get(config)
    assert_equal("fresh cache reused", cached, state)
    assert_equal("no cache error", cache.error, "")


def main() -> int:
    tests = [
        test_primary_action_specs,
        test_readiness_snapshot_fields,
        test_readiness_snapshot_fallback_fields,
        test_cache_returns_fresh_state_without_rebuild,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
