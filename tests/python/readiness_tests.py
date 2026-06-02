#!/usr/bin/env python3
"""Regression checks for the shared readiness model."""
from __future__ import annotations

from dataclasses import replace

import _path  # noqa: F401

from core.readiness import (  # noqa: E402
    CheckResult,
    ProjectState,
    RepairAction,
    derive_next_action,
    state_to_dict,
    status_from_checks,
)


def base_state() -> ProjectState:
    return ProjectState(
        generated_at="2026-06-03T00:00:00+00:00",
        root=".",
        overall="pass",
        next_action="",
        next_action_detail="",
        config_ok=True,
        config_path="Xray-config/MITM-DomainFronting.json",
        profiles_present=True,
        profiles_synced=True,
        xray_available=True,
        listener_status="open",
        listener_host="127.0.0.1",
        listener_port=10808,
        listener_exposure="loopback",
        cert_exists=True,
        key_exists=True,
        cert_key_match="match",
        cert_expiry_status="valid",
        key_permission_status="restricted",
        trust_status="pass",
        trust_windows_user="pass",
        trust_windows_machine="pass",
        browser_deps_ok=True,
        playwright_ok=True,
        cloakbrowser_ok=True,
        page_check_status="pass",
        ja3_configured=True,
        ja3_validation_status="not_measured",
        release_ready=True,
    )


def expect(name: str, actual: object, expected: object) -> bool:
    if actual != expected:
        print(f"FAIL {name}: expected={expected!r} actual={actual!r}")
        return False
    print(f"PASS {name}")
    return True


def main() -> int:
    ok = True
    ok &= expect("status_fail_wins", status_from_checks([
        CheckResult("a", "runtime", "pass", "ok"),
        CheckResult("b", "runtime", "fail", "bad"),
    ]), "fail")
    ok &= expect("status_warn_without_fail", status_from_checks([
        CheckResult("a", "runtime", "pass", "ok"),
        CheckResult("b", "runtime", "warn", "careful"),
    ]), "warn")

    action, _ = derive_next_action(replace(base_state(), config_ok=False))
    ok &= expect("next_action_missing_config_first", action, "Repair Config")

    action, _ = derive_next_action(replace(base_state(), profiles_synced=False))
    ok &= expect("next_action_profiles_before_runtime", action, "Regenerate Profiles")

    action, _ = derive_next_action(replace(base_state(), cert_exists=False))
    ok &= expect("next_action_missing_cert", action, "Generate Local CA")

    action, _ = derive_next_action(replace(base_state(), cert_key_match="mismatch"))
    ok &= expect("next_action_cert_key_mismatch", action, "Regenerate Local CA")

    action, _ = derive_next_action(replace(base_state(), key_permission_status="broad"))
    ok &= expect("next_action_broad_key_permissions", action, "Restrict Private Key")

    action, _ = derive_next_action(replace(base_state(), key_permission_status="broad", listener_exposure="exposed"))
    ok &= expect("next_action_exposed_listener_over_key_permissions", action, "Fix Exposed Listener")

    action, _ = derive_next_action(replace(base_state(), xray_available=False))
    ok &= expect("next_action_missing_xray", action, "Download Xray Core")

    action, _ = derive_next_action(replace(base_state(), listener_exposure="exposed"))
    ok &= expect("next_action_exposed_listener_blocks_ready", action, "Fix Exposed Listener")

    action, _ = derive_next_action(replace(base_state(), listener_status="closed", listener_exposure="closed"))
    ok &= expect("next_action_closed_listener", action, "Start Core")

    action, _ = derive_next_action(replace(base_state(), trust_status="mismatch"))
    ok &= expect("next_action_trust_before_page_check", action, "Trust Certificate")

    action, _ = derive_next_action(replace(base_state(), playwright_ok=False))
    ok &= expect("next_action_missing_playwright", action, "Install Page Check Tools")

    action, _ = derive_next_action(replace(base_state(), page_check_status="not_run"))
    ok &= expect("next_action_page_check", action, "Run Page Check")

    action, _ = derive_next_action(base_state())
    ok &= expect("next_action_ja3_optional_when_configured_not_measured", action, "Optional JA3 Validation")

    ready = replace(base_state(), ja3_validation_status="match", ja3_measured=True)
    action, _ = derive_next_action(ready)
    ok &= expect("next_action_ready_after_ja3_measured", action, "Ready")

    state = replace(
        base_state(),
        checks=[CheckResult("listener.loopback", "runtime", "pass", "ok")],
        repairs=[RepairAction("repair.playwright", "Install page-check tools", "Install deps")],
    )
    payload = state_to_dict(state)
    ok &= expect("state_to_dict_checks_serialized", payload["checks"][0]["id"], "listener.loopback")
    ok &= expect("state_to_dict_repairs_serialized", payload["repairs"][0]["id"], "repair.playwright")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
