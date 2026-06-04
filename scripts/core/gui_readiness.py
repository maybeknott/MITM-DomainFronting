#!/usr/bin/env python3
"""GUI-facing readiness bridge.

The shared readiness engine owns facts and next-action decisions. This module
keeps the GUI-specific cache and action mapping out of the Tk application so
the dashboard can stay a renderer instead of a second diagnostics engine.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from core.readiness import ProjectState, build_project_state


DEFAULT_REFRESH_SECONDS = 12.0


@dataclass(frozen=True)
class GuiActionSpec:
    button: str
    target: str
    tone: str


ACTION_SPECS: dict[str, GuiActionSpec] = {
    "Repair Config": GuiActionSpec("Open Config Folder", "config_folder", "red"),
    "Regenerate Profiles": GuiActionSpec("Generate Profiles", "generate_profiles", "amber"),
    "Generate Local CA": GuiActionSpec("Generate Local CA", "generate_ca", "amber"),
    "Regenerate Local CA": GuiActionSpec("Generate Local CA", "generate_ca", "red"),
    "Download Xray Core": GuiActionSpec("Download Xray Core", "download_xray", "amber"),
    "Fix Exposed Listener": GuiActionSpec("Open Health", "health_tab", "red"),
    "Start Core": GuiActionSpec("Start Core", "start_core", "blue"),
    "Restrict Private Key": GuiActionSpec("Open Certificates", "certificates_tab", "amber"),
    "Trust Certificate": GuiActionSpec("Open Certificates", "certificates_tab", "amber"),
    "Install Page Check Tools": GuiActionSpec("Install Page Tools", "install_page_tools", "amber"),
    "Run Page Check": GuiActionSpec("Run Page Check", "page_check", "green"),
    "Optional JA3 Validation": GuiActionSpec("Open Fingerprint Check", "browser_tab", "blue"),
    "Ready": GuiActionSpec("Run Page Check", "page_check", "green"),
}

FALLBACK_ACTION = GuiActionSpec("Run Check Setup", "check_setup", "blue")


class GuiReadinessCache:
    def __init__(
        self,
        *,
        root: Path,
        cert_path: Path,
        key_path: Path,
        refresh_seconds: float = DEFAULT_REFRESH_SECONDS,
    ) -> None:
        self.root = root
        self.cert_path = cert_path
        self.key_path = key_path
        self.refresh_seconds = refresh_seconds
        self.state: Optional[ProjectState] = None
        self.cache_key = ""
        self.cache_at = 0.0
        self.error = ""

    def get(self, selected_config: Path, *, force: bool = False) -> Optional[ProjectState]:
        now = time.monotonic()
        try:
            cache_key = str(selected_config.resolve()) if selected_config.exists() else str(selected_config)
        except (OSError, ValueError) as exc:
            self.error = str(exc)
            return self.state
        cache_fresh = (
            self.state is not None
            and self.cache_key == cache_key
            and now - self.cache_at < self.refresh_seconds
        )
        if cache_fresh and not force:
            return self.state
        try:
            self.state = build_project_state(
                root=self.root,
                config_path=selected_config,
                cert_path=self.cert_path,
                key_path=self.key_path,
            )
            self.cache_key = cache_key
            self.cache_at = now
            self.error = ""
            return self.state
        except Exception as exc:  # noqa: BLE001
            self.error = str(exc)
            return self.state


def readiness_snapshot_fields(state: Optional[ProjectState], error: str = "") -> dict[str, object]:
    return {
        "readiness_overall": state.overall if state else "warn",
        "readiness_next_action": state.next_action if state else "Run Check Setup",
        "readiness_next_action_detail": (
            state.next_action_detail
            if state
            else error or "Shared readiness state is not available yet."
        ),
        "readiness_error": error,
        "profiles_present": state.profiles_present if state else False,
        "profiles_synced": state.profiles_synced if state else False,
        "config_remarks": state.config_remarks if state else "",
        "config_min_xray_version": state.config_min_xray_version if state else "",
        "cert_key_match": state.cert_key_match if state else "unknown",
        "cert_expiry_status": state.cert_expiry_status if state else "unknown",
        "key_permission_status": state.key_permission_status if state else "unknown",
        "trust_status": state.trust_status if state else "unknown",
        "trust_windows_user": state.trust_windows_user if state else "unknown",
        "trust_windows_machine": state.trust_windows_machine if state else "unknown",
        "playwright_ok": state.playwright_ok if state else False,
        "cloakbrowser_ok": state.cloakbrowser_ok if state else False,
        "ja3_configured": state.ja3_configured if state else False,
        "ja3_measured": state.ja3_measured if state else False,
        "ja3_validation_status": state.ja3_validation_status if state else "not_measured",
        "ja3_oracle_url": state.ja3_oracle_url if state else "",
        "ja3_expected": state.ja3_expected if state else "",
        "ja3_observed": state.ja3_observed if state else "",
    }


def primary_action_spec(action: str) -> GuiActionSpec:
    return ACTION_SPECS.get(action, FALLBACK_ACTION)
