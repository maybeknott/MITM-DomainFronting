#!/usr/bin/env python3
"""Lightweight startup gate for GUI connect and preflight surfacing."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.version_utils import version_at_least

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PREFLIGHT_CACHE = ROOT / ".local-state" / "preflight.latest.json"


def load_cached_preflight(path: Path = DEFAULT_PREFLIGHT_CACHE) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def evaluate_startup_gate(
    snapshot: dict[str, Any],
    *,
    cached_preflight: dict[str, Any] | None = None,
) -> tuple[str, list[str]]:
    """Return overall gate level and blocker ids."""
    blockers: list[str] = []

    if not snapshot.get("selected_config_exists"):
        blockers.append("config_missing")

    min_version = str(snapshot.get("config_min_xray_version") or "").strip()
    runtime_version = str(snapshot.get("xray_version") or "").strip()
    if min_version:
        if not snapshot.get("xray_local"):
            blockers.append("xray_missing")
        elif runtime_version and runtime_version.lower() != "unknown":
            if not version_at_least(runtime_version, min_version):
                blockers.append("xray_pin")

    if str(snapshot.get("key_permission_status") or "") == "broad":
        blockers.append("key_acl")

    if str(snapshot.get("listener_exposure") or "") == "exposed":
        blockers.append("listener_exposed")

    if cached_preflight and str(cached_preflight.get("overall") or "") == "fail":
        blockers.append("preflight_fail")

    if blockers:
        return "fail", blockers
    if str(snapshot.get("readiness_overall") or "") == "warn":
        return "warn", []
    return "pass", []


def blocker_messages(blockers: list[str]) -> list[str]:
    mapping = {
        "config_missing": "Selected Xray config is missing or invalid.",
        "xray_missing": "Bundled Xray Core is not installed.",
        "xray_pin": "Bundled Xray Core is below the config minimum version pin.",
        "key_acl": "Local CA private key ACL is broader than recommended.",
        "listener_exposed": "A non-loopback proxy listener is exposed.",
        "preflight_fail": "Latest full preflight report failed.",
    }
    return [mapping.get(item, item) for item in blockers]
