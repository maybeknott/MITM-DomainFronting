#!/usr/bin/env python3
"""GUI operator preferences persisted under .local-state."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PREFS_PATH = ROOT / ".local-state" / "gui-preferences.json"
TELEMETRY_MODES = frozenset({"local_disk", "ram_only"})


@dataclass(frozen=True)
class GuiPreferences:
    telemetry_mode: str = "local_disk"
    telemetry_max_events: int = 500
    block_connect_on_preflight_fail: bool = True
    auto_apply_strategy_on_probe: bool = False

    def ram_only(self) -> bool:
        return self.telemetry_mode == "ram_only"


def load_preferences(path: Path = DEFAULT_PREFS_PATH) -> GuiPreferences:
    if not path.exists():
        return GuiPreferences()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return GuiPreferences()
    if not isinstance(data, dict):
        return GuiPreferences()
    mode = str(data.get("telemetry_mode") or "local_disk")
    if mode not in TELEMETRY_MODES:
        mode = "local_disk"
    max_events = int(data.get("telemetry_max_events") or 500)
    if max_events < 50:
        max_events = 50
    if max_events > 5000:
        max_events = 5000
    block_connect = bool(data.get("block_connect_on_preflight_fail", True))
    auto_apply = bool(data.get("auto_apply_strategy_on_probe", False))
    return GuiPreferences(
        telemetry_mode=mode,
        telemetry_max_events=max_events,
        block_connect_on_preflight_fail=block_connect,
        auto_apply_strategy_on_probe=auto_apply,
    )


def save_preferences(prefs: GuiPreferences, path: Path = DEFAULT_PREFS_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "telemetry_mode": prefs.telemetry_mode,
        "telemetry_max_events": prefs.telemetry_max_events,
        "block_connect_on_preflight_fail": prefs.block_connect_on_preflight_fail,
        "auto_apply_strategy_on_probe": prefs.auto_apply_strategy_on_probe,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
