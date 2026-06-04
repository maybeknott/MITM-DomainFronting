#!/usr/bin/env python3
"""Persist last successful strategy profile across sessions (Track B)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_PATH = Path(__file__).resolve().parents[2] / ".local-state" / "strategy-winner.json"


@dataclass(frozen=True)
class StrategyWinner:
    profile_id: str
    reason: str
    failure_labels: tuple[str, ...]
    saved_at_utc: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "reason": self.reason,
            "failure_labels": list(self.failure_labels),
            "saved_at_utc": self.saved_at_utc,
        }


def remember_winner(
    profile_id: str,
    *,
    reason: str = "",
    failure_labels: tuple[str, ...] = (),
    path: Path = DEFAULT_PATH,
) -> StrategyWinner:
    entry = StrategyWinner(
        profile_id=profile_id.strip(),
        reason=reason.strip() or "remember_winner",
        failure_labels=tuple(sorted({label.strip().lower() for label in failure_labels if label.strip()})),
        saved_at_utc=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(entry.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return entry


def load_winner(path: Path = DEFAULT_PATH) -> Optional[StrategyWinner]:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    profile_id = str(data.get("profile_id") or "").strip()
    if not profile_id:
        return None
    labels = data.get("failure_labels")
    if not isinstance(labels, list):
        labels = []
    return StrategyWinner(
        profile_id=profile_id,
        reason=str(data.get("reason") or ""),
        failure_labels=tuple(str(item) for item in labels),
        saved_at_utc=str(data.get("saved_at_utc") or ""),
    )


def clear_winner(path: Path = DEFAULT_PATH) -> None:
    if path.exists():
        path.unlink(missing_ok=True)
