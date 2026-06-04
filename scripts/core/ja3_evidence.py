#!/usr/bin/env python3
"""Persist and load optional JA3 oracle measurements for readiness/GUI honesty."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_EVIDENCE_PATH = ROOT / ".local-state" / "ja3-evidence.json"


@dataclass(frozen=True)
class Ja3Evidence:
    measured: bool
    validation_status: str
    oracle_url: str = ""
    expected_ja3: str = ""
    observed_ja3: str = ""
    verification_method: str = "not_measured"
    recorded_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_validation(
    *,
    observed_ja3: str | None,
    expected_ja3: str | None,
    verification_method: str,
) -> str:
    observed = (observed_ja3 or "").strip().lower()
    expected = (expected_ja3 or "").strip().lower()
    if not observed:
        return "not_measured"
    if expected and observed == expected:
        return "match"
    if expected:
        return "mismatch"
    return "measured"


def build_evidence(
    *,
    oracle_url: str = "",
    expected_ja3: str | None = None,
    observed_ja3: str | None = None,
    verification_method: str = "ja3_echo_oracle",
) -> Ja3Evidence:
    status = normalize_validation(
        observed_ja3=observed_ja3,
        expected_ja3=expected_ja3,
        verification_method=verification_method,
    )
    return Ja3Evidence(
        measured=bool((observed_ja3 or "").strip()),
        validation_status=status,
        oracle_url=oracle_url.strip(),
        expected_ja3=(expected_ja3 or "").strip(),
        observed_ja3=(observed_ja3 or "").strip(),
        verification_method=verification_method,
        recorded_at=_now_iso(),
    )


def save_evidence(evidence: Ja3Evidence, path: Path = DEFAULT_EVIDENCE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(evidence.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_evidence(path: Path = DEFAULT_EVIDENCE_PATH) -> Ja3Evidence | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return Ja3Evidence(
        measured=bool(data.get("measured")),
        validation_status=str(data.get("validation_status") or "not_measured"),
        oracle_url=str(data.get("oracle_url") or ""),
        expected_ja3=str(data.get("expected_ja3") or ""),
        observed_ja3=str(data.get("observed_ja3") or ""),
        verification_method=str(data.get("verification_method") or "not_measured"),
        recorded_at=str(data.get("recorded_at") or ""),
    )
