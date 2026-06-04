#!/usr/bin/env python3
"""Resolve or apply a strategy-engine profile recommendation."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from core.failure_classifier import derive_strategy_labels  # noqa: E402
from core.strategy_profiles import recommend_profile  # noqa: E402


def load_report(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def main() -> int:
    parser = argparse.ArgumentParser(description="Recommend or describe an Xray operating profile")
    parser.add_argument("--report", type=Path, default=ROOT / ".local-state" / "decision-report.latest.json")
    parser.add_argument("--operator-intent", default="balanced")
    parser.add_argument("--session-counter", type=int, default=0)
    parser.add_argument("--leak-hint", action="append", default=[])
    parser.add_argument("--phase", default="", help="optional failure_classifier phase label")
    args = parser.parse_args()

    report = load_report(args.report)
    strategy = report.get("strategy_recommendation") if isinstance(report.get("strategy_recommendation"), dict) else {}
    if strategy.get("selected_profile_id"):
        payload = strategy
    else:
        labels = tuple(strategy.get("failure_labels") or [])
        if not labels:
            labels = derive_strategy_labels(phase=args.phase or None, leak_hints=tuple(args.leak_hint or ()))
        if report.get("phase_diagnostics", {}).get("phase_classification") and not args.phase:
            labels = derive_strategy_labels(
                phase=str(report["phase_diagnostics"]["phase_classification"]),
                leak_hints=tuple(args.leak_hint or ()),
            )
        intent = str(report.get("profile") or args.operator_intent)
        decision = recommend_profile(
            failure_labels=labels,
            operator_intent=intent,
            session_counter=max(0, args.session_counter),
        )
        payload = {
            "selected_profile_id": decision.selected_profile_id,
            "selected_profile_path": decision.selected_profile_path,
            "reason": decision.reason,
            "confidence": decision.confidence,
            "confirmation_required": decision.confirmation_required,
            "failure_labels": list(labels),
            "evidence": decision.evidence,
        }
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    path = Path(str(payload.get("selected_profile_path") or ""))
    return 0 if path.exists() else 2


if __name__ == "__main__":
    raise SystemExit(main())
