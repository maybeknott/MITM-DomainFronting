#!/usr/bin/env python3
"""Named Xray profile candidates for the control-plane strategy engine."""
from __future__ import annotations

from pathlib import Path

from core.strategy_engine import ProfileCandidate, StrategyDecision, StrategyInput, choose_profile

ROOT = Path(__file__).resolve().parents[2]

PROFILE_TAGS: dict[str, tuple[str, ...]] = {
    "strict": ("fakedns", "profile_trust"),
    "balanced": ("multi_utls",),
    "compatibility": ("fragment", "profile_trust"),
    "debug": ("profile_trust",),
}

PROFILE_INTENTS: dict[str, str] = {
    "strict": "strict",
    "balanced": "balanced",
    "compatibility": "compatibility",
    "debug": "debug",
}

PROFILE_PRIORITY: dict[str, int] = {
    "strict": 90,
    "balanced": 100,
    "compatibility": 80,
    "debug": 70,
}


def default_candidates(root: Path = ROOT) -> tuple[ProfileCandidate, ...]:
    candidates: list[ProfileCandidate] = []
    for profile_id in ("strict", "balanced", "compatibility", "debug"):
        path = root / "Xray-config" / f"MITM-DomainFronting.{profile_id}.json"
        candidates.append(
            ProfileCandidate(
                profile_id=profile_id,
                profile_path=str(path),
                intent=PROFILE_INTENTS[profile_id],
                tags=PROFILE_TAGS[profile_id],
                priority=PROFILE_PRIORITY[profile_id],
                requires_confirmation=profile_id in {"compatibility", "debug"},
            )
        )
    return tuple(candidates)


def recommend_profile(
    *,
    failure_labels: tuple[str, ...] = (),
    operator_intent: str = "balanced",
    session_counter: int = 0,
    avoid_profiles: tuple[str, ...] = (),
    root: Path = ROOT,
) -> StrategyDecision:
    request = StrategyInput(
        failure_labels=failure_labels,
        operator_intent=operator_intent,
        session_counter=session_counter,
        avoid_profiles=avoid_profiles,
    )
    return choose_profile(default_candidates(root), request)
