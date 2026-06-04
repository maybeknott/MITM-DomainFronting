#!/usr/bin/env python3
"""Named Xray profile candidates for the control-plane strategy engine."""
from __future__ import annotations

from pathlib import Path

from core.strategy_engine import ProfileCandidate, StrategyDecision, StrategyInput, choose_profile
from core.strategy_winner import load_winner, remember_winner

ROOT = Path(__file__).resolve().parents[2]

PROFILE_TAGS: dict[str, tuple[str, ...]] = {
    "strict": ("fakedns", "profile_trust"),
    "balanced": ("multi_utls",),
    "compatibility": ("fragment", "profile_trust"),
    "debug": ("profile_trust",),
    "evasion-fragment": ("fragment", "multi_utls"),
    "evasion-high-stealth": ("fragment", "fakedns", "tun", "multi_utls"),
}

PROFILE_INTENTS: dict[str, str] = {
    "strict": "strict",
    "balanced": "balanced",
    "compatibility": "compatibility",
    "debug": "debug",
    "evasion-fragment": "balanced",
    "evasion-high-stealth": "strict",
}

PROFILE_PRIORITY: dict[str, int] = {
    "strict": 90,
    "balanced": 100,
    "compatibility": 80,
    "debug": 70,
    "evasion-fragment": 85,
    "evasion-high-stealth": 95,
}


def default_candidates(root: Path = ROOT) -> tuple[ProfileCandidate, ...]:
    candidates: list[ProfileCandidate] = []
    profile_ids = (
        "strict",
        "balanced",
        "compatibility",
        "debug",
        "evasion-fragment",
        "evasion-high-stealth",
    )
    for profile_id in profile_ids:
        path = root / "Xray-config" / f"MITM-DomainFronting.{profile_id}.json"
        if not path.exists():
            continue
        candidates.append(
            ProfileCandidate(
                profile_id=profile_id,
                profile_path=str(path),
                intent=PROFILE_INTENTS[profile_id],
                tags=PROFILE_TAGS[profile_id],
                priority=PROFILE_PRIORITY[profile_id],
                requires_confirmation=profile_id
                in {"compatibility", "debug", "evasion-fragment", "evasion-high-stealth"},
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
    labels = {label.strip().lower() for label in failure_labels if label.strip()}
    if not labels:
        remembered = load_winner()
        if remembered:
            for candidate in default_candidates(root):
                if candidate.profile_id == remembered.profile_id:
                    return StrategyDecision(
                        selected_profile_id=candidate.profile_id,
                        selected_profile_path=candidate.profile_path,
                        reason=f"remember_winner:{remembered.reason}",
                        confidence="medium",
                        confirmation_required=candidate.requires_confirmation,
                        evidence={"remembered_profile": remembered.profile_id},
                    )

    decision = choose_profile(default_candidates(root), request)
    if decision.confidence == "medium" and not labels:
        remember_winner(
            decision.selected_profile_id,
            reason=decision.reason,
            failure_labels=failure_labels,
        )
    return decision
