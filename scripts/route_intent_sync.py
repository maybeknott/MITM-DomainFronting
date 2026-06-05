#!/usr/bin/env python3
"""Compare Xray config ruleTag/outboundTag wiring against configs/route-intent.json."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Set

INTENT_PATH = Path("configs/route-intent.json")
PROFILE_UDP_RULES = {
    "strict": "r050_block_quic_udp443",
    "debug": "r050_block_quic_udp443",
    "balanced": "r050_direct_quic_udp443",
    "compatibility": "r050_direct_quic_udp443",
}
PROFILE_CATCHALL_RULES = {
    "strict": "r900_block_global_catchall",
    "balanced": "r900_direct_global_catchall",
    "compatibility": "r900_direct_global_catchall",
    "debug": "r900_direct_global_catchall",
}


def load_intent(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level must be an object")
    return data


def config_rules(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    rules = config.get("routing", {}).get("rules", [])
    return [rule for rule in rules if isinstance(rule, dict)] if isinstance(rules, list) else []


def profile_name(config: Dict[str, Any], path: Path) -> str:
    remarks = config.get("remarks")
    if isinstance(remarks, str):
        for profile in ("strict", "balanced", "compatibility", "debug"):
            if remarks.endswith("_" + profile) or f"_{profile}" in remarks:
                return profile
    for profile in ("strict", "balanced", "compatibility", "debug"):
        if profile in path.stem:
            return profile
    return "base"


def expected_order(intent: Dict[str, Any], profile: str) -> List[str]:
    base = list(intent.get("base_rule_order") or [])
    if profile == "base":
        return base
    udp = PROFILE_UDP_RULES.get(profile)
    catchall = PROFILE_CATCHALL_RULES.get(profile, "r900_direct_global_catchall")
    ordered = list(base[:5])
    if udp:
        ordered.append(udp)
    tail = base[5:]
    if catchall == "r900_block_global_catchall":
        tail = [tag for tag in tail if tag not in {"r900_direct_global_catchall", "r999_block_final"}]
        ordered.extend(tail)
        ordered.extend(["r900_block_global_catchall", "r999_block_final"])
    else:
        ordered.extend(tail)
    return ordered


def sync_config(config_path: Path, intent_path: Path) -> List[str]:
    errors: List[str] = []
    intent = load_intent(intent_path)
    rule_specs: Dict[str, Dict[str, Any]] = intent.get("rules") or {}
    config = json.loads(config_path.read_text(encoding="utf-8"))
    profile = profile_name(config, config_path)
    by_tag = {
        rule.get("ruleTag"): rule
        for rule in config_rules(config)
        if isinstance(rule.get("ruleTag"), str)
    }
    tags = [rule.get("ruleTag") for rule in config_rules(config) if isinstance(rule.get("ruleTag"), str)]

    for tag, spec in rule_specs.items():
        profiles = spec.get("profiles")
        if isinstance(profiles, list) and profile not in profiles and profile != "base":
            if tag not in by_tag:
                continue
        if tag.startswith("r050_") and profile in PROFILE_UDP_RULES:
            if tag != PROFILE_UDP_RULES[profile] and tag in by_tag:
                errors.append(f"{config_path}: unexpected UDP/443 rule {tag} for profile {profile}")
            continue
        if tag.startswith("r900_") and profile in PROFILE_CATCHALL_RULES:
            expected_catchall = PROFILE_CATCHALL_RULES[profile]
            if tag in by_tag and tag != expected_catchall:
                errors.append(f"{config_path}: catch-all tag {tag} does not match profile {profile}")
            continue
        if tag not in by_tag and tag in expected_order(intent, profile):
            errors.append(f"{config_path}: documented ruleTag missing in config: {tag}")
            continue
        if tag not in by_tag:
            continue
        expected_outbound = spec.get("outbound")
        actual_outbound = by_tag[tag].get("outboundTag")
        if expected_outbound and actual_outbound != expected_outbound:
            errors.append(
                f"{config_path}: {tag} outboundTag={actual_outbound!r} expected {expected_outbound!r} per route-intent"
            )

    documented: Set[str] = set(rule_specs)
    for tag in tags:
        if tag not in documented:
            errors.append(f"{config_path}: config ruleTag not documented in route-intent.json: {tag}")

    order = expected_order(intent, profile)
    if tags != order:
        if [t for t in tags if t in order] != [t for t in order if t in tags]:
            errors.append(f"{config_path}: ruleTag order differs from route-intent for profile {profile}")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync-check Xray configs against route intent manifest")
    parser.add_argument("configs", nargs="*", type=Path)
    parser.add_argument("--intent", type=Path, default=INTENT_PATH)
    args = parser.parse_args()

    intent_path = args.intent
    if not intent_path.exists():
        print(f"route intent manifest missing: {intent_path}")
        return 2

    paths = args.configs or [Path("Xray-config/Xray-Cooperative-Overlay.json")]
    errors: List[str] = []
    for path in paths:
        if not path.exists():
            errors.append(f"missing config: {path}")
            continue
        errors.extend(sync_config(path, intent_path))

    if errors:
        for error in errors:
            print(error)
        return 2
    print("route intent sync passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
