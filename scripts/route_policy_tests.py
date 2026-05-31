#!/usr/bin/env python3
"""Deterministic route/profile policy checks for committed configs."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


def load(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level JSON must be an object")
    return data


def rules(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    value = config.get("routing", {}).get("rules", [])
    return [rule for rule in value if isinstance(rule, dict)] if isinstance(value, list) else []


def rule_by_tag(config: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {rule.get("ruleTag"): rule for rule in rules(config) if isinstance(rule.get("ruleTag"), str)}


def profile_name(config: Dict[str, Any], path: Path) -> str:
    remarks = config.get("remarks")
    if isinstance(remarks, str):
        for profile in ("strict", "balanced", "compatibility", "debug"):
            if remarks.endswith("_" + profile) or profile in remarks.split("_"):
                return profile
    parts = path.stem.split(".")
    for profile in ("strict", "balanced", "compatibility", "debug"):
        if profile in parts:
            return profile
    return ""


def check_base(config: Dict[str, Any], path: Path) -> List[str]:
    errors: List[str] = []
    by_tag = rule_by_tag(config)
    if by_tag.get("r900_direct_global_catchall", {}).get("outboundTag") != "direct":
        errors.append(f"{path}: base config must keep direct global catch-all")
    if any(rule.get("network") == "udp" and str(rule.get("port")) == "443" for rule in rules(config)):
        errors.append(f"{path}: base config should not add profile-specific UDP/443 policy")
    return errors


def check_profile(config: Dict[str, Any], path: Path) -> List[str]:
    errors: List[str] = []
    name = profile_name(config, path)
    by_tag = rule_by_tag(config)
    udp_rules = [rule for rule in rules(config) if rule.get("network") == "udp" and str(rule.get("port")) == "443"]
    if len(udp_rules) != 1:
        errors.append(f"{path}: expected exactly one UDP/443 policy rule, found {len(udp_rules)}")
    if name == "strict":
        if by_tag.get("r900_block_global_catchall", {}).get("outboundTag") != "block":
            errors.append(f"{path}: strict profile must block global catch-all")
        if not udp_rules or udp_rules[0].get("outboundTag") != "block":
            errors.append(f"{path}: strict profile must block UDP/443")
    elif name == "debug":
        if not udp_rules or udp_rules[0].get("outboundTag") != "block":
            errors.append(f"{path}: debug profile must block UDP/443 to surface QUIC mismatch")
        log = config.get("log", {})
        if not isinstance(log, dict) or log.get("access") != "none":
            errors.append(f"{path}: debug profile must keep access logs disabled")
    elif name in {"balanced", "compatibility"}:
        if by_tag.get("r900_direct_global_catchall", {}).get("outboundTag") != "direct":
            errors.append(f"{path}: {name} profile must keep direct global catch-all")
        if not udp_rules or udp_rules[0].get("outboundTag") != "direct":
            errors.append(f"{path}: {name} profile must direct UDP/443 with documented warning")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate route policy semantics across base and profile configs")
    parser.add_argument("configs", nargs="*", type=Path)
    args = parser.parse_args()
    paths = args.configs or sorted(Path("Xray-config").glob("MITM-DomainFronting*.json"))
    errors: List[str] = []
    for path in paths:
        config = load(path)
        if path.name == "MITM-DomainFronting.json":
            errors.extend(check_base(config, path))
        elif profile_name(config, path):
            errors.extend(check_profile(config, path))
    if errors:
        for error in errors:
            print(error)
        return 2
    print("route policy tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
