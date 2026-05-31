#!/usr/bin/env python3
"""Generate explicit operating profiles from the primary Xray config."""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any, Dict, List

PROFILE_POLICIES = {
    "strict": {
        "catchall": "block",
        "udp443": "block",
        "loglevel": "warning",
        "udp_rule_tag": "r050_block_quic_udp443",
    },
    "balanced": {
        "catchall": "direct",
        "udp443": "direct",
        "loglevel": "warning",
        "udp_rule_tag": "r050_direct_quic_udp443",
    },
    "compatibility": {
        "catchall": "direct",
        "udp443": "direct",
        "loglevel": "warning",
        "udp_rule_tag": "r050_direct_quic_udp443",
    },
    "debug": {
        "catchall": "direct",
        "udp443": "block",
        "loglevel": "info",
        "udp_rule_tag": "r050_block_quic_udp443",
    },
}


def load_config(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("config must be a JSON object")
    return data


def rule_tags(rules: List[Dict[str, Any]]) -> set[str]:
    return {rule.get("ruleTag") for rule in rules if isinstance(rule.get("ruleTag"), str)}


def insert_udp_policy(rules: List[Dict[str, Any]], outbound_tag: str, rule_tag: str) -> None:
    tags = rule_tags(rules)
    if rule_tag in tags:
        return
    rule = {
        "outboundTag": outbound_tag,
        "network": "udp",
        "port": 443,
        "ruleTag": rule_tag,
    }
    insert_at = 0
    for index, existing in enumerate(rules):
        if existing.get("ruleTag") == "r040_direct_private_regional":
            insert_at = index + 1
            break
    rules.insert(insert_at, rule)


def set_global_catchall(rules: List[Dict[str, Any]], outbound_tag: str) -> None:
    for rule in rules:
        if rule.get("ruleTag") == "r900_direct_global_catchall":
            rule["outboundTag"] = outbound_tag
            if outbound_tag == "block":
                rule["ruleTag"] = "r900_block_global_catchall"
            return
        if rule.get("ruleTag") == "r900_block_global_catchall":
            rule["outboundTag"] = outbound_tag
            if outbound_tag == "direct":
                rule["ruleTag"] = "r900_direct_global_catchall"
            return


def make_profile(base: Dict[str, Any], profile: str) -> Dict[str, Any]:
    policy = PROFILE_POLICIES[profile]
    config = copy.deepcopy(base)
    config.pop("__Credits__", None)
    config["remarks"] = f"{base.get('remarks', 'MITM-DomainFronting')}_{profile}"
    log = config.setdefault("log", {})
    if isinstance(log, dict):
        log["loglevel"] = policy["loglevel"]
        log["access"] = "none"
        log["dnsLog"] = False
    rules = config.setdefault("routing", {}).setdefault("rules", [])
    if not isinstance(rules, list):
        raise ValueError("routing.rules must be a list")
    insert_udp_policy(rules, policy["udp443"], policy["udp_rule_tag"])
    set_global_catchall(rules, policy["catchall"])
    return config


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate MITM-DomainFronting operating profile configs")
    parser.add_argument("--base", type=Path, default=Path("Xray-config/MITM-DomainFronting.json"))
    parser.add_argument("--out-dir", type=Path, default=Path("Xray-config"))
    args = parser.parse_args()

    base = load_config(args.base)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    for profile in PROFILE_POLICIES:
        output = args.out_dir / f"MITM-DomainFronting.{profile}.json"
        output.write_text(json.dumps(make_profile(base, profile), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
