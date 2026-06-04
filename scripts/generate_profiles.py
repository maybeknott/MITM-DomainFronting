#!/usr/bin/env python3
"""Generate explicit operating profiles from the primary Xray config."""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))
from core.ja3_pool_attach import attach_for_operating_profile  # noqa: E402

DEFAULT_LOCAL_PORTS = {
    "mixed-in": 10808,
    "tls-decrypt-google-h11": 11666,
    "tls-decrypt-google-h2": 11777,
    "tls-decrypt-fastly-h2": 11888,
    "tls-decrypt-meta-h2": 11999,
}

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


def apply_port_offset(config: Dict[str, Any], offset: int) -> None:
    if offset == 0:
        return
    replacements = {old: old + offset for old in DEFAULT_LOCAL_PORTS.values()}
    for old_port, new_port in replacements.items():
        if not 1 <= new_port <= 65535:
            raise ValueError(f"port offset produces invalid port: {old_port} -> {new_port}")
    for inbound in config.get("inbounds", []):
        if not isinstance(inbound, dict):
            continue
        tag = inbound.get("tag")
        if tag in DEFAULT_LOCAL_PORTS:
            inbound["port"] = DEFAULT_LOCAL_PORTS[tag] + offset
    for outbound in config.get("outbounds", []):
        if not isinstance(outbound, dict):
            continue
        settings = outbound.get("settings")
        if not isinstance(settings, dict):
            continue
        redirect = settings.get("redirect")
        if not isinstance(redirect, str) or ":" not in redirect:
            continue
        host, port_text = redirect.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError:
            continue
        if port in replacements:
            settings["redirect"] = f"{host}:{replacements[port]}"


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
    attach_for_operating_profile(config, profile, Path(__file__).resolve().parents[1])
    return config


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate MITM-DomainFronting operating profile configs")
    parser.add_argument("--base", type=Path, default=Path("Xray-config/MITM-DomainFronting.json"))
    parser.add_argument("--out-dir", type=Path, default=Path("Xray-config"))
    parser.add_argument("--port-offset", type=int, default=0, help="shift local listener and redirect ports together")
    parser.add_argument("--suffix", default="", help="filename suffix before .json, for example .altports")
    args = parser.parse_args()

    base = load_config(args.base)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    suffix = args.suffix
    if args.port_offset and not suffix:
        direction = "plus" if args.port_offset > 0 else "minus"
        suffix = f".ports-{direction}{abs(args.port_offset)}"
    for profile in PROFILE_POLICIES:
        output = args.out_dir / f"MITM-DomainFronting.{profile}{suffix}.json"
        config = make_profile(base, profile)
        apply_port_offset(config, args.port_offset)
        output.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
