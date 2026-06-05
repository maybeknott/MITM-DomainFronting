#!/usr/bin/env python3
"""Conservative first-match route isolation verifier for Xray configs."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


def load_config(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("config must be a JSON object")
    return data


def inbound_tags(rule: Dict[str, Any]) -> set[str] | None:
    tags = rule.get("inboundTag")
    if tags is None:
        return None
    if isinstance(tags, str):
        return {tags}
    if isinstance(tags, list):
        return {str(tag) for tag in tags}
    return set()


def rule_applies_to_inbound(rule: Dict[str, Any], inbound: str) -> bool:
    tags = inbound_tags(rule)
    return tags is None or inbound in tags


def verify(config: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    inbounds = [
        item.get("tag")
        for item in config.get("inbounds", [])
        if isinstance(item, dict) and isinstance(item.get("tag"), str)
    ]
    decrypted = [tag for tag in inbounds if str(tag).startswith("tls-decrypt-")]
    rules = [
        rule
        for rule in config.get("routing", {}).get("rules", [])
        if isinstance(rule, dict)
    ]

    for inbound in decrypted:
        terminal_block_seen = False
        repack_seen = False
        for index, rule in enumerate(rules):
            if not rule_applies_to_inbound(rule, str(inbound)):
                continue
            outbound = rule.get("outboundTag")
            if isinstance(outbound, str) and outbound.startswith("tls-repack-"):
                if inbound_tags(rule) is None:
                    errors.append(f"{inbound}: repack rule {rule.get('ruleTag')} is not scoped by inboundTag")
                repack_seen = True
                continue
            if outbound == "block" and inbound_tags(rule) is not None:
                terminal_block_seen = True
                break
            if outbound == "direct" and inbound_tags(rule) is not None:
                errors.append(f"{inbound}: inbound-scoped direct route at rule[{index}] {rule.get('ruleTag')}")
            if outbound == "direct" and rule.get("ip") == ["0.0.0.0/0", "::/0"]:
                errors.append(f"{inbound}: global direct catch-all reachable before terminal block")
                break
        if not repack_seen:
            errors.append(f"{inbound}: no inbound-scoped repack route found")
        if not terminal_block_seen:
            errors.append(f"{inbound}: no inbound-scoped terminal block found before global fallback")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify decrypted route isolation")
    parser.add_argument("config", type=Path, nargs="?", default=Path("Xray-config/Xray-Cooperative-Overlay.json"))
    args = parser.parse_args()
    errors = verify(load_config(args.config))
    if errors:
        for error in errors:
            print(error)
        return 2
    print("route graph verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
