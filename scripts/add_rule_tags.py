#!/usr/bin/env python3
"""Add deterministic ruleTag fields to routing.rules in an Xray config.

The script preserves the current single-config workflow. It does not change
routing criteria or outbound behavior; it only adds missing ruleTag values.
Review the output before replacing the original config.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List


def slug(value: str) -> str:
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "_", value).strip("_")
    return value[:48] or "rule"


def infer_rule_name(index: int, rule: Dict[str, Any]) -> str:
    out = str(rule.get("outboundTag", "out"))
    inbound = rule.get("inboundTag")
    network = str(rule.get("network", ""))
    port = str(rule.get("port", ""))
    domains = rule.get("domain") if isinstance(rule.get("domain"), list) else []
    ips = rule.get("ip") if isinstance(rule.get("ip"), list) else []

    parts: List[str] = [f"r{(index + 1) * 10:03d}"]

    if out == "block":
        parts.append("block")
    elif out == "direct":
        parts.append("direct")
    elif out.startswith("redirect-out"):
        parts.append("redirect")
    elif out.startswith("tls-repack"):
        parts.append("repack")
    elif out == "dns-out":
        parts.append("dns")
    else:
        parts.append(slug(out))

    if domains:
        first = str(domains[0]).replace("geosite:", "").replace("domain:", "").replace("full:", "")
        parts.append(slug(first))
    elif ips:
        first = str(ips[0]).replace("geoip:", "")
        if first in ("0.0.0.0/0", "::/0"):
            parts.append("catchall")
        else:
            parts.append(slug(first))
    elif inbound:
        if isinstance(inbound, list):
            parts.append(slug(str(inbound[0])))
        else:
            parts.append(slug(str(inbound)))
    elif port:
        parts.append("port" + slug(port))

    if network:
        parts.append(slug(network))
    if port and port not in ("", "None"):
        parts.append("p" + slug(port))

    return "_".join(parts)


def add_rule_tags(config: Dict[str, Any], overwrite: bool = False) -> int:
    routing = config.setdefault("routing", {})
    rules = routing.setdefault("rules", [])
    if not isinstance(rules, list):
        raise ValueError("routing.rules must be a list")
    used = set()
    changed = 0
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        existing = rule.get("ruleTag")
        if isinstance(existing, str) and existing and not overwrite:
            used.add(existing)
            continue
        base = infer_rule_name(i, rule)
        tag = base
        n = 2
        while tag in used:
            tag = f"{base}_{n}"
            n += 1
        rule["ruleTag"] = tag
        used.add(tag)
        changed += 1
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description="Add missing ruleTag fields to Xray routing rules")
    parser.add_argument("config", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--overwrite", action="store_true", help="replace existing ruleTag values")
    args = parser.parse_args()

    config = json.loads(args.config.read_text(encoding="utf-8"))
    changed = add_rule_tags(config, overwrite=args.overwrite)
    args.out.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"changed_rules": changed, "output": str(args.out)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
