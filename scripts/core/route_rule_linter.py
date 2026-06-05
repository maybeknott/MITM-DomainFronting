#!/usr/bin/env python3
"""First-match route shadowing and decrypted-inbound isolation linter."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


GLOBAL_IP_CATCHALL = {"0.0.0.0/0", "::/0"}


def load_config(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("config must be a JSON object")
    return data


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def inbound_tags(rule: dict[str, Any]) -> set[str]:
    return {str(item) for item in as_list(rule.get("inboundTag"))}


def has_match_constraint(rule: dict[str, Any]) -> bool:
    for key in ("domain", "ip", "port", "network", "source", "user", "protocol", "inboundTag", "attrs"):
        if rule.get(key):
            return True
    return False


def is_absolute_catchall(rule: dict[str, Any]) -> bool:
    return not has_match_constraint(rule)


def is_global_ip_fallback(rule: dict[str, Any]) -> bool:
    return set(str(item) for item in as_list(rule.get("ip"))) == GLOBAL_IP_CATCHALL and not inbound_tags(rule)


def is_final_port_fallback(rule: dict[str, Any]) -> bool:
    return str(rule.get("port", "")) == "0-65535" and not inbound_tags(rule) and not rule.get("domain") and not rule.get("ip")


def decrypted_inbounds(config: dict[str, Any]) -> set[str]:
    return {
        str(item.get("tag"))
        for item in config.get("inbounds", [])
        if isinstance(item, dict) and isinstance(item.get("tag"), str) and str(item.get("tag")).startswith("tls-decrypt-")
    }


def lint(config: dict[str, Any]) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    rules = [rule for rule in config.get("routing", {}).get("rules", []) if isinstance(rule, dict)]
    decrypt_tags = decrypted_inbounds(config)
    absolute_catchall_index: int | None = None
    absolute_catchall_tag = ""

    for idx, rule in enumerate(rules):
        tag = str(rule.get("ruleTag", f"rule[{idx}]"))
        outbound = rule.get("outboundTag")
        scoped_inbounds = inbound_tags(rule)

        if absolute_catchall_index is not None:
            errors.append(
                f"{tag}: unreachable after absolute catch-all {absolute_catchall_tag} at index {absolute_catchall_index}"
            )
            continue

        if is_absolute_catchall(rule):
            absolute_catchall_index = idx
            absolute_catchall_tag = tag
            warnings.append(f"{tag}: absolute catch-all boundary at index {idx} -> {outbound}")

        if is_global_ip_fallback(rule):
            warnings.append(f"{tag}: global IP fallback boundary at index {idx} -> {outbound}")
        elif is_final_port_fallback(rule):
            warnings.append(f"{tag}: final port fallback boundary at index {idx} -> {outbound}")

        leaked = sorted(decrypt_tags & scoped_inbounds)
        if leaked and outbound == "direct":
            errors.append(f"{tag}: decrypted inbound(s) route directly: {', '.join(leaked)}")

    for inbound in sorted(decrypt_tags):
        repack_seen = False
        terminal_seen = False
        for idx, rule in enumerate(rules):
            scoped = inbound_tags(rule)
            if scoped and inbound not in scoped:
                continue
            outbound = rule.get("outboundTag")
            tag = str(rule.get("ruleTag", f"rule[{idx}]"))
            if isinstance(outbound, str) and outbound.startswith("tls-repack-") and inbound in scoped:
                repack_seen = True
            if outbound == "direct" and inbound in scoped:
                errors.append(f"{tag}: {inbound} has inbound-scoped direct route")
            if outbound == "block" and inbound in scoped:
                terminal_seen = True
                break
            if is_global_ip_fallback(rule) or is_absolute_catchall(rule):
                errors.append(f"{tag}: {inbound} can reach global fallback before scoped terminal block")
                break
        if not repack_seen:
            errors.append(f"{inbound}: no scoped tls-repack route found")
        if not terminal_seen:
            errors.append(f"{inbound}: no scoped terminal block before fallback")

    return errors, warnings


def main() -> int:
    parser = argparse.ArgumentParser(description="Lint first-match route shadowing and decrypted inbound isolation")
    parser.add_argument("config", type=Path, nargs="?", default=Path("Xray-config/Xray-Cooperative-Overlay.json"))
    parser.add_argument("--quiet", action="store_true", help="suppress warning output when checks pass")
    args = parser.parse_args()

    errors, warnings = lint(load_config(args.config))
    if warnings and not args.quiet:
        for warning in warnings:
            print(f"WARN {warning}")
    if errors:
        for error in errors:
            print(f"FAIL {error}")
        return 2
    print("route rule lint passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

