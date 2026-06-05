#!/usr/bin/env python3
"""Validate transport profile metadata against generated Xray profiles."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "configs" / "transport-profiles.yml"
DOC = ROOT / "docs" / "transport-profiles.md"
CONFIG_DIR = ROOT / "Xray-config"

EXPECTED_PROFILE_POLICIES = {
    "strict": {"udp": "block", "catchall": "block"},
    "balanced": {"udp": "direct", "catchall": "direct"},
    "compatibility": {"udp": "direct", "catchall": "direct"},
    "debug": {"udp": "block", "catchall": "direct"},
}


def load_config(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level must be an object")
    return data


def rules(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    value = config.get("routing", {}).get("rules", [])
    return [rule for rule in value if isinstance(rule, dict)] if isinstance(value, list) else []


def first_udp443_rule(config: Dict[str, Any]) -> Dict[str, Any] | None:
    for rule in rules(config):
        if rule.get("network") == "udp" and str(rule.get("port")) == "443":
            return rule
    return None


def catchall_rule(config: Dict[str, Any]) -> Dict[str, Any] | None:
    for rule in rules(config):
        ips = rule.get("ip")
        if isinstance(ips, list) and "0.0.0.0/0" in ips and "::/0" in ips:
            return rule
    return None


def validate_registry_text(text: str) -> List[str]:
    errors: List[str] = []
    for needle in [
        "single_primary_config: Xray-config/Xray-Cooperative-Overlay.json",
        "profile_policies:",
        "external_engine_transports:",
        "evidence_commands:",
        "transport_profile_sync: python scripts/transport_profile_validate.py",
        "protocol_smoke: python scripts/protocol_smoke.py --scenario udp443-policy",
    ]:
        if needle not in text:
            errors.append(f"{REGISTRY}: missing {needle}")
    for profile in ["base", "strict", "balanced", "compatibility", "debug"]:
        if f"  {profile}:" not in text:
            errors.append(f"{REGISTRY}: missing profile policy {profile}")
    for transport in ["xhttp", "grpc", "websocket", "hysteria"]:
        block = f"  {transport}:\n    default_enabled: false\n    repository_action: upstream_or_separate_architecture_review"
        if block not in text:
            errors.append(f"{REGISTRY}: external transport {transport} must be default-disabled and review-gated")
    return errors


def validate_profile_configs() -> List[str]:
    errors: List[str] = []
    base = load_config(CONFIG_DIR / "Xray-Cooperative-Overlay.json")
    if first_udp443_rule(base) is not None:
        errors.append("base config must keep UDP/443 policy in generated profiles, not primary config")
    base_catchall = catchall_rule(base)
    if not base_catchall or base_catchall.get("outboundTag") != "direct":
        errors.append("base config must keep direct global catch-all")

    for profile, expected in EXPECTED_PROFILE_POLICIES.items():
        path = CONFIG_DIR / f"Xray-Cooperative-Overlay.{profile}.json"
        if not path.exists():
            errors.append(f"{path}: missing generated profile")
            continue
        config = load_config(path)
        udp = first_udp443_rule(config)
        if not udp:
            errors.append(f"{path}: missing UDP/443 policy rule")
        elif udp.get("outboundTag") != expected["udp"]:
            errors.append(f"{path}: UDP/443 outboundTag={udp.get('outboundTag')!r} expected {expected['udp']!r}")
        catchall = catchall_rule(config)
        if not catchall:
            errors.append(f"{path}: missing global catch-all")
        elif catchall.get("outboundTag") != expected["catchall"]:
            errors.append(
                f"{path}: catch-all outboundTag={catchall.get('outboundTag')!r} expected {expected['catchall']!r}"
            )
        if profile == "debug" and config.get("log", {}).get("access") != "none":
            errors.append(f"{path}: debug profile must keep access log disabled")
    return errors


def validate_docs() -> List[str]:
    text = DOC.read_text(encoding="utf-8") if DOC.exists() else ""
    errors: List[str] = []
    for needle in [
        "profile-defined",
        "Strict/debug block UDP/443",
        "balanced/compatibility direct-route with warning",
        "Unsupported transports must stay explicitly labeled",
    ]:
        if needle not in text:
            errors.append(f"{DOC}: missing documented transport policy: {needle}")
    return errors


def main() -> int:
    errors: List[str] = []
    if not REGISTRY.exists():
        errors.append(f"{REGISTRY}: missing")
    else:
        errors.extend(validate_registry_text(REGISTRY.read_text(encoding="utf-8")))
    errors.extend(validate_profile_configs())
    errors.extend(validate_docs())
    if errors:
        for error in errors:
            print(error)
        return 2
    print("transport profile validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
