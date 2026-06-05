#!/usr/bin/env python3
"""Validate repository policy metadata without third-party dependencies."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

DATE_RE = re.compile(r"last_tested:\s*(\d{4}-\d{2}-\d{2})")
ID_RE = re.compile(r"^id:\s*([a-z0-9-]+)\s*$", re.MULTILINE)
STATUS_RE = re.compile(r"^status:\s*([a-z0-9_-]+)\s*$", re.MULTILINE)
LIST_ITEM_RE = re.compile(r"^\s*-\s*([A-Za-z0-9_.:-]+)\s*$", re.MULTILINE)


def route_tags_from_config(path: Path) -> set[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    rules = data.get("routing", {}).get("rules", [])
    if not isinstance(rules, list):
        return set()
    return {
        rule.get("ruleTag")
        for rule in rules
        if isinstance(rule, dict) and isinstance(rule.get("ruleTag"), str)
    }


def list_values_under(text: str, key: str) -> list[str]:
    match = re.search(rf"^{re.escape(key)}:\s*$", text, flags=re.MULTILINE)
    if not match:
        return []
    tail = text[match.end():]
    block_lines: list[str] = []
    for line in tail.splitlines():
        if line and not line.startswith((" ", "\t", "-")):
            break
        block_lines.append(line)
    return LIST_ITEM_RE.findall("\n".join(block_lines))


def has_scalar_value(text: str, key: str, expected: str) -> bool:
    for line in text.splitlines():
        clean = line.split("#", 1)[0].strip()
        if not clean or ":" not in clean:
            continue
        found_key, value = clean.split(":", 1)
        if found_key.strip() == key and value.strip() == expected:
            return True
    return False


def require_scalar_values(path: Path, values: dict[str, str]) -> list[str]:
    text = path.read_text(encoding="utf-8")
    return [
        f"{path}: missing guardrail {key}: {expected}"
        for key, expected in values.items()
        if not has_scalar_value(text, key, expected)
    ]


def validate_provider(path: Path, known_route_tags: set[str]) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    if not ID_RE.search(text):
        errors.append(f"{path}: missing id")
    if not STATUS_RE.search(text):
        errors.append(f"{path}: missing status")
    if not DATE_RE.search(text):
        errors.append(f"{path}: missing ISO last_tested")
    if "failure_policy:" not in text:
        errors.append(f"{path}: missing failure_policy")
    if "known_risks:" not in text:
        errors.append(f"{path}: missing known_risks")
    routes = list_values_under(text, "routes")
    if not routes:
        errors.append(f"{path}: missing routes")
    for route in routes:
        if route not in known_route_tags:
            errors.append(f"{path}: unknown route tag {route}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate provider and profile metadata")
    parser.add_argument("--providers-dir", type=Path, default=Path("providers"))
    parser.add_argument("--config", type=Path, default=Path("Xray-config/Xray-Cooperative-Overlay.json"))
    args = parser.parse_args()
    errors: list[str] = []
    try:
        known_route_tags = route_tags_from_config(args.config)
    except Exception as exc:  # noqa: BLE001
        known_route_tags = set()
        errors.append(f"{args.config}: cannot read route tags: {exc}")
    if args.providers_dir.exists():
        for path in sorted(args.providers_dir.glob("*.yml")):
            errors.extend(validate_provider(path, known_route_tags))
    else:
        errors.append(f"{args.providers_dir}: missing providers directory")
    for required in [Path("configs/profiles.yml"), Path("configs/dns-profiles.yml")]:
        if not required.exists():
            errors.append(f"{required}: missing")
    relay = Path("configs/relay-profiles.yml")
    if relay.exists():
        errors.extend(require_scalar_values(relay, {
            "default_enabled": "false",
            "public_open_relays_allowed": "false",
            "authentication_required": "true",
            "owner_metadata_required": "true",
            "payload_logging_allowed": "false",
        }))
    else:
        errors.append(f"{relay}: missing")
    metrics = Path("configs/metrics-profiles.yml")
    if metrics.exists():
        text = metrics.read_text(encoding="utf-8")
        errors.extend(require_scalar_values(metrics, {
            "default_enabled": "false",
            "bind": "127.0.0.1",
            "payload_logging": "false",
            "access_log": "none",
        }))
        if "decrypted_payload" not in text:
            errors.append(f"{metrics}: missing guardrail decrypted_payload")
    else:
        errors.append(f"{metrics}: missing")
    tun = Path("configs/tun-profiles.yml")
    if tun.exists():
        text = tun.read_text(encoding="utf-8")
        for needle in [
            "browser-proxy-first:",
            "android-browser-safe:",
            "desktop-full-system-strict:",
            "desktop-split-tunnel:",
            "requires_external_vpn_service: true",
            "stop_on_vpn_proxy_or_dns_conflict",
        ]:
            if needle not in text:
                errors.append(f"{tun}: missing guardrail {needle}")
    else:
        errors.append(f"{tun}: missing")
    health = Path("configs/health-checks.yml")
    if health.exists():
        text = health.read_text(encoding="utf-8")
        for needle in [
            "local_only: true",
            "payload_logging: false",
            "local_ports:",
            "certificate:",
            "dns:",
            "routing:",
            "environment:",
            "strict_mode_no_direct_leak",
            "vpn_tun_interface_conflict",
        ]:
            if needle not in text:
                errors.append(f"{health}: missing guardrail {needle}")
    else:
        errors.append(f"{health}: missing")
    if errors:
        for error in errors:
            print(error)
        return 2
    print("metadata validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
