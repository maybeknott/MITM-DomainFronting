#!/usr/bin/env python3
"""Validate provider dossier metadata and route-tag linkage."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Set

DATE_RE = re.compile(r"last_tested:\s*(\d{4}-\d{2}-\d{2})")
ID_RE = re.compile(r"^id:\s*([a-z0-9-]+)\s*$", re.MULTILINE)
STATUS_RE = re.compile(r"^status:\s*([a-z0-9_-]+)\s*$", re.MULTILINE)
LIST_ITEM_RE = re.compile(r"^\s*-\s*(.+?)\s*$", re.MULTILINE)
ALLOWED_STATUSES = {"experimental", "supported_test_required", "unsupported", "unknown"}
ALLOWED_PROFILES = {"strict", "balanced", "compatibility", "debug"}


def route_tags_from_config(path: Path) -> Set[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    rules = data.get("routing", {}).get("rules", [])
    if not isinstance(rules, list):
        return set()
    return {
        rule.get("ruleTag")
        for rule in rules
        if isinstance(rule, dict) and isinstance(rule.get("ruleTag"), str)
    }


def collect_route_tags(config_glob: List[Path]) -> Set[str]:
    tags: Set[str] = set()
    for path in config_glob:
        try:
            tags.update(route_tags_from_config(path))
        except Exception:
            continue
    return tags


def list_values_under(text: str, key: str) -> List[str]:
    match = re.search(rf"^{re.escape(key)}:\s*$", text, flags=re.MULTILINE)
    if not match:
        return []
    tail = text[match.end():]
    block_lines: List[str] = []
    for line in tail.splitlines():
        if line and not line.startswith((" ", "\t", "-")):
            break
        block_lines.append(line)
    return LIST_ITEM_RE.findall("\n".join(block_lines))


def _has_nested_key(text: str, parent: str, child: str) -> bool:
    pattern = re.compile(rf"^{re.escape(parent)}:\s*$", re.MULTILINE)
    match = pattern.search(text)
    if not match:
        return False
    tail = text[match.end():]
    for line in tail.splitlines():
        if line and not line.startswith((" ", "\t")):
            break
        if re.search(rf"^\s+{re.escape(child)}:\s*", line):
            return True
    return False


def validate_provider(path: Path, known_route_tags: Set[str]) -> List[str]:
    text = path.read_text(encoding="utf-8")
    errors: List[str] = []
    id_match = ID_RE.search(text)
    status_match = STATUS_RE.search(text)
    if not id_match:
        errors.append(f"{path}: missing id")
    if not status_match:
        errors.append(f"{path}: missing status")
    elif status_match.group(1) not in ALLOWED_STATUSES:
        errors.append(f"{path}: unsupported status {status_match.group(1)}")
    if not DATE_RE.search(text):
        errors.append(f"{path}: missing ISO last_tested")
    for key in ("routes", "known_risks", "supported_profiles", "rollback", "evidence_required"):
        values = list_values_under(text, key)
        if not values:
            errors.append(f"{path}: missing or empty {key}")
    for key in ("geosite_refs", "geoip_refs", "domain_refs"):
        if not re.search(rf"^{re.escape(key)}:", text, flags=re.MULTILINE):
            errors.append(f"{path}: missing {key}")
    for profile in list_values_under(text, "supported_profiles"):
        if profile not in ALLOWED_PROFILES:
            errors.append(f"{path}: unsupported profile in supported_profiles: {profile}")
    routes = list_values_under(text, "routes")
    for route in routes:
        if route not in known_route_tags:
            errors.append(f"{path}: unknown route tag {route}")
    if "failure_policy:" not in text:
        errors.append(f"{path}: missing failure_policy")
    else:
        if not _has_nested_key(text, "failure_policy", "strict"):
            errors.append(f"{path}: failure_policy.strict missing")
        if not _has_nested_key(text, "failure_policy", "balanced"):
            errors.append(f"{path}: failure_policy.balanced missing")
    for key in ("os", "client", "xray_min", "xray", "environment"):
        if not _has_nested_key(text, "tested_with", key):
            errors.append(f"{path}: tested_with.{key} missing")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate provider dossiers and route-tag coverage")
    parser.add_argument("--providers-dir", type=Path, default=Path("providers"))
    parser.add_argument("--config-dir", type=Path, default=Path("Xray-config"))
    args = parser.parse_args()

    errors: List[str] = []
    config_paths = sorted(args.config_dir.glob("MITM-DomainFronting*.json"))
    known_tags = collect_route_tags(config_paths)
    if not known_tags:
        errors.append("no route tags discovered from Xray-config/MITM-DomainFronting*.json")
    if not args.providers_dir.exists():
        errors.append(f"{args.providers_dir}: missing providers directory")
    else:
        for provider_file in sorted(args.providers_dir.glob("*.yml")):
            errors.extend(validate_provider(provider_file, known_tags))

    if errors:
        for error in errors:
            print(error)
        return 2
    print("provider dossier validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
