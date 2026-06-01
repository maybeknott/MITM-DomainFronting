#!/usr/bin/env python3
"""Validate redacted lab evidence bundle shape and scenario completeness."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

REQUIRED_SCENARIOS = {
    "resolver-timeout",
    "fallback-order",
    "dns-hijack",
    "fake-dns-lab",
    "split-dns",
    "nat64-dns64",
    "captive-portal",
    "fakedns_recovery",
}

ALLOWED_STATUS = {"pass", "warn", "fail", "info"}


def validate_bundle(path: Path, allow_warn: bool) -> List[str]:
    errors: List[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [f"{path}: failed to parse JSON: {exc}"]
    if not isinstance(data, dict):
        return [f"{path}: bundle must be a JSON object"]
    scenarios = data.get("scenarios")
    if not isinstance(scenarios, dict):
        return [f"{path}: missing scenarios object"]
    missing = sorted(REQUIRED_SCENARIOS.difference(scenarios.keys()))
    if missing:
        errors.append(f"{path}: missing scenario(s): {', '.join(missing)}")
    for name, entry in scenarios.items():
        if not isinstance(entry, dict):
            errors.append(f"{path}: scenario {name} must be an object")
            continue
        status = str(entry.get("status", ""))
        if status not in ALLOWED_STATUS:
            errors.append(f"{path}: scenario {name} has invalid status {status!r}")
        report = entry.get("report")
        if name != "fakedns_recovery" and not isinstance(report, dict):
            errors.append(f"{path}: scenario {name} missing report object")
        if not allow_warn and status != "pass":
            errors.append(f"{path}: scenario {name} is {status}, expected pass")
    overall = str(data.get("overall", ""))
    if overall not in ALLOWED_STATUS:
        errors.append(f"{path}: invalid overall status {overall!r}")
    if not allow_warn and overall != "pass":
        errors.append(f"{path}: overall is {overall}, expected pass")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate lab evidence bundle schema")
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--allow-warn", action="store_true", help="accept warn scenarios for non-lab CI")
    args = parser.parse_args()

    errors = validate_bundle(args.bundle, args.allow_warn)
    if errors:
        for error in errors:
            print(error)
        return 2
    print("lab evidence bundle validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
