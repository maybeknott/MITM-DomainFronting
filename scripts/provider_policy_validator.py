#!/usr/bin/env python3
"""Validate typed provider-policy sections for all provider dossiers."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from core.provider_policy import provider_source, validate_policy_dict  # noqa: E402


def validate_all_providers(providers_dir: Path, stale_days: int) -> int:
    errors: list[str] = []
    warnings: list[str] = []

    if not providers_dir.exists():
        print(f"{providers_dir}: missing providers directory")
        return 2

    for provider_file in sorted(providers_dir.glob("*.yml")):
        if provider_file.name == "dns-resolvers.yml":
            continue
        try:
            data = yaml.safe_load(provider_file.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            errors.append(f"{provider_source(provider_file)}: YAML parse failed ({exc})")
            continue
        if not isinstance(data, dict):
            errors.append(f"{provider_source(provider_file)}: root must be a YAML object")
            continue

        provider_errors, provider_warnings = validate_policy_dict(
            data,
            source=provider_source(provider_file),
            stale_days=stale_days,
        )
        errors.extend(provider_errors)
        warnings.extend(provider_warnings)

    for warning in warnings:
        print(f"WARN {warning}")
    if errors:
        for error in errors:
            print(error)
        return 2
    print("provider policy validation passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate provider policy hardening fields")
    parser.add_argument("--providers-dir", type=Path, default=ROOT / "providers")
    parser.add_argument("--stale-days", type=int, default=90)
    args = parser.parse_args()
    return validate_all_providers(args.providers_dir, args.stale_days)


if __name__ == "__main__":
    raise SystemExit(main())

