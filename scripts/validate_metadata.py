#!/usr/bin/env python3
"""Validate repository policy metadata without third-party dependencies."""
from __future__ import annotations

import argparse
import re
from pathlib import Path

DATE_RE = re.compile(r"last_tested:\s*(\d{4}-\d{2}-\d{2})")
ID_RE = re.compile(r"^id:\s*([a-z0-9-]+)\s*$", re.MULTILINE)
STATUS_RE = re.compile(r"^status:\s*([a-z0-9_-]+)\s*$", re.MULTILINE)


def validate_provider(path: Path) -> list[str]:
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
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate provider and profile metadata")
    parser.add_argument("--providers-dir", type=Path, default=Path("providers"))
    args = parser.parse_args()
    errors: list[str] = []
    if args.providers_dir.exists():
        for path in sorted(args.providers_dir.glob("*.yml")):
            errors.extend(validate_provider(path))
    else:
        errors.append(f"{args.providers_dir}: missing providers directory")
    for required in [Path("configs/profiles.yml"), Path("configs/dns-profiles.yml")]:
        if not required.exists():
            errors.append(f"{required}: missing")
    if errors:
        for error in errors:
            print(error)
        return 2
    print("metadata validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
