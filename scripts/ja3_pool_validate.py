#!/usr/bin/env python3
"""Validate offline JA3 pool artifacts against Rust fixture hashes."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POOL = ROOT / "config-src" / "templates" / "ja3-pools" / "chrome-baseline-pool.json"

# Mirrors src/ja3.rs unit-test vectors (GREASE stripped).
RUST_FIXTURE_HASHES: dict[str, str] = {
    "772,4865-4866,0-10-16,29-23,0": "e5e1e38579ae55ca3ec29f347d63149e",
    "771,4865,0,,": "1e7c622032b0cb79401b0f7be3793a1a",
}


def md5_hex(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def validate_pool(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    templates = data.get("templates")
    if not isinstance(templates, list) or not templates:
        errors.append("templates must be a non-empty array")
        return errors
    seen_ids: set[str] = set()
    for index, template in enumerate(templates):
        if not isinstance(template, dict):
            errors.append(f"templates[{index}] must be an object")
            continue
        template_id = str(template.get("id") or "").strip()
        ja3_string = str(template.get("ja3_string") or "")
        ja3_hash = str(template.get("ja3_hash_md5") or "").strip().lower()
        if not template_id:
            errors.append(f"templates[{index}] missing id")
        elif template_id in seen_ids:
            errors.append(f"duplicate template id: {template_id}")
        else:
            seen_ids.add(template_id)
        if not ja3_string:
            errors.append(f"templates[{index}] missing ja3_string")
            continue
        computed = md5_hex(ja3_string)
        if ja3_hash and ja3_hash != computed:
            errors.append(f"{template_id or index}: ja3_hash_md5 mismatch (expected {computed}, got {ja3_hash})")
        expected = RUST_FIXTURE_HASHES.get(ja3_string)
        if expected and ja3_hash and ja3_hash != expected:
            errors.append(f"{template_id or index}: hash does not match src/ja3.rs fixture ({expected})")
        if expected and computed != expected:
            errors.append(f"{template_id or index}: computed hash drift from src/ja3.rs fixture")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate config-src JA3 pool artifacts")
    parser.add_argument("--pool", type=Path, default=DEFAULT_POOL)
    args = parser.parse_args()
    if not args.pool.exists():
        print(f"pool missing: {args.pool}")
        return 2
    try:
        data = json.loads(args.pool.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"invalid pool JSON: {exc}")
        return 2
    if not isinstance(data, dict):
        print("pool root must be an object")
        return 2
    errors = validate_pool(data)
    if errors:
        for error in errors:
            print(error)
        return 1
    print(json.dumps({"pool": str(args.pool), "templates": len(data.get("templates", [])), "status": "pass"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
