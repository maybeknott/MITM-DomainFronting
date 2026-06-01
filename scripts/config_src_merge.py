#!/usr/bin/env python3
"""Deep-merge Xray JSON config fragments for config-src builds."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, List


def deep_merge(base: Any, overlay: Any) -> Any:
    if isinstance(base, dict) and isinstance(overlay, dict):
        merged = copy.deepcopy(base)
        for key, value in overlay.items():
            if key in merged:
                merged[key] = deep_merge(merged[key], value)
            else:
                merged[key] = copy.deepcopy(value)
        return merged
    if isinstance(base, list) and isinstance(overlay, list):
        return copy.deepcopy(base) + copy.deepcopy(overlay)
    return copy.deepcopy(overlay)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def compile_config(primary: Path, fragment_paths: List[Path]) -> Any:
    config = load_json(primary)
    for fragment_path in fragment_paths:
        config = deep_merge(config, load_json(fragment_path))
    return config


def validate_fragments(root: Path, fragments: List[str]) -> List[str]:
    errors: List[str] = []
    for rel in fragments:
        path = root / rel
        if not path.exists():
            errors.append(f"fragment missing: {rel}")
            continue
        try:
            data = load_json(path)
        except json.JSONDecodeError as exc:
            errors.append(f"fragment not valid JSON: {rel} ({exc})")
            continue
        if not isinstance(data, dict):
            errors.append(f"fragment must be a JSON object: {rel}")
    return errors
