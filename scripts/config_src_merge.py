#!/usr/bin/env python3
"""Deep-merge Xray JSON config fragments for config-src builds."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, List


_MERGE_STRATEGY = "__merge_strategy__"
_REPLACE = "__replace__"
_LIST_STRATEGIES = {"append", "replace", "append_unique", "append_unique_by_tag"}


def _strip_control_keys(value: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in value.items() if k not in {_MERGE_STRATEGY, _REPLACE}}


def _stable_key(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _item_tag(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    for key in ("tag", "ruleTag", "id", "name"):
        raw = value.get(key)
        if isinstance(raw, str) and raw.strip():
            return f"{key}:{raw.strip()}"
    return None


def _merge_list(base: list[Any], overlay: list[Any], strategy: str) -> list[Any]:
    if strategy not in _LIST_STRATEGIES:
        raise ValueError(f"unsupported list merge strategy {strategy!r}; expected one of {sorted(_LIST_STRATEGIES)}")
    if strategy == "replace":
        return copy.deepcopy(overlay)
    if strategy == "append":
        return copy.deepcopy(base) + copy.deepcopy(overlay)
    if strategy == "append_unique":
        seen: set[str] = set()
        merged: list[Any] = []
        for item in [*base, *overlay]:
            key = _stable_key(item)
            if key in seen:
                continue
            seen.add(key)
            merged.append(copy.deepcopy(item))
        return merged
    # append_unique_by_tag: replace tagged entries by tag, append untagged entries uniquely.
    tagged: dict[str, Any] = {}
    untagged: list[Any] = []
    untagged_seen: set[str] = set()
    for item in base:
        tag = _item_tag(item)
        if tag is not None:
            tagged[tag] = copy.deepcopy(item)
        else:
            key = _stable_key(item)
            if key not in untagged_seen:
                untagged_seen.add(key)
                untagged.append(copy.deepcopy(item))
    for item in overlay:
        tag = _item_tag(item)
        if tag is not None:
            tagged[tag] = copy.deepcopy(item)
        else:
            key = _stable_key(item)
            if key not in untagged_seen:
                untagged_seen.add(key)
                untagged.append(copy.deepcopy(item))
    return [*tagged.values(), *untagged]


def deep_merge(base: Any, overlay: Any, *, list_strategy: str = "append") -> Any:
    if isinstance(base, dict) and isinstance(overlay, dict):
        if overlay.get(_REPLACE) is True:
            return copy.deepcopy(_strip_control_keys(overlay))
        key_strategies = overlay.get(_MERGE_STRATEGY, {})
        if key_strategies is not None and not isinstance(key_strategies, dict):
            raise ValueError(f"{_MERGE_STRATEGY} must be an object mapping child keys to strategies")
        merged = copy.deepcopy(base)
        for key, value in _strip_control_keys(overlay).items():
            child_strategy = str(key_strategies.get(key, list_strategy)) if isinstance(key_strategies, dict) else list_strategy
            if key in merged:
                merged[key] = deep_merge(merged[key], value, list_strategy=child_strategy)
            else:
                merged[key] = copy.deepcopy(value)
        return merged
    if isinstance(base, list) and isinstance(overlay, list):
        return _merge_list(base, overlay, list_strategy)
    return copy.deepcopy(overlay)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def compile_config(primary: Path, fragment_paths: List[Path]) -> Any:
    config = load_json(primary)
    for fragment_path in fragment_paths:
        config = deep_merge(config, load_json(fragment_path))
    return config


def explain_merge_controls() -> dict[str, Any]:
    return {
        "control_keys": [_MERGE_STRATEGY, _REPLACE],
        "list_strategies": sorted(_LIST_STRATEGIES),
        "default": "append",
        "recommended_for_xray_tags": "append_unique_by_tag",
    }


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
