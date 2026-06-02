#!/usr/bin/env python3
"""Regression checks for config-src fragment merge."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import _path  # noqa: F401

from config_src_merge import compile_config, deep_merge  # noqa: E402


def test_deep_merge_dict_and_list() -> None:
    base = {"routing": {"rules": [{"ruleTag": "a"}]}, "remarks": "base"}
    overlay = {"routing": {"rules": [{"ruleTag": "b"}]}, "log": {"loglevel": "warning"}}
    merged = deep_merge(base, overlay)
    assert merged["remarks"] == "base"
    assert merged["log"] == {"loglevel": "warning"}
    assert [rule["ruleTag"] for rule in merged["routing"]["rules"]] == ["a", "b"]


def test_compile_config_from_files() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        primary = root / "primary.json"
        fragment = root / "fragment.json"
        primary.write_text(json.dumps({"remarks": "primary", "routing": {"rules": []}}), encoding="utf-8")
        fragment.write_text(json.dumps({"routing": {"rules": [{"ruleTag": "r001"}]}}), encoding="utf-8")
        compiled = compile_config(primary, [fragment])
        assert compiled["remarks"] == "primary"
        assert compiled["routing"]["rules"] == [{"ruleTag": "r001"}]


def main() -> int:
    tests = [test_deep_merge_dict_and_list, test_compile_config_from_files]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
