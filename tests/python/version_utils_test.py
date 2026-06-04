#!/usr/bin/env python3
"""Tests for Xray version pin helpers."""
from __future__ import annotations

import _path  # noqa: F401

from core.version_utils import parse_xray_version, version_at_least


def test_parse_xray_version_extracts_semver() -> None:
    assert parse_xray_version("Xray 26.2.6 (Xray, Penetrates Everything.)") == (26, 2, 6)


def test_version_at_least_compares_tuple() -> None:
    assert version_at_least("26.2.6", "26.2.6")
    assert version_at_least("26.3.0", "26.2.6")
    assert not version_at_least("26.1.9", "26.2.6")


def main() -> int:
    for test in (test_parse_xray_version_extracts_semver, test_version_at_least_compares_tuple):
        test()
        print(f"PASS {test.__name__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
