#!/usr/bin/env python3
"""Minimal Xray semver helpers for preflight pin checks."""
from __future__ import annotations

import re


def parse_xray_version(raw: str) -> tuple[int, ...]:
    match = re.search(r"(\d+(?:\.\d+)*)", raw or "")
    if not match:
        return ()
    parts: list[int] = []
    for piece in match.group(1).split("."):
        try:
            parts.append(int(piece))
        except ValueError:
            return ()
    return tuple(parts)


def version_at_least(current: str, minimum: str) -> bool:
    cur = parse_xray_version(current)
    req = parse_xray_version(minimum)
    if not cur or not req:
        return False
    width = max(len(cur), len(req))
    cur_padded = cur + (0,) * (width - len(cur))
    req_padded = req + (0,) * (width - len(req))
    return cur_padded >= req_padded
