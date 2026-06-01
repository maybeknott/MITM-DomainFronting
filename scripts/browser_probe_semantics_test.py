#!/usr/bin/env python3
"""Tiny script-level regression checks for browser probe success semantics."""
from __future__ import annotations

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from browser_common import navigation_succeeded  # noqa: E402


class _DummyResponse:
    def __init__(self, ok: bool) -> None:
        self.ok = ok


def main() -> int:
    checks = [
        (
            "about_blank_success_without_response",
            navigation_succeeded("about:blank", "about:blank", None),
            True,
        ),
        (
            "file_url_success_without_response",
            navigation_succeeded("file:///tmp/test.html", "file:///tmp/test.html", None),
            True,
        ),
        (
            "https_requires_ok_response_pass",
            navigation_succeeded("https://example.com", "https://example.com", _DummyResponse(True)),
            True,
        ),
        (
            "https_requires_ok_response_fail_missing",
            navigation_succeeded("https://example.com", "https://example.com", None),
            False,
        ),
        (
            "https_requires_ok_response_fail_not_ok",
            navigation_succeeded("https://example.com", "https://example.com", _DummyResponse(False)),
            False,
        ),
    ]
    failed = False
    for name, actual, expected in checks:
        if actual != expected:
            failed = True
            print(f"FAIL {name}: expected={expected} actual={actual}")
        else:
            print(f"PASS {name}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
