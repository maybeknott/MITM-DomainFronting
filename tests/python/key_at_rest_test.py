#!/usr/bin/env python3
"""Tests for private-key ACL restriction helper."""
from __future__ import annotations

import _path  # noqa: F401

import os
import stat
import tempfile
from pathlib import Path

from core.key_at_rest import restrict_key_permissions


def test_restrict_key_permissions_posix() -> None:
    if os.name == "nt":
        print("SKIP test_restrict_key_permissions_posix (Windows)")
        return
    with tempfile.TemporaryDirectory() as tmp:
        key = Path(tmp) / "mycert.key"
        key.write_text("secret", encoding="utf-8")
        key.chmod(0o644)
        report = restrict_key_permissions(key)
        assert report.status == "pass"
        mode = stat.S_IMODE(key.stat().st_mode)
        assert mode == 0o600


def main() -> int:
    test_restrict_key_permissions_posix()
    print("PASS test_restrict_key_permissions_posix")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
