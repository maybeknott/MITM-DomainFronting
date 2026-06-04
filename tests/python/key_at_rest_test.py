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


def test_dpapi_wrap_unwrap_roundtrip() -> None:
    from core.key_at_rest import dpapi_available, dpapi_sidecar_path, unwrap_key_dpapi, wrap_key_dpapi

    if not dpapi_available():
        print("SKIP test_dpapi_wrap_unwrap_roundtrip (non-Windows)")
        return
    with tempfile.TemporaryDirectory() as tmp:
        key = Path(tmp) / "mycert.key"
        key.write_text("secret-key-material", encoding="utf-8")
        wrap = wrap_key_dpapi(key)
        assert wrap.status == "pass"
        assert dpapi_sidecar_path(key).exists()
        key.unlink()
        unwrap = unwrap_key_dpapi(key)
        assert unwrap.status == "pass"
        assert key.read_text(encoding="utf-8") == "secret-key-material"


def main() -> int:
    test_restrict_key_permissions_posix()
    print("PASS test_restrict_key_permissions_posix")
    test_dpapi_wrap_unwrap_roundtrip()
    print("PASS test_dpapi_wrap_unwrap_roundtrip")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
