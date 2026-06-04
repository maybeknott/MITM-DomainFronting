#!/usr/bin/env python3
"""Unit tests for profile-scoped trust broker scaffolding."""
from __future__ import annotations

import _path  # noqa: F401

import json
import tempfile
from pathlib import Path

from core.trust_broker import prepare_chromium_session, session_manifest


def test_prepare_chromium_session_builds_command() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        cert = root / "mycert.crt"
        cert.write_text("TEST CERT", encoding="utf-8")
        profile = root / "profile"
        session = prepare_chromium_session(
            browser="chromium",
            profile_dir=profile,
            proxy_url="socks5://127.0.0.1:10808",
            cert_path=cert,
            remote_debugging_port=9333,
            binary="C:\\Fake\\chromium.exe",
        )
        assert session.trust_scope == "profile-scoped-user-confirmed"
        assert f"--user-data-dir={profile.resolve()}" in session.command[1]
        assert session.command[-1] == "--disable-background-networking"
        manifest = json.loads(session_manifest(session))
        assert "warning" in manifest
        assert "user-confirmed" in manifest["warning"]


def test_missing_cert_raises() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        try:
            prepare_chromium_session(browser="chromium", profile_dir=root / "p", cert_path=root / "missing.crt")
        except FileNotFoundError:
            return
        raise AssertionError("expected FileNotFoundError")


def main() -> int:
    tests = [test_prepare_chromium_session_builds_command, test_missing_cert_raises]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
