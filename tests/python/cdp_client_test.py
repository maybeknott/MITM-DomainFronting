#!/usr/bin/env python3
"""Tests for CDP HTTP assist helpers."""
from __future__ import annotations

import _path  # noqa: F401

import json
from unittest.mock import MagicMock, patch

from core.cdp_client import assist_profile_trust_setup, wait_for_cdp_version


def test_wait_for_cdp_version_parses_json() -> None:
    payload = {"Browser": "Chrome", "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/browser/abc"}
    response = MagicMock()
    response.read.return_value = json.dumps(payload).encode("utf-8")
    response.__enter__.return_value = response
    with patch("core.cdp_client.urllib.request.urlopen", return_value=response):
        data = wait_for_cdp_version(9222, timeout_s=1.0, poll_s=0.01)
    assert data["webSocketDebuggerUrl"].startswith("ws://")


def test_assist_profile_trust_setup_opens_settings() -> None:
    version = {"webSocketDebuggerUrl": "ws://127.0.0.1:9333/devtools/browser/x"}
    tab = {"id": "TAB1", "url": "chrome://settings/security"}

    def fake_fetch(url: str, *, method: str = "GET", timeout: float = 2.0) -> dict:
        if url.endswith("/json/version"):
            return version
        if "/json/new?" in url:
            return tab
        raise AssertionError(f"unexpected url {url}")

    with patch("core.cdp_client._fetch_json", side_effect=fake_fetch):
        report = assist_profile_trust_setup(port=9333, cert_path="Xray-config/mycert.crt")
    assert report.status == "pass"
    assert report.opened_url == "chrome://settings/security"
    assert "Import Xray-config/mycert.crt" in report.detail


def main() -> int:
    test_wait_for_cdp_version_parses_json()
    print("PASS test_wait_for_cdp_version_parses_json")
    test_assist_profile_trust_setup_opens_settings()
    print("PASS test_assist_profile_trust_setup_opens_settings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
