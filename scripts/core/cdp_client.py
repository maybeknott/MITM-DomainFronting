#!/usr/bin/env python3
"""Minimal Chrome DevTools HTTP helpers (no WebSocket dependency).

Opens operator-assist tabs in an isolated Chromium profile with remote debugging.
Does not import CAs silently or patch trust stores.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CdpAssistReport:
    port: int
    action: str
    status: str
    detail: str
    browser: str = ""
    web_socket_url: str = ""
    opened_url: str = ""


def _fetch_json(url: str, *, method: str = "GET", timeout: float = 2.0) -> dict[str, Any]:
    request = urllib.request.Request(url, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        payload = response.read().decode("utf-8")
    data = json.loads(payload)
    if not isinstance(data, dict):
        raise ValueError("expected JSON object")
    return data


def wait_for_cdp_version(port: int, *, timeout_s: float = 12.0, poll_s: float = 0.35) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last_error = "CDP endpoint not ready"
    url = f"http://127.0.0.1:{port}/json/version"
    while time.monotonic() < deadline:
        try:
            return _fetch_json(url, timeout=min(2.0, timeout_s))
        except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError) as exc:
            last_error = str(exc)
            time.sleep(poll_s)
    raise TimeoutError(last_error)


def open_debugger_tab(port: int, target_url: str, *, timeout: float = 3.0) -> dict[str, Any]:
    encoded = urllib.parse.quote(target_url, safe=":/?#[]@!$&'()*+,;=")
    url = f"http://127.0.0.1:{port}/json/new?{encoded}"
    try:
        return _fetch_json(url, method="PUT", timeout=timeout)
    except urllib.error.HTTPError:
        return _fetch_json(f"http://127.0.0.1:{port}/json/new?{encoded}", timeout=timeout)


def assist_profile_trust_setup(
    *,
    port: int,
    cert_path: str,
    browser: str = "chromium",
    settings_url: str = "chrome://settings/security",
    wait_timeout_s: float = 12.0,
) -> CdpAssistReport:
    """Wait for CDP, open certificate settings, return operator-facing status."""
    try:
        version = wait_for_cdp_version(port, timeout_s=wait_timeout_s)
    except TimeoutError as exc:
        return CdpAssistReport(
            port=port,
            action="cdp_assist",
            status="fail",
            detail=f"Remote debugging not reachable on 127.0.0.1:{port}: {exc}",
            browser=browser,
        )
    ws_url = str(version.get("webSocketDebuggerUrl") or "")
    try:
        tab = open_debugger_tab(port, settings_url)
    except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError) as exc:
        return CdpAssistReport(
            port=port,
            action="cdp_assist",
            status="warn",
            detail=f"CDP reachable but could not open settings tab: {exc}",
            browser=browser,
            web_socket_url=ws_url,
        )
    tab_id = str(tab.get("id") or "")
    detail = (
        f"Opened {settings_url} in isolated profile (tab={tab_id or 'unknown'}). "
        f"Import {cert_path} manually for this profile only. No silent trust-store writes."
    )
    return CdpAssistReport(
        port=port,
        action="cdp_assist",
        status="pass",
        detail=detail,
        browser=browser,
        web_socket_url=ws_url,
        opened_url=settings_url,
    )
