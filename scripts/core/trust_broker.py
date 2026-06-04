#!/usr/bin/env python3
"""Consent-based profile-scoped browser launch helper.

The broker prepares an isolated Chromium profile and proxy command line. It does
not silently install a CA, patch browser stores, inject DLLs, or modify system
trust. Certificate trust remains a user-confirmed profile operation documented in
the CA/browser guides.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from core.cdp_client import assist_profile_trust_setup


@dataclass(frozen=True)
class BrowserTrustSession:
    browser: str
    binary: str
    profile_dir: str
    proxy_url: str
    remote_debugging_port: int
    cert_path: str
    trust_scope: str
    command: list[str]


def prepare_chromium_session(
    *,
    browser: str,
    profile_dir: Path,
    proxy_url: str = "socks5://127.0.0.1:10808",
    cert_path: Path = Path("Xray-config/mycert.crt"),
    remote_debugging_port: int = 9222,
    binary: str | None = None,
) -> BrowserTrustSession:
    resolved_binary = binary or _find_chromium_binary(browser)
    profile_dir = profile_dir.expanduser().resolve()
    cert_path = cert_path.expanduser().resolve()
    if not cert_path.exists():
        raise FileNotFoundError(f"certificate not found: {cert_path}")
    if remote_debugging_port < 1024 or remote_debugging_port > 65535:
        raise ValueError("remote_debugging_port must be between 1024 and 65535")
    profile_dir.mkdir(parents=True, exist_ok=True)
    command = [
        resolved_binary,
        f"--user-data-dir={profile_dir}",
        f"--proxy-server={proxy_url}",
        f"--remote-debugging-port={remote_debugging_port}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
    ]
    return BrowserTrustSession(
        browser=browser,
        binary=resolved_binary,
        profile_dir=str(profile_dir),
        proxy_url=proxy_url,
        remote_debugging_port=remote_debugging_port,
        cert_path=str(cert_path),
        trust_scope="profile-scoped-user-confirmed",
        command=command,
    )


def launch_session(session: BrowserTrustSession) -> subprocess.Popen[bytes]:
    return subprocess.Popen(session.command, cwd=str(Path.cwd()))  # noqa: S603


def session_manifest(session: BrowserTrustSession) -> str:
    payload = asdict(session)
    payload["warning"] = (
        "This broker only launches an isolated profile. Import/trust of the local CA "
        "must remain user-confirmed and profile-scoped."
    )
    payload["cdp_trust_steps"] = cdp_cert_import_steps(session)
    return json.dumps(payload, indent=2, sort_keys=True)


def cdp_cert_import_steps(session: BrowserTrustSession) -> list[str]:
    """Operator-visible CDP/profile trust steps — no silent store writes."""
    port = session.remote_debugging_port
    return [
        f"Launch the isolated profile (command already prepared for port {port}).",
        "Run CDP assist (GUI or mitm_trust cdp-assist) to open chrome://settings/security in that profile.",
        f"Import {session.cert_path} as a user-trusted CA for this profile only.",
        "Verify MITM only after explicit import; the broker never patches cert9.db or system stores.",
        f"CDP endpoint: http://127.0.0.1:{port}/json/version",
    ]


def run_cdp_trust_assist(
    session: BrowserTrustSession,
    *,
    wait_timeout_s: float = 12.0,
) -> dict[str, object]:
    report = assist_profile_trust_setup(
        port=session.remote_debugging_port,
        cert_path=session.cert_path,
        browser=session.browser,
        wait_timeout_s=wait_timeout_s,
    )
    return {
        "port": report.port,
        "action": report.action,
        "status": report.status,
        "detail": report.detail,
        "browser": report.browser,
        "web_socket_url": report.web_socket_url,
        "opened_url": report.opened_url,
    }


def launch_session_with_cdp_assist(
    session: BrowserTrustSession,
    *,
    wait_timeout_s: float = 12.0,
    startup_delay_s: float = 1.0,
) -> tuple[subprocess.Popen[bytes], dict[str, object]]:
    proc = launch_session(session)
    time.sleep(startup_delay_s)
    assist = run_cdp_trust_assist(session, wait_timeout_s=wait_timeout_s)
    return proc, assist


def _find_chromium_binary(browser: str) -> str:
    key = browser.strip().lower()
    candidates: tuple[str, ...]
    if key in {"chrome", "google-chrome"}:
        candidates = ("chrome", "chrome.exe", "google-chrome", "google-chrome-stable")
    elif key in {"edge", "msedge"}:
        candidates = ("msedge", "msedge.exe", "microsoft-edge")
    elif key in {"chromium", "chromium-browser"}:
        candidates = ("chromium", "chromium-browser", "chromium.exe")
    else:
        raise ValueError("browser must be one of: chrome, edge, chromium")
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    raise FileNotFoundError(f"{browser} binary not found in PATH")
