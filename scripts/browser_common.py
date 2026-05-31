#!/usr/bin/env python3
"""Shared settings for MITM-DomainFronting browser integration (diagnostics + stealth)."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = REPO_ROOT / "configs" / "browser-integration.json"
DEFAULT_CERT = REPO_ROOT / "Xray-config" / "mycert.crt"
DEFAULT_KEY = REPO_ROOT / "Xray-config" / "mycert.key"

CLOAKBROWSER_PROJECT_URL = "https://github.com/CloakHQ/CloakBrowser"


def load_integration_config() -> Dict[str, Any]:
    if CONFIG_PATH.exists():
        with CONFIG_PATH.open(encoding="utf-8") as f:
            return json.load(f)
    return {
        "default_proxy": "socks5://127.0.0.1:10808",
        "mixed_in_port": 10808,
        "transport_hardening_args": ["--disable-quic", "--disable-udp-proxies"],
        "stealth": {
            "engine": "cloakbrowser",
            "project_url": CLOAKBROWSER_PROJECT_URL,
            "profile_dir": "browser-profiles/stealth-cloakbrowser",
            "default_headless": False,
            "default_humanize": True,
        },
        "diagnostics": {
            "engine": "playwright-chromium",
            "profile_dir": "browser-profiles/diagnostics-playwright",
            "default_headless": False,
        },
    }


def resolve_profile_dir(relative: str) -> Path:
    path = (REPO_ROOT / relative).resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def transport_hardening_args(cfg: Optional[Dict[str, Any]] = None) -> List[str]:
    cfg = cfg or load_integration_config()
    return list(cfg.get("transport_hardening_args") or ["--disable-quic", "--disable-udp-proxies"])


def default_proxy_url(cfg: Optional[Dict[str, Any]] = None) -> str:
    cfg = cfg or load_integration_config()
    port = int(cfg.get("mixed_in_port", 10808))
    return str(cfg.get("default_proxy") or f"socks5://127.0.0.1:{port}")


def find_windows_chrome(cfg: Optional[Dict[str, Any]] = None) -> Optional[str]:
    cfg = cfg or load_integration_config()
    diag = cfg.get("diagnostics") or {}
    candidates: List[str] = list(diag.get("windows_chrome_paths") or [])
    candidates.extend([
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ])
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    return None


def base_telemetry(
    mode: str,
    *,
    proxy_url: str,
    url: str,
    browser_flavor: str,
    headless: bool,
) -> Dict[str, Any]:
    return {
        "mode": mode,
        "runtime_environment": {
            "browser_flavor": browser_flavor,
            "upstream_gateway": proxy_url,
            "is_headless": headless,
        },
        "network_telemetry": {
            "handshake_latency_ms": None,
            "established_protocol": None,
            "quic_leakage_detected": None,
            "local_mitm_decryption_verified": None,
            "certificate_chain_state": None,
        },
        "fingerprint_validation": {
            "navigator_webdriver_shadowed": None,
            "canvas_noise_injected": None,
            "tls_fingerprint_ja3_matches_browser": None,
        },
        "execution_state": {
            "target_url": url,
            "page_load_success": False,
            "dom_title": "",
            "resolved_url": "",
            "anti_bot_challenge_encountered": None,
            "mitigation_remediation": "none",
            "execution_exception": None,
        },
    }


def emit_json(payload: Dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def import_mitm_trust():
    script_dir = Path(__file__).resolve().parent
    if str(script_dir) not in sys.path:
        sys.path.insert(0, str(script_dir))
    try:
        import mitm_trust  # type: ignore

        return mitm_trust
    except Exception:
        return None


def cert_trust_hint(cert_path: Path) -> str:
    if not cert_path.exists():
        return "ca_missing_use_ignore_https_or_install_mycert"
    trust = import_mitm_trust()
    if trust is None:
        return "install_mycert_or_ignore_https_errors"
    fp = trust.public_key_fingerprint_from_cert(cert_path)
    if fp:
        return f"spki_sha256_hex={fp} (optional: --ignore-certificate-errors-spki-list after base64 encode)"
    return "install_mycert_or_ignore_https_errors"


def env_executable_override() -> Optional[str]:
    for name in ("MITM_BROWSER_EXECUTABLE", "CHROME_PATH"):
        value = os.environ.get(name, "").strip()
        if value and Path(value).exists():
            return value
    return None
