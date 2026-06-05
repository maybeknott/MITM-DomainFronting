#!/usr/bin/env python3
"""Shared settings for Xray-Cooperative-Overlay browser integration (diagnostics + stealth)."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import re

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
        # Two honest buckets instead of one ambiguous one:
        # - `engine_capabilities` captures what the stealth engine is configured
        #   to do once it launches (a claim, true by construction).
        # - `fingerprint_validation` is reserved for measurements against an
        #   external oracle. It must never be fabricated to True.
        "engine_capabilities": {
            "navigator_webdriver_shadowed": None,
            "canvas_noise_injected": None,
        },
        "fingerprint_validation": {
            "tls_fingerprint_ja3_matches_browser": None,
            "observed_ja3": None,
            "expected_ja3": None,
            "verification_method": "not_measured",
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


def verify_ja3_against_oracle(
    page: Any,
    oracle_url: str,
    *,
    expected_ja3: Optional[str] = None,
    timeout_ms: int = 15000,
) -> Dict[str, Any]:
    """
    Measure the live TLS fingerprint by navigating to a JA3-echo oracle and
    reading the JA3/JA3-hash it reports back.

    JA3 is a property of the TLS ClientHello on the wire; it cannot be observed
    from browser JavaScript. This helper is therefore intentionally opt-in and
    relies on an operator-supplied oracle URL they trust.
    """
    result: Dict[str, Any] = {
        "tls_fingerprint_ja3_matches_browser": None,
        "observed_ja3": None,
        "expected_ja3": expected_ja3,
        "verification_method": "ja3_echo_oracle",
    }
    try:
        response = page.goto(oracle_url, wait_until="domcontentloaded", timeout=timeout_ms)
    except Exception as exc:  # noqa: BLE001
        result["verification_method"] = f"ja3_echo_oracle_error:{exc}"
        return result

    observed = _extract_ja3_from_oracle(page, response)
    result["observed_ja3"] = observed
    if observed is None:
        result["verification_method"] = "ja3_echo_oracle_no_ja3_in_response"
        return result

    if expected_ja3:
        result["tls_fingerprint_ja3_matches_browser"] = (
            observed.strip().lower() == expected_ja3.strip().lower()
        )
    try:
        from core.ja3_evidence import build_evidence, save_evidence

        save_evidence(
            build_evidence(
                oracle_url=oracle_url,
                expected_ja3=expected_ja3,
                observed_ja3=observed,
                verification_method=str(result.get("verification_method") or "ja3_echo_oracle"),
            )
        )
    except Exception:  # noqa: BLE001
        pass
    return result


def _extract_ja3_from_oracle(page: Any, response: Any) -> Optional[str]:
    """
    Best-effort extraction of a JA3 value from a JA3 echo service.

    Tries JSON first (common shapes: {"ja3": ...}, {"ja3_hash": ...},
    {"tls": {"ja3": ...}}), then falls back to scraping a 32-hex token from the
    rendered page content.
    """
    if response is not None:
        try:
            body = response.json()
            candidate = _ja3_from_mapping(body)
            if candidate:
                return candidate
        except Exception:  # noqa: BLE001
            pass

    try:
        text = page.content()
    except Exception:  # noqa: BLE001
        return None
    match = re.search(r"\b[0-9a-f]{32}\b", text.lower())
    if match:
        return match.group(0)
    return None


def _ja3_from_mapping(body: Any) -> Optional[str]:
    if isinstance(body, dict):
        for key in ("ja3_hash", "ja3", "ja3_md5", "fingerprint"):
            value = body.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        for value in body.values():
            nested = _ja3_from_mapping(value)
            if nested:
                return nested
    return None


def navigation_succeeded(target_url: str, resolved_url: str, response: Any) -> bool:
    """
    Decide whether page navigation succeeded.

    HTTP(S) targets require a successful HTTP response object.
    Non-HTTP targets (about:, file:, data:, etc.) are considered successful
    when navigation completes and resolves to a URL without exceptions.
    """
    target_scheme = urlparse(target_url).scheme.lower()
    if target_scheme in {"http", "https"}:
        return bool(response is not None and bool(getattr(response, "ok", False)))
    if resolved_url:
        return True
    return response is not None


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
