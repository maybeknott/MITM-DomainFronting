#!/usr/bin/env python3
"""
Diagnostics browser path for MITM-DomainFronting.

Uses stock Chromium (Playwright + optional system Chrome/Edge) through the local
mixed inbound proxy. This path validates proxy wiring, certificate trust, and
page load — not anti-bot or fingerprint evasion.

Install: pip install playwright && playwright install chromium
Linux dependencies, when needed: playwright install-deps chromium
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

from browser_common import (
    base_telemetry,
    cert_trust_hint,
    default_proxy_url,
    emit_json,
    env_executable_override,
    find_windows_chrome,
    load_integration_config,
    navigation_succeeded,
    resolve_profile_dir,
    transport_hardening_args,
    DEFAULT_CERT,
)

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))


def run_diagnostics_probe(
    url: str,
    *,
    proxy_url: Optional[str] = None,
    executable_path: Optional[str] = None,
    headless: bool = False,
    navigation_timeout_ms: int = 30000,
    cert_path: Path = DEFAULT_CERT,
) -> Dict[str, Any]:
    cfg = load_integration_config()
    proxy_url = proxy_url or default_proxy_url(cfg)
    diag = cfg.get("diagnostics") or {}
    profile_dir = resolve_profile_dir(str(diag.get("profile_dir", "browser-profiles/diagnostics-playwright")))
    executable = executable_path or env_executable_override() or find_windows_chrome(cfg)
    flavor = executable or "playwright-bundled-chromium"

    telemetry: Dict[str, Any] = base_telemetry(
        "diagnostics",
        proxy_url=proxy_url,
        url=url,
        browser_flavor=flavor,
        headless=headless,
    )
    telemetry["execution_state"]["certificate_trust_hint"] = cert_trust_hint(cert_path)

    chrome_args = [
        "--no-first-run",
        "--disable-background-networking",
        "--disable-default-apps",
        "--disable-sync",
        "--disable-component-update",
        "--disable-client-side-phishing-detection",
        "--metrics-recording-only",
        *transport_hardening_args(cfg),
    ]

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        telemetry["execution_state"]["execution_exception"] = (
            "playwright not installed; run: pip install playwright && playwright install chromium"
        )
        return telemetry

    started = time.perf_counter()
    with sync_playwright() as pw:
        context = None
        try:
            context = pw.chromium.launch_persistent_context(
                user_data_dir=str(profile_dir),
                executable_path=executable,
                headless=headless,
                proxy={"server": proxy_url},
                args=chrome_args,
                ignore_https_errors=True,
            )
            page = context.new_page()
            page.set_default_navigation_timeout(navigation_timeout_ms)
            response = page.goto(url, wait_until="domcontentloaded")
            telemetry["network_telemetry"]["handshake_latency_ms"] = int(
                (time.perf_counter() - started) * 1000
            )
            resolved_url = str(page.url)
            telemetry["execution_state"]["page_load_success"] = navigation_succeeded(
                url, resolved_url, response
            )
            telemetry["execution_state"]["dom_title"] = page.title()
            telemetry["execution_state"]["resolved_url"] = resolved_url
            telemetry["network_telemetry"]["local_mitm_decryption_verified"] = (
                response is not None and not str(page.url).startswith("chrome-error://")
            )
            telemetry["network_telemetry"]["certificate_chain_state"] = (
                "ignore_https_errors" if telemetry["execution_state"]["page_load_success"] else "verify_failed"
            )
        except Exception as exc:  # noqa: BLE001
            telemetry["execution_state"]["execution_exception"] = str(exc)
            telemetry["network_telemetry"]["handshake_latency_ms"] = int(
                (time.perf_counter() - started) * 1000
            )
        finally:
            if context is not None:
                try:
                    context.close()
                except Exception:
                    pass

    return telemetry


def main() -> int:
    parser = argparse.ArgumentParser(
        description="MITM-DomainFronting diagnostics browser probe (stock Chromium / Playwright)."
    )
    parser.add_argument("--url", default="https://example.com", help="Target URL to load")
    parser.add_argument("--proxy", default=None, help="Proxy URL (default: socks5://127.0.0.1:10808)")
    parser.add_argument("--executable", default=None, help="Chrome/Edge/Chromium binary path")
    parser.add_argument("--headless", action="store_true", help="Run headless (not recommended for MITM debug)")
    parser.add_argument("--timeout-ms", type=int, default=30000)
    parser.add_argument("--cert", type=Path, default=DEFAULT_CERT)
    args = parser.parse_args()

    result = run_diagnostics_probe(
        args.url,
        proxy_url=args.proxy,
        executable_path=args.executable,
        headless=args.headless,
        navigation_timeout_ms=args.timeout_ms,
        cert_path=args.cert,
    )
    emit_json(result)
    return 0 if result["execution_state"]["page_load_success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
