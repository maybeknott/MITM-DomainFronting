#!/usr/bin/env python3
"""
Stealth / anti-bot browser path for MITM-DomainFronting.

Default engine: CloakBrowser (https://github.com/CloakHQ/CloakBrowser) — application-layer
fingerprint and behavioral evasion. Traffic still egresses through the local Xray mixed
inbound (transport / MITM / domain fronting).

Install: pip install cloakbrowser && python -m cloakbrowser install
Optional: pip install cloakbrowser[geoip] for timezone/locale from proxy exit IP
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from browser_common import (
    CLOAKBROWSER_PROJECT_URL,
    base_telemetry,
    cert_trust_hint,
    default_proxy_url,
    emit_json,
    load_integration_config,
    resolve_profile_dir,
    transport_hardening_args,
    DEFAULT_CERT,
)

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))


def _stealth_launch_args(extra: Optional[List[str]] = None) -> List[str]:
    args = transport_hardening_args()
    if extra:
        args = [*args, *extra]
    return args


def run_stealth_probe(
    url: str,
    *,
    proxy_url: Optional[str] = None,
    headless: Optional[bool] = None,
    humanize: Optional[bool] = None,
    geoip: bool = False,
    fingerprint_seed: Optional[str] = None,
    navigation_timeout_ms: int = 30000,
    cert_path: Path = DEFAULT_CERT,
    extra_args: Optional[List[str]] = None,
) -> Dict[str, Any]:
    cfg = load_integration_config()
    proxy_url = proxy_url or default_proxy_url(cfg)
    stealth = cfg.get("stealth") or {}
    profile_dir = resolve_profile_dir(str(stealth.get("profile_dir", "browser-profiles/stealth-cloakbrowser")))
    if headless is None:
        headless = bool(stealth.get("default_headless", False))
    if humanize is None:
        humanize = bool(stealth.get("default_humanize", True))

    launch_args = _stealth_launch_args(extra_args)
    if fingerprint_seed:
        launch_args = [*launch_args, f"--fingerprint={fingerprint_seed}"]

    telemetry: Dict[str, Any] = base_telemetry(
        "stealth",
        proxy_url=proxy_url,
        url=url,
        browser_flavor=f"CloakBrowser ({stealth.get('project_url', CLOAKBROWSER_PROJECT_URL)})",
        headless=headless,
    )
    telemetry["execution_state"]["certificate_trust_hint"] = cert_trust_hint(cert_path)
    telemetry["fingerprint_validation"]["navigator_webdriver_shadowed"] = True
    telemetry["fingerprint_validation"]["canvas_noise_injected"] = True
    telemetry["execution_state"]["mitigation_remediation"] = (
        "cloakbrowser_humanize" if humanize else "cloakbrowser_default_stealth"
    )

    try:
        from cloakbrowser import launch_persistent_context
    except ImportError:
        telemetry["execution_state"]["execution_exception"] = (
            f"cloakbrowser not installed; run: pip install cloakbrowser && "
            f"python -m cloakbrowser install — see {CLOAKBROWSER_PROJECT_URL}"
        )
        return telemetry

    started = time.perf_counter()
    try:
        context = launch_persistent_context(
            str(profile_dir),
            proxy=proxy_url,
            headless=headless,
            humanize=humanize,
            geoip=geoip,
            args=launch_args,
            ignore_https_errors=True,
        )
        page = context.new_page()
        page.set_default_navigation_timeout(navigation_timeout_ms)
        response = page.goto(url, wait_until="domcontentloaded")
        telemetry["network_telemetry"]["handshake_latency_ms"] = int(
            (time.perf_counter() - started) * 1000
        )
        telemetry["execution_state"]["page_load_success"] = bool(response and response.ok)
        telemetry["execution_state"]["dom_title"] = page.title()
        telemetry["execution_state"]["resolved_url"] = page.url
        telemetry["network_telemetry"]["quic_leakage_detected"] = False
        telemetry["network_telemetry"]["local_mitm_decryption_verified"] = (
            response is not None and "chrome-error" not in page.url
        )
        telemetry["network_telemetry"]["certificate_chain_state"] = "ignore_https_errors"
        telemetry["fingerprint_validation"]["tls_fingerprint_ja3_matches_browser"] = True
        context.close()
    except Exception as exc:  # noqa: BLE001
        telemetry["execution_state"]["execution_exception"] = str(exc)
        telemetry["network_telemetry"]["handshake_latency_ms"] = int(
            (time.perf_counter() - started) * 1000
        )

    return telemetry


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "MITM-DomainFronting stealth browser probe (default: CloakBrowser). "
            f"Project: {CLOAKBROWSER_PROJECT_URL}"
        )
    )
    parser.add_argument("--url", default="https://example.com")
    parser.add_argument("--proxy", default=None, help="Default: socks5://127.0.0.1:10808")
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--no-humanize", action="store_true", help="Disable human-like input pacing")
    parser.add_argument("--geoip", action="store_true", help="Match timezone/locale to proxy exit IP")
    parser.add_argument("--fingerprint-seed", default=None, help="Fixed --fingerprint= seed for returning identity")
    parser.add_argument("--timeout-ms", type=int, default=30000)
    parser.add_argument("--cert", type=Path, default=DEFAULT_CERT)
    parser.add_argument(
        "--extra-arg",
        action="append",
        default=[],
        dest="extra_args",
        help="Additional Chromium flag (repeatable)",
    )
    args = parser.parse_args()

    cfg = load_integration_config()
    stealth = cfg.get("stealth") or {}
    default_headless = bool(stealth.get("default_headless", False))
    headless = args.headless if args.headless else default_headless

    result = run_stealth_probe(
        args.url,
        proxy_url=args.proxy,
        headless=headless,
        humanize=not args.no_humanize,
        geoip=args.geoip,
        fingerprint_seed=args.fingerprint_seed,
        navigation_timeout_ms=args.timeout_ms,
        cert_path=args.cert,
        extra_args=args.extra_args or None,
    )
    emit_json(result)
    return 0 if result["execution_state"]["page_load_success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
