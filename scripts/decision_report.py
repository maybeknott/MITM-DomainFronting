#!/usr/bin/env python3
"""Produce a deterministic, redacted local decision report."""
from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import sys
from pathlib import Path
from typing import Any, Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
from validate_config import load_json, summarize, validate_config  # noqa: E402
try:
    from trust_store_check import build_report as build_trust_store_report  # noqa: E402
except Exception:  # noqa: BLE001
    build_trust_store_report = None
try:
    from platform_capability_check import build_report as build_platform_capability_report  # noqa: E402
except Exception:  # noqa: BLE001
    build_platform_capability_report = None
try:
    from preflight import captive_portal_warning_check  # noqa: E402
except Exception:  # noqa: BLE001
    captive_portal_warning_check = None
try:
    from health_probe import build_policy_recommendation  # noqa: E402
except Exception:  # noqa: BLE001
    build_policy_recommendation = None

PROFILE_RULES = {
    "strict": "block_unknown_non_private_and_udp443",
    "balanced": "direct_fallback_with_documented_udp443_warning",
    "compatibility": "direct_fallback_for_troubleshooting",
    "debug": "redacted_diagnostics_no_payload_logging",
}


def exists(path: Path) -> bool:
    return path.exists() and path.is_file()


def key_permissions_ok(path: Path) -> bool | None:
    if not path.exists():
        return False
    if os.name == "nt":
        return None
    mode = stat.S_IMODE(path.stat().st_mode)
    return (mode & 0o077) == 0


def port_state(port: int) -> str:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.25):
            return "listening-loopback"
    except OSError:
        return "not-listening"


def dns_tags(config: Dict[str, Any]) -> Dict[str, str]:
    servers = config.get("dns", {}).get("servers", []) if isinstance(config.get("dns"), dict) else []
    tags = {server.get("tag") for server in servers if isinstance(server, dict)}
    return {
        "primary": "configured" if "no-filter-dns-cloudflare" in tags else "missing",
        "fallback": "configured" if "no-filter-dns-google" in tags else "missing",
        "local_private": "configured" if any(isinstance(server, dict) and server.get("address") == "localhost" for server in servers) else "missing",
    }


def route_summary(config: Dict[str, Any]) -> Dict[str, Any]:
    rules = config.get("routing", {}).get("rules", []) if isinstance(config.get("routing"), dict) else []
    rule_tags = [rule.get("ruleTag") for rule in rules if isinstance(rule, dict) and rule.get("ruleTag")]
    return {
        "rule_count": len(rules) if isinstance(rules, list) else 0,
        "rule_tags_present": len(rule_tags),
        "strict_direct_leak_test": "not_applicable_to_base_profile",
        "unknown_udp_policy": "explicit" if any(isinstance(rule, dict) and rule.get("network") == "udp" and str(rule.get("port")) == "443" for rule in rules) else "documented_by_profile",
    }


def trust_store_status(cert_path: Path) -> Dict[str, Any]:
    if build_trust_store_report is None:
        return {"status": "unknown", "reason": "trust_store_check import failed"}
    try:
        report = build_trust_store_report(cert_path)
        return {
            "status": report.get("status", "unknown"),
            "platform": report.get("platform"),
            "firefox": report.get("firefox"),
            "stores": report.get("store_checks", []),
        }
    except Exception as exc:  # noqa: BLE001
        return {"status": "unknown", "reason": str(exc)}


def platform_capabilities() -> Dict[str, Any]:
    if build_platform_capability_report is None:
        return {"status": "unknown", "reason": "platform_capability_check import failed"}
    try:
        report = build_platform_capability_report()
        ech = report.get("ech", {}) if isinstance(report, dict) else {}
        return {
            "status": "pass",
            "platform": report.get("platform"),
            "browsers": report.get("browsers"),
            "ech": ech,
            "network_interfaces": report.get("network_interfaces"),
        }
    except Exception as exc:  # noqa: BLE001
        return {"status": "unknown", "reason": str(exc)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a redacted MITM-DomainFronting decision report")
    parser.add_argument("--config", type=Path, default=Path("Xray-config/MITM-DomainFronting.json"))
    parser.add_argument("--cert", type=Path, default=Path("Xray-config/mycert.crt"))
    parser.add_argument("--key", type=Path, default=Path("Xray-config/mycert.key"))
    parser.add_argument("--profile", choices=sorted(PROFILE_RULES), default="balanced")
    args = parser.parse_args()

    config, checks = load_json(args.config)
    if config is not None:
        checks.extend(validate_config(config))
    validation = summarize(checks)

    report = {
        "config_version": config.get("remarks") if config else None,
        "xray_min_required": config.get("version", {}).get("min") if config else None,
        "profile": args.profile,
        "profile_policy": PROFILE_RULES[args.profile],
        "cert": {
            "crt_exists": exists(args.cert),
            "key_exists": exists(args.key),
            "key_permissions_ok": key_permissions_ok(args.key),
            "trusted_store_fingerprint_match": trust_store_status(args.cert),
        },
        "ports": {
            "10808": port_state(10808),
            "11666": port_state(11666),
            "11777": port_state(11777),
        },
        "dns": dns_tags(config or {}),
        "routing": route_summary(config or {}),
        "platform_capabilities": platform_capabilities(),
        "validation": {
            "overall": validation,
            "failures": [c for c in checks if c.get("status") == "fail"],
            "warnings": [c for c in checks if c.get("status") == "warn"],
        },
        "warnings": [
            "Android apps with certificate pinning or custom trust are unsupported unless the app cooperates.",
            "HTTP/3/QUIC behavior is profile-dependent.",
            "This report is redacted and never includes URLs, cookies, payloads, or private-key contents.",
        ],
    }
    if captive_portal_warning_check is not None:
        report["captive_portal"] = captive_portal_warning_check()
    if build_policy_recommendation is not None:
        health_checks = {
            "local_ports": [{"id": f"port_{p}", "status": "pass" if port_state(p) == "listening-loopback" else "warn", "detail": port_state(p)} for p in (10808, 11666, 11777)],
            "certificate": [{"id": "crt_exists", "status": "pass" if exists(args.cert) else "warn"}],
            "dns": [{"id": "dns_config", "status": "pass" if dns_tags(config or {}).get("primary") == "configured" else "warn"}],
            "trust_store": trust_store_status(args.cert),
        }
        report["policy_recommendation"] = build_policy_recommendation(health_checks, validation, Path("."))
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 2 if validation == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
