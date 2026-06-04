#!/usr/bin/env python3
"""Produce a deterministic, redacted local decision report."""
from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import sys
import time
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
    from health_probe import build_policy_recommendation, provider_freshness  # noqa: E402
except Exception:  # noqa: BLE001
    build_policy_recommendation = None
    provider_freshness = None
try:
    from geodata_pin import build_report as geodata_report, missing_geodata_errors, verify_against_lock  # noqa: E402
except Exception:  # noqa: BLE001
    geodata_report = None
try:
    from core.failure_classifier import derive_strategy_labels, run_staged_probe  # noqa: E402
except Exception:  # noqa: BLE001
    derive_strategy_labels = None
    run_staged_probe = None
try:
    from core.strategy_profiles import recommend_profile  # noqa: E402
except Exception:  # noqa: BLE001
    recommend_profile = None

PROFILE_RULES = {
    "strict": "block_unknown_non_private_and_udp443",
    "balanced": "direct_fallback_with_documented_udp443_warning",
    "compatibility": "direct_fallback_for_troubleshooting",
    "debug": "redacted_diagnostics_no_payload_logging",
}

DECISION_REPORT_SCHEMA_VERSION = 2
PHASE_DIAGNOSTICS_SCHEMA_VERSION = 1
VALID_PHASES = {
    "healthy",
    "dns_poisoned_or_failed",
    "dns_resolution_failed",
    "dns_poisoned",
    "dns_timeout",
    "tcp_timeout_blackhole",
    "tcp_timeout",
    "tcp_refused",
    "tcp_failed",
    "tls_alert_or_rst",
    "tls_alert",
    "tls_silent_drop",
    "alpn_mismatch",
    "http_status_bad",
    "first_byte_timeout",
    "throughput_stall",
    "cert_missing",
    "cert_untrusted",
    "port_occupied",
    "xray_config_invalid",
    "probe_unavailable",
}

PHASE_ACTION_MAP = {
    "healthy": ("maintain_current_profile", "All staged phases completed successfully."),
    "dns_resolution_failed": ("switch_dns_resolver_profile", "Target failed at DNS resolution stage."),
    "dns_poisoned_or_failed": ("switch_dns_resolver_profile", "Target failed at DNS resolution stage."),
    "dns_timeout": ("switch_dns_resolver_profile", "DNS queries timed out before address resolution."),
    "tcp_timeout_blackhole": ("swap_cdn_edge_ip", "Edge IP path timed out during TCP connect."),
    "tcp_refused": ("swap_cdn_edge_ip", "Edge path actively refused the connection."),
    "tcp_failed": ("swap_cdn_edge_ip", "TCP connect failed before TLS state could begin."),
    "tls_alert_or_rst": ("rotate_fronted_sni", "TLS handshake was rejected or reset."),
    "tls_silent_drop": ("rotate_fronted_sni", "TLS handshake timed out after TCP connect."),
    "alpn_mismatch": ("rotate_fronted_sni", "ALPN was not negotiated cleanly for this path."),
    "throughput_stall": ("manual_review_required", "Connection stalled after handshake completion."),
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


def geodata_summary(root: Path) -> Dict[str, Any]:
    if geodata_report is None:
        return {"status": "unknown", "reason": "geodata_pin import failed"}
    current = geodata_report(root, "xray")
    lock_file = root / "release-geodata-lock.json"
    if not lock_file.exists():
        return {"status": "info", "detail": "release-geodata-lock.json not present", **current}
    lock = json.loads(lock_file.read_text(encoding="utf-8"))
    mismatches = verify_against_lock(lock, current)
    missing = missing_geodata_errors(lock, current)
    if mismatches:
        return {"status": "warn", "detail": "; ".join(mismatches), **current}
    if missing:
        return {"status": "info", "detail": "; ".join(missing), **current}
    return {"status": "pass", "detail": "geodata hashes match release-geodata-lock.json", **current}


def phase_recommendation(phase: str) -> Dict[str, Any]:
    action, reason = PHASE_ACTION_MAP.get(phase, ("manual_review_required", "Phase classification was inconclusive."))
    return {
        "auto_switch_safe": False,
        "action": action,
        "reason": reason,
    }


def normalize_phase(phase: str) -> str:
    aliases = {
        "dns_failed": "dns_resolution_failed",
        "dns_poisoned_or_failed": "dns_resolution_failed",
        "tcp_connect_timeout": "tcp_timeout",
        "tls_timeout": "tls_silent_drop",
        "tls_eof": "tls_alert_or_rst",
    }
    candidate = aliases.get(phase, phase)
    return candidate if candidate in VALID_PHASES else "probe_unavailable"


def phase_validation_block(raw_phase: str, normalized_phase: str) -> Dict[str, Any]:
    return {
        "status": "pass" if raw_phase == normalized_phase and normalized_phase in VALID_PHASES else "warn",
        "raw_phase": raw_phase,
        "normalized_phase": normalized_phase,
        "allowed_values_count": len(VALID_PHASES),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a redacted MITM-DomainFronting decision report")
    parser.add_argument("--config", type=Path, default=Path("Xray-config/MITM-DomainFronting.json"))
    parser.add_argument("--cert", type=Path, default=Path("Xray-config/mycert.crt"))
    parser.add_argument("--key", type=Path, default=Path("Xray-config/mycert.key"))
    parser.add_argument("--profile", choices=sorted(PROFILE_RULES), default="balanced")
    parser.add_argument(
        "--target-sni",
        "--target",
        "--sni",
        dest="target_sni",
        default="",
        help="Optional host/SNI for staged DNS/TCP/TLS/ALPN phase probe",
    )
    parser.add_argument("--provider-family", default="unknown", help="Optional provider family label for phase probe output")
    parser.add_argument("--probe-port", type=int, default=443, help="Destination port for staged probe")
    parser.add_argument("--probe-timeout", type=float, default=5.0, help="Timeout (seconds) for each staged probe boundary")
    parser.add_argument("--session-counter", type=int, default=0, help="Deterministic pool index for strategy recommendation")
    parser.add_argument("--leak-hint", action="append", default=[], help="Optional leak label hints (dns_leak, webrtc_leak, ...)")
    parser.add_argument("--json-out", type=Path, default=None, help="Optional file path to save JSON output")
    args = parser.parse_args()

    config, checks = load_json(args.config)
    if config is not None:
        checks.extend(validate_config(config))
    validation = summarize(checks)

    report = {
        "report_schema_version": DECISION_REPORT_SCHEMA_VERSION,
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
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
        "geodata": geodata_summary(Path(".")),
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
        root = Path(".")
        health_checks = {
            "local_ports": [{"id": f"port_{p}", "status": "pass" if port_state(p) == "listening-loopback" else "warn", "detail": port_state(p)} for p in (10808, 11666, 11777)],
            "certificate": [{"id": "crt_exists", "status": "pass" if exists(args.cert) else "warn"}],
            "dns": [{"id": "dns_config", "status": "pass" if dns_tags(config or {}).get("primary") == "configured" else "warn"}],
            "trust_store": trust_store_status(args.cert),
            "geodata": report.get("geodata", {}),
            "captive_portal": report.get("captive_portal", {}),
        }
        if provider_freshness is not None and (root / "providers").exists():
            health_checks["providers"] = provider_freshness(root / "providers", 45)
        report["policy_recommendation"] = build_policy_recommendation(health_checks, validation, root)
    probe = None
    if args.target_sni and run_staged_probe is not None:
        probe = run_staged_probe(host=args.target_sni, port=args.probe_port, timeout=args.probe_timeout)
        raw_phase = probe.phase_classification
        normalized_phase = normalize_phase(raw_phase)
        report["phase_diagnostics"] = {
            "phase_schema_version": PHASE_DIAGNOSTICS_SCHEMA_VERSION,
            "diagnostic_run_id": f"diag_{int(time.time())}",
            "target": args.target_sni,
            "provider_family": args.provider_family,
            "phase_classification": normalized_phase,
            "confidence_score": round(probe.confidence_score, 3),
            "telemetry": probe.to_dict()["telemetry"],
            "transport_probe_mode": "tls_no_cert_validation",
            "phase_validation": phase_validation_block(raw_phase, normalized_phase),
            "actionable_recommendation": phase_recommendation(normalized_phase),
        }
    elif args.target_sni and run_staged_probe is None:
        report["phase_diagnostics"] = {
            "phase_schema_version": PHASE_DIAGNOSTICS_SCHEMA_VERSION,
            "diagnostic_run_id": f"diag_{int(time.time())}",
            "target": args.target_sni,
            "provider_family": args.provider_family,
            "phase_classification": "probe_unavailable",
            "confidence_score": 0.0,
            "telemetry": {},
            "transport_probe_mode": "unavailable",
            "phase_validation": phase_validation_block("probe_unavailable", "probe_unavailable"),
            "actionable_recommendation": {
                "auto_switch_safe": False,
                "action": "manual_review_required",
                "reason": "failure_classifier import failed",
            },
        }
    if recommend_profile is not None:
        labels: tuple[str, ...] = ()
        if derive_strategy_labels is not None:
            labels = derive_strategy_labels(probe, leak_hints=tuple(args.leak_hint or ()))
        try:
            decision = recommend_profile(
                failure_labels=labels,
                operator_intent=args.profile,
                session_counter=max(0, int(args.session_counter)),
            )
            report["strategy_recommendation"] = {
                "selected_profile_id": decision.selected_profile_id,
                "selected_profile_path": decision.selected_profile_path,
                "reason": decision.reason,
                "confidence": decision.confidence,
                "confirmation_required": decision.confirmation_required,
                "failure_labels": list(labels),
                "evidence": decision.evidence,
            }
        except ValueError as exc:
            report["strategy_recommendation"] = {
                "status": "unavailable",
                "reason": str(exc),
                "failure_labels": list(labels),
            }
    output = json.dumps(report, indent=2, ensure_ascii=False)
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(output + "\n", encoding="utf-8")
    print(output)
    return 2 if validation == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
