#!/usr/bin/env python3
"""Local redacted health probe for ports, cert, trust, DNS, providers, and geodata."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import socket
import stat
import subprocess
from pathlib import Path
from typing import Dict, List

from check_dns import query_udp
from geodata_pin import build_report as geodata_report, missing_geodata_errors, verify_against_lock
from trust_store_check import build_report as trust_report

EXPECTED_PORTS = [10808, 11666, 11777]


def _status_from_checks(checks: List[Dict[str, object]]) -> str:
    statuses = {str(c.get("status", "info")) for c in checks}
    if "fail" in statuses:
        return "fail"
    if statuses.intersection({"warn", "missing", "mismatch", "unknown"}):
        return "warn"
    return "pass"


def local_port_checks() -> List[Dict[str, object]]:
    checks: List[Dict[str, object]] = []
    for port in EXPECTED_PORTS:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                checks.append({"id": f"port_{port}", "status": "pass", "detail": "listening-loopback"})
        except OSError:
            checks.append({"id": f"port_{port}", "status": "warn", "detail": "not_listening"})
    return checks


def listener_exposure_checks() -> List[Dict[str, object]]:
    try:
        from preflight import listener_exposure_checks as preflight_listener_exposure_checks
    except Exception as exc:  # noqa: BLE001
        return [{
            "id": "runtime_listener_exposure",
            "status": "info",
            "detail": f"unavailable: {exc}",
        }]
    return preflight_listener_exposure_checks(EXPECTED_PORTS)


def cert_checks(cert: Path, key: Path) -> List[Dict[str, object]]:
    checks: List[Dict[str, object]] = []
    checks.append({"id": "cert_exists", "status": "pass" if cert.exists() else "warn", "detail": str(cert)})
    checks.append({"id": "key_exists", "status": "pass" if key.exists() else "warn", "detail": str(key)})
    if key.exists():
        if os.name == "nt":
            checks.append({"id": "key_permissions", "status": "info", "detail": "Windows ACL not evaluated; keep key private"})
            return checks
        if key.stat().st_mode & stat.S_IROTH:
            checks.append({"id": "key_permissions", "status": "warn", "detail": "world-readable key file"})
        else:
            checks.append({"id": "key_permissions", "status": "pass", "detail": "no world-readable bit"})
    return checks


def dns_checks(domain: str, resolvers: List[str], timeout: float) -> List[Dict[str, object]]:
    checks: List[Dict[str, object]] = []
    for resolver in resolvers:
        result = query_udp(resolver, domain, "A", timeout)
        checks.append({
            "id": f"dns_{resolver}",
            "status": result.get("status", "warn"),
            "detail": f"rcode={result.get('rcode')} answers={result.get('answers')} elapsed_ms={result.get('elapsed_ms')}",
        })
    return checks


def provider_freshness(providers_dir: Path, stale_days: int) -> List[Dict[str, object]]:
    checks: List[Dict[str, object]] = []
    now = dt.date.today()
    for path in sorted(providers_dir.glob("*.yml")):
        last_tested = None
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("last_tested:"):
                last_tested = line.split(":", 1)[1].strip().strip('"')
                break
        if not last_tested:
            checks.append({"id": f"provider_{path.stem}", "status": "warn", "detail": "last_tested missing"})
            continue
        try:
            tested_date = dt.date.fromisoformat(last_tested)
        except ValueError:
            checks.append({"id": f"provider_{path.stem}", "status": "warn", "detail": f"invalid last_tested: {last_tested}"})
            continue
        age = (now - tested_date).days
        status = "warn" if age > stale_days else "pass"
        checks.append({"id": f"provider_{path.stem}", "status": status, "detail": f"last_tested={last_tested} age_days={age}"})
    return checks


def geodata_checks(root: Path) -> Dict[str, object]:
    current = geodata_report(root, "xray")
    lock_file = root / "release-geodata-lock.json"
    if not lock_file.exists():
        return {"status": "info", "detail": "release-geodata-lock.json not present", **current}
    lock = json.loads(lock_file.read_text(encoding="utf-8"))
    missing = missing_geodata_errors(lock, current)
    mismatches = verify_against_lock(lock, current)
    if mismatches:
        return {"status": "warn", "detail": "; ".join(mismatches), **current}
    if missing:
        return {"status": "info", "detail": "; ".join(missing), **current}
    return {"status": "pass", "detail": "geodata hashes match release-geodata-lock.json", **current}


def captive_portal_check(timeout: float = 3.0) -> Dict[str, object]:
    try:
        from preflight import captive_portal_warning_check
    except Exception as exc:  # noqa: BLE001
        return {"id": "captive_portal", "status": "info", "detail": f"unavailable: {exc}"}
    return captive_portal_warning_check(timeout=timeout)


def xray_check(config: Path, xray_bin: str | None) -> Dict[str, object]:
    if not xray_bin:
        return {"id": "xray_runtime", "status": "info", "detail": "not requested"}
    try:
        proc = subprocess.run(
            [xray_bin, "run", "-test", "-config", str(config)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=20,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001
        return {"id": "xray_runtime", "status": "warn", "detail": str(exc)}
    return {
        "id": "xray_runtime",
        "status": "pass" if proc.returncode == 0 else "warn",
        "detail": (proc.stdout or "").strip()[-700:] or f"exit={proc.returncode}",
    }


def load_profile_policy(profile: str, root: Path) -> Dict[str, str]:
    path = root / "configs" / "profiles.yml"
    if not path.exists() or profile not in {"strict", "balanced", "compatibility", "debug"}:
        return {}
    text = path.read_text(encoding="utf-8")
    block_match = None
    for line in text.splitlines():
        if line.startswith(f"  {profile}:"):
            block_match = profile
            break
    if not block_match:
        return {}
    fields: Dict[str, str] = {}
    capture = False
    for line in text.splitlines():
        if line.startswith(f"  {profile}:"):
            capture = True
            continue
        if capture:
            if line and not line.startswith("    "):
                break
            if ":" in line:
                key, value = line.strip().split(":", 1)
                fields[key.strip()] = value.strip()
    return fields


def build_policy_recommendation(checks: Dict[str, object], overall: str, root: Path) -> Dict[str, object]:
    actions: List[str] = []
    suggested_profile = "balanced"
    rationale_parts: List[str] = []

    local_ports = checks.get("local_ports", [])
    if isinstance(local_ports, list):
        not_listening = [
            c for c in local_ports
            if isinstance(c, dict) and c.get("status") == "warn" and "not_listening" in str(c.get("detail", ""))
        ]
        if not_listening:
            actions.append("Start Xray/v2rayN and confirm mixed-in on 127.0.0.1:10808 before browser or health validation.")
            rationale_parts.append("local proxy ports are not listening")

    listener_exposure = checks.get("runtime_listener_exposure", [])
    if isinstance(listener_exposure, list):
        exposed = [
            c for c in listener_exposure
            if isinstance(c, dict) and c.get("status") == "fail"
        ]
        if exposed:
            actions.append("Restrict local proxy listeners to 127.0.0.1 before using strict or balanced profiles.")
            rationale_parts.append("runtime listener exposure is not loopback-only")

    cert_checks = checks.get("certificate", [])
    if isinstance(cert_checks, list):
        if any(isinstance(c, dict) and c.get("status") == "warn" for c in cert_checks):
            actions.append("Generate or verify local mycert.crt/mycert.key and install the CA per docs/ca-install-guide.md.")
            rationale_parts.append("certificate material incomplete or weak permissions")

    trust = checks.get("trust_store", {})
    if isinstance(trust, dict) and str(trust.get("status", "unknown")) not in {"pass", "not_supported"}:
        actions.append("Install mycert.crt into the intended OS/browser trust store or use automation-only ignore_https_errors.")
        rationale_parts.append(f"trust store check reported {trust.get('status', 'unknown')}")

    dns_checks = checks.get("dns", [])
    if isinstance(dns_checks, list) and any(isinstance(c, dict) and c.get("status") != "pass" for c in dns_checks):
        actions.append("Run scripts/dns_lab_harness.py for resolver-timeout, fake-dns-lab, or captive-portal evidence.")
        suggested_profile = "compatibility"
        rationale_parts.append("DNS resolver checks did not all pass")

    providers = checks.get("providers", [])
    if isinstance(providers, list) and any(isinstance(c, dict) and c.get("status") == "warn" for c in providers):
        actions.append("Refresh provider dossier last_tested dates and rerun provider_dossier_validate.py.")
        rationale_parts.append("provider dossier evidence is stale")

    geodata = checks.get("geodata", {})
    if isinstance(geodata, dict) and geodata.get("status") == "warn":
        actions.append("Record geosite.dat/geoip.dat hashes with scripts/geodata_pin.py for release evidence.")
        rationale_parts.append("geodata lock verification warned")

    captive = checks.get("captive_portal", {})
    if isinstance(captive, dict) and captive.get("status") == "warn":
        actions.append("Complete captive portal login before strict profile or DNS validation.")
        suggested_profile = "compatibility"
        rationale_parts.append("captive portal warning active")

    xray_runtime = checks.get("xray_runtime", {})
    if isinstance(xray_runtime, dict) and xray_runtime.get("status") == "warn":
        actions.append("Run xray run -test locally with --xray-bin when validating config changes.")
        rationale_parts.append("optional Xray runtime test did not pass")

    if overall == "fail":
        suggested_profile = "compatibility"
        actions.append("Use compatibility profile while investigating; do not assume strict routing until health is green.")
    elif overall == "pass" and not actions:
        suggested_profile = "balanced"
        rationale_parts.append("health checks passed without warnings")

    profile_policy = load_profile_policy(suggested_profile, root)
    return {
        "auto_switch": False,
        "suggested_profile": suggested_profile,
        "profile_policy": {
            "purpose": profile_policy.get("purpose", ""),
            "non_private_catchall": profile_policy.get("non_private_catchall", ""),
            "udp_443": profile_policy.get("udp_443", ""),
            "source": "configs/profiles.yml",
        },
        "rationale": "; ".join(rationale_parts) if rationale_parts else "no policy adjustment suggested",
        "actions": actions,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run local health probe and emit redacted JSON")
    parser.add_argument("--config", type=Path, default=Path("Xray-config/MITM-DomainFronting.json"))
    parser.add_argument("--cert", type=Path, default=Path("Xray-config/mycert.crt"))
    parser.add_argument("--key", type=Path, default=Path("Xray-config/mycert.key"))
    parser.add_argument("--providers-dir", type=Path, default=Path("providers"))
    parser.add_argument("--resolver", action="append", default=[])
    parser.add_argument("--dns-domain", default="example.com")
    parser.add_argument("--dns-timeout", type=float, default=1.5)
    parser.add_argument("--provider-stale-days", type=int, default=45)
    parser.add_argument("--xray-bin", default=None)
    parser.add_argument("--skip-captive-portal", action="store_true")
    args = parser.parse_args()

    report: Dict[str, object] = {
        "checks": {
            "local_ports": local_port_checks(),
            "runtime_listener_exposure": listener_exposure_checks(),
            "certificate": cert_checks(args.cert, args.key),
            "dns": dns_checks(args.dns_domain, args.resolver or ["1.1.1.1", "8.8.8.8"], args.dns_timeout),
            "providers": provider_freshness(args.providers_dir, args.provider_stale_days),
            "trust_store": trust_report(args.cert),
            "geodata": geodata_checks(Path(".")),
            "xray_runtime": xray_check(args.config, args.xray_bin),
        }
    }
    if not args.skip_captive_portal:
        report["checks"]["captive_portal"] = captive_portal_check(args.dns_timeout + 1.5)
    all_checks: List[Dict[str, object]] = []
    for key, value in report["checks"].items():
        if isinstance(value, list):
            all_checks.extend(value)
        elif isinstance(value, dict):
            status = value.get("status")
            if isinstance(status, str):
                all_checks.append({"id": key, "status": status, "detail": value.get("detail", "")})
    report["overall"] = _status_from_checks(all_checks)
    report["policy_recommendation"] = build_policy_recommendation(report["checks"], str(report["overall"]), Path("."))
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["overall"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
