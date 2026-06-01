#!/usr/bin/env python3
"""
Local preflight checks for MITM-DomainFronting.

The script validates config shape, local certificate/key presence, key file
permissions, port/listener exposure, and optional DNS reachability. It does not
inspect browser traffic, request bodies, cookies, credentials, or private-key
contents.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
try:
    from validate_config import load_json, summarize, validate_config  # type: ignore
except Exception:  # noqa: BLE001
    load_json = None
    validate_config = None
    summarize = None
try:
    from platform_capability_check import build_report as build_platform_report  # type: ignore
except Exception:  # noqa: BLE001
    build_platform_report = None

EXPECTED_PORTS = [10808, 11666, 11777, 11888, 11999]
BAD_LISTEN_ADDRS = {"0.0.0.0", "::", "[::]", "*"}
LOOPBACK_ADDRS = {"127.0.0.1", "::1", "localhost"}
PROXY_ENV_VARS = {
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
}
VPN_INTERFACE_KEYWORDS = {
    "tailscale",
    "tun",
    "tap",
    "vpn",
    "wireguard",
    "wintun",
    "openvpn",
    "zerotier",
    "cloudflare warp",
}
REQUIRED_DOCS = [
    "docs/protocol-coverage.md",
    "docs/platform-compatibility.md",
    "docs/dns-resilience.md",
    "docs/fakedns-recovery.md",
    "docs/release-engineering.md",
    "docs/provider-status.md",
    "docs/tun-operational-notes.md",
    "docs/release-evidence.md",
]


def check_file(path: Path, check_id: str, label: str) -> Dict[str, str]:
    if path.exists():
        return {"id": check_id, "status": "pass", "detail": f"{label} exists: {path}"}
    return {"id": check_id, "status": "fail", "detail": f"{label} missing: {path}"}


def sha256_file(path: Path) -> Optional[str]:
    if not path.exists() or not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def check_key_permissions(key_path: Path) -> Dict[str, str]:
    if not key_path.exists():
        return {"id": "key_permissions", "status": "fail", "detail": "key missing"}
    if os.name == "nt":
        output = run_cmd(["icacls", str(key_path)], timeout=5)
        if not output:
            return {"id": "key_permissions", "status": "info", "detail": "Windows ACL unavailable; keep key private"}
        lowered = output.lower()
        broad_acl_markers = ["everyone", "builtin\\users", "authenticated users"]
        if any(marker in lowered for marker in broad_acl_markers):
            return {
                "id": "key_permissions",
                "status": "warn",
                "detail": "Windows ACL appears to include broad local users; restrict mycert.key to the current user",
            }
        return {"id": "key_permissions", "status": "pass", "detail": "Windows ACL did not show broad local user access"}
    mode = stat.S_IMODE(key_path.stat().st_mode)
    world_readable = bool(mode & stat.S_IROTH)
    group_readable = bool(mode & stat.S_IRGRP)
    if world_readable:
        return {"id": "key_permissions", "status": "warn", "detail": f"key is world-readable mode={oct(mode)}; run chmod 600 {key_path}"}
    if group_readable:
        return {"id": "key_permissions", "status": "info", "detail": f"key is group-readable mode={oct(mode)}; chmod 600 is stricter"}
    return {"id": "key_permissions", "status": "pass", "detail": f"mode={oct(mode)}"}


def openssl_cert_info(cert: Path) -> List[Dict[str, str]]:
    checks: List[Dict[str, str]] = []
    if not cert.exists():
        return checks
    openssl = "openssl.exe" if os.name == "nt" else "openssl"
    try:
        proc = subprocess.run(
            [openssl, "x509", "-in", str(cert), "-noout", "-subject", "-issuer", "-enddate", "-fingerprint", "-sha256"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001
        return [{"id": "cert_openssl", "status": "info", "detail": f"openssl not available or failed: {exc}"}]
    if proc.returncode != 0:
        return [{"id": "cert_openssl", "status": "warn", "detail": proc.stderr.strip() or "openssl failed"}]
    one_line = "; ".join(line.strip() for line in proc.stdout.splitlines() if line.strip())
    checks.append({"id": "cert_openssl", "status": "pass", "detail": one_line})
    try:
        text_proc = subprocess.run(
            [openssl, "x509", "-in", str(cert), "-noout", "-text"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001
        checks.append({"id": "cert_extensions", "status": "info", "detail": f"extension parse skipped: {exc}"})
        return checks
    if text_proc.returncode != 0:
        checks.append({"id": "cert_extensions", "status": "info", "detail": "extension parse skipped"})
        return checks
    cert_text = text_proc.stdout.lower().replace(" ", "")
    ca_ok = "ca:true" in cert_text
    key_usage_ok = "keycertsign" in cert_text or "certificatesign" in cert_text
    if ca_ok and key_usage_ok:
        checks.append({"id": "cert_extensions", "status": "pass", "detail": "CA:TRUE and keyCertSign present"})
    elif ca_ok:
        checks.append({"id": "cert_extensions", "status": "warn", "detail": "CA:TRUE present but keyCertSign not detected"})
    else:
        checks.append({"id": "cert_extensions", "status": "warn", "detail": "CA:TRUE not detected; browsers may reject this CA"})
    return checks


def can_connect_local(port: int, timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def run_cmd(cmd: List[str], timeout: float = 5.0) -> str:
    try:
        p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        return p.stdout or ""
    except Exception:
        return ""


def proxy_environment_checks() -> List[Dict[str, str]]:
    found = sorted({
        name.upper()
        for name, value in os.environ.items()
        if name.upper() in PROXY_ENV_VARS and value
    })
    if not found:
        return [{"id": "proxy_env", "status": "pass", "detail": "no standard proxy environment variables set"}]
    return [{
        "id": "proxy_env",
        "status": "warn",
        "detail": "proxy environment variables are set; review for proxy-chain loops: " + ", ".join(found),
    }]


def windows_proxy_check() -> List[Dict[str, str]]:
    if platform.system().lower() != "windows":
        return []
    key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    enabled = run_cmd(["reg", "query", key, "/v", "ProxyEnable"], timeout=3)
    server = run_cmd(["reg", "query", key, "/v", "ProxyServer"], timeout=3)
    if not enabled:
        return [{"id": "system_proxy", "status": "info", "detail": "Windows proxy registry state unavailable"}]
    enabled_on = "0x1" in enabled.lower()
    server_set = "ProxyServer" in server
    if enabled_on:
        detail = "Windows user proxy is enabled"
        if server_set:
            detail += "; proxy server value is configured but redacted"
        return [{"id": "system_proxy", "status": "warn", "detail": detail}]
    if server_set:
        return [{"id": "system_proxy", "status": "info", "detail": "Windows proxy is disabled; stored proxy server value is redacted"}]
    return [{"id": "system_proxy", "status": "pass", "detail": "Windows user proxy is disabled"}]


def interface_conflict_checks() -> List[Dict[str, str]]:
    system = platform.system().lower()
    if system == "windows":
        output = run_cmd(["netsh", "interface", "show", "interface"], timeout=5)
    else:
        output = run_cmd(["ip", "link", "show"], timeout=5) or run_cmd(["ifconfig"], timeout=5)
    if not output:
        return [{"id": "vpn_tun_interfaces", "status": "info", "detail": "interface list unavailable"}]
    lowered = output.lower()
    matched = sorted({keyword for keyword in VPN_INTERFACE_KEYWORDS if keyword in lowered})
    if matched:
        return [{
            "id": "vpn_tun_interfaces",
            "status": "warn",
            "detail": "possible VPN/TUN interface keywords observed; review capture conflicts: " + ", ".join(matched),
        }]
    return [{"id": "vpn_tun_interfaces", "status": "pass", "detail": "no common VPN/TUN interface keywords observed"}]


def collect_listener_lines() -> List[str]:
    system = platform.system().lower()
    outputs: List[str] = []
    if system == "windows":
        outputs.append(run_cmd(["netstat", "-ano", "-p", "tcp"]))
    else:
        out = run_cmd(["ss", "-ltn"])
        if out:
            outputs.append(out)
        out = run_cmd(["netstat", "-an"])
        if out:
            outputs.append(out)
        # lsof is slower and may be absent; only use if ss/netstat gave little.
    lines: List[str] = []
    for out in outputs:
        lines.extend(line.strip() for line in out.splitlines() if line.strip())
    return lines


def listener_exposure_checks(ports: List[int]) -> List[Dict[str, str]]:
    checks: List[Dict[str, str]] = []
    lines = collect_listener_lines()
    for port in ports:
        matched = [line for line in lines if f":{port}" in line or f".{port}" in line]
        if not matched:
            checks.append({"id": f"runtime_listener_{port}", "status": "info", "detail": "not currently listening or netstat/ss unavailable; client may be stopped"})
            continue
        bad = []
        good = []
        for line in matched:
            normalized = line.replace("[::]", "::")
            if "0.0.0.0" in normalized or ":::" in normalized or "*" in normalized:
                bad.append(line)
            elif "127.0.0.1" in normalized or "localhost" in normalized or "::1" in normalized:
                good.append(line)
        if bad:
            checks.append({"id": f"runtime_listener_{port}", "status": "fail", "detail": "possible non-loopback listener: " + " | ".join(bad[:3])})
        elif good:
            checks.append({"id": f"runtime_listener_{port}", "status": "pass", "detail": "loopback listener observed: " + " | ".join(good[:3])})
        else:
            checks.append({"id": f"runtime_listener_{port}", "status": "warn", "detail": "listener observed but address ambiguous: " + " | ".join(matched[:3])})
    return checks


def basic_dns_check(domain: str = "example.com", timeout: float = 3.0) -> Dict[str, str]:
    start = time.time()
    try:
        socket.setdefaulttimeout(timeout)
        results = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
        elapsed_ms = int((time.time() - start) * 1000)
        addrs = sorted({r[4][0] for r in results})
        return {"id": "system_dns", "status": "pass", "detail": f"{domain} resolved {len(addrs)} address(es) in {elapsed_ms}ms"}
    except Exception as exc:  # noqa: BLE001
        elapsed_ms = int((time.time() - start) * 1000)
        return {"id": "system_dns", "status": "warn", "detail": f"{domain} failed after {elapsed_ms}ms: {exc}"}


def captive_portal_warning_check(timeout: float = 3.0) -> Dict[str, str]:
    """Best-effort captive portal warning using the same probe as dns_lab_harness."""
    start = time.time()
    try:
        import urllib.request

        req = urllib.request.Request(
            "http://connectivitycheck.gstatic.com/generate_204",
            headers={"User-Agent": "mitm-domainfronting-preflight"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            code = int(response.getcode())
            elapsed_ms = int((time.time() - start) * 1000)
            if code == 204:
                return {
                    "id": "captive_portal",
                    "status": "pass",
                    "detail": f"connectivity check returned HTTP 204 in {elapsed_ms}ms",
                }
            return {
                "id": "captive_portal",
                "status": "warn",
                "detail": f"captive portal likely: HTTP {code} in {elapsed_ms}ms; complete network login before strict checks",
            }
    except Exception as exc:  # noqa: BLE001
        elapsed_ms = int((time.time() - start) * 1000)
        return {
            "id": "captive_portal",
            "status": "warn",
            "detail": f"captive portal possible or probe blocked after {elapsed_ms}ms: {exc}",
        }


def config_required_ports(config: Dict[str, Any]) -> List[int]:
    ports = []
    for inbound in config.get("inbounds", []) if isinstance(config.get("inbounds"), list) else []:
        port = inbound.get("port")
        if isinstance(port, int):
            ports.append(port)
    return sorted(set([p for p in ports if p in EXPECTED_PORTS] or EXPECTED_PORTS))


def documentation_checks(root: Path) -> List[Dict[str, str]]:
    checks: List[Dict[str, str]] = []
    for rel in REQUIRED_DOCS:
        path = root / rel
        checks.append({
            "id": "doc_" + rel.replace("/", "_").replace(".", "_"),
            "status": "pass" if path.exists() else "warn",
            "detail": "present" if path.exists() else f"missing: {rel}",
        })
    return checks


def geodata_checks(root: Path) -> List[Dict[str, str]]:
    checks: List[Dict[str, str]] = []
    for name in ("geosite.dat", "geoip.dat"):
        matches = [p for p in root.rglob(name) if ".git" not in p.parts]
        if matches:
            digest = sha256_file(matches[0])
            checks.append({"id": f"geodata_{name}", "status": "info", "detail": f"{matches[0]} sha256={digest}"})
        else:
            checks.append({"id": f"geodata_{name}", "status": "info", "detail": "not found in repo; record client/runtime package hash during release"})
    return checks


def platform_capability_checks() -> List[Dict[str, str]]:
    if build_platform_report is None:
        return [{"id": "platform_capabilities", "status": "info", "detail": "platform_capability_check import unavailable"}]
    try:
        report = build_platform_report()
    except Exception as exc:  # noqa: BLE001
        return [{"id": "platform_capabilities", "status": "warn", "detail": f"capability check failed: {exc}"}]
    checks: List[Dict[str, str]] = []
    browsers = report.get("browsers", [])
    browser_summary = ", ".join(
        f"{item.get('family')}:{item.get('version', 'unknown')}" for item in browsers if isinstance(item, dict)
    ) or "none detected"
    checks.append({"id": "browser_versions", "status": "info", "detail": browser_summary})
    ech = report.get("ech", {})
    if isinstance(ech, dict):
        checks.append({
            "id": "ech_capability",
            "status": str(ech.get("status", "info")),
            "detail": str(ech.get("detail", "ECH capability not evaluated")),
        })
    interfaces = report.get("network_interfaces", {})
    if isinstance(interfaces, dict):
        checks.append({
            "id": "capability_network_interfaces",
            "status": str(interfaces.get("status", "info")),
            "detail": str(interfaces.get("detail", "interface probe not available")),
        })
    return checks


def xray_config_test(config: Path, xray_bin: str) -> Dict[str, str]:
    try:
        proc = subprocess.run(
            [xray_bin, "run", "-test", "-config", str(config)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=20,
            check=False,
        )
    except FileNotFoundError:
        return {"id": "xray_run_test", "status": "info", "detail": f"{xray_bin!r} not found; skipped"}
    except Exception as exc:  # noqa: BLE001
        return {"id": "xray_run_test", "status": "warn", "detail": str(exc)}
    detail = (proc.stdout or "").strip().replace("\n", " | ")[-1200:]
    return {"id": "xray_run_test", "status": "pass" if proc.returncode == 0 else "fail", "detail": detail or f"exit={proc.returncode}"}


def emit_report(report: Dict[str, Any]) -> str:
    """Emit JSON for automation and a compact table for interactive terminals."""
    if not sys.stdout.isatty():
        return json.dumps(report, indent=2, ensure_ascii=False)

    colors = {
        "pass": "\033[92m",
        "warn": "\033[93m",
        "fail": "\033[91m",
        "info": "\033[94m",
        "reset": "\033[0m",
    }
    lines = [
        "",
        "=" * 72,
        " MITM-DomainFronting Preflight",
        "=" * 72,
    ]
    for check in report.get("checks", []):
        if not isinstance(check, dict):
            continue
        status = str(check.get("status", "info")).lower()
        color = colors.get(status, colors["info"])
        lines.append(f"[{color}{status.upper():^6}{colors['reset']}] {str(check.get('id', 'check')):<34} {check.get('detail', '')}")
    lines.extend([
        "=" * 72,
        f"Overall: {report.get('overall', 'unknown')}",
        "=" * 72,
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run local MITM-DomainFronting preflight checks")
    parser.add_argument("--config", type=Path, default=Path("Xray-config/MITM-DomainFronting.json"))
    parser.add_argument("--cert", type=Path, default=Path("Xray-config/mycert.crt"))
    parser.add_argument("--key", type=Path, default=Path("Xray-config/mycert.key"))
    parser.add_argument("--json-out", type=Path, default=None)
    parser.add_argument("--no-dns", action="store_true", help="skip system DNS resolution check")
    parser.add_argument("--skip-captive-portal", action="store_true", help="skip captive portal warning probe")
    parser.add_argument("--skip-cert", action="store_true", help="skip local certificate/key checks for CI or static-only validation")
    parser.add_argument("--skip-runtime", action="store_true", help="skip live local port/listener checks")
    parser.add_argument("--xray-bin", default=None, help="optional Xray binary for xray run -test")
    args = parser.parse_args()

    checks: List[Dict[str, str]] = []
    checks.append({"id": "platform", "status": "info", "detail": f"{platform.system()} {platform.release()} Python {platform.python_version()}"})

    checks.append(check_file(args.config, "config_exists", "config"))
    config: Optional[Dict[str, Any]] = None
    if load_json and validate_config:
        config, config_checks = load_json(args.config)
        # Avoid duplicating config_exists; keep JSON and structural checks.
        checks.extend(config_checks)
        if config is not None:
            checks.extend(validate_config(config))
    else:
        checks.append({"id": "validator_import", "status": "warn", "detail": "validate_config.py could not be imported"})

    checks.extend(proxy_environment_checks())
    checks.extend(windows_proxy_check())
    checks.extend(interface_conflict_checks())
    checks.extend(platform_capability_checks())

    if args.skip_cert:
        checks.append({"id": "cert_checks", "status": "info", "detail": "skipped by --skip-cert"})
    else:
        checks.append(check_file(args.cert, "cert_exists", "certificate"))
        checks.append(check_file(args.key, "key_exists", "private key"))
        cert_hash = sha256_file(args.cert)
        if cert_hash:
            checks.append({"id": "cert_sha256", "status": "info", "detail": cert_hash})
        checks.extend(openssl_cert_info(args.cert))
        checks.append(check_key_permissions(args.key))

    ports = config_required_ports(config) if config else EXPECTED_PORTS
    if args.skip_runtime:
        checks.append({"id": "runtime_listener_checks", "status": "info", "detail": "skipped by --skip-runtime"})
    else:
        for port in ports:
            accepts_local_connection = can_connect_local(port)
            checks.append({
                "id": f"connect_127_0_0_1_{port}",
                "status": "pass" if accepts_local_connection else "info",
                "detail": "listener accepted local TCP connection" if accepts_local_connection else "not listening on 127.0.0.1 now; OK if client is stopped",
            })
        checks.extend(listener_exposure_checks(ports))

    if not args.no_dns:
        checks.append(basic_dns_check())
    if not args.skip_captive_portal and not args.no_dns:
        checks.append(captive_portal_warning_check())
    elif args.skip_captive_portal:
        checks.append({"id": "captive_portal", "status": "info", "detail": "skipped by --skip-captive-portal"})
    checks.extend(documentation_checks(Path.cwd()))
    checks.extend(geodata_checks(Path.cwd()))
    if args.xray_bin:
        checks.append(xray_config_test(args.config, args.xray_bin))

    if summarize:
        overall = summarize(checks)
    else:
        statuses = {c.get("status") for c in checks}
        overall = "fail" if "fail" in statuses else "warn" if "warn" in statuses else "pass"

    report = {
        "overall": overall,
        "generated_by": "scripts/preflight.py",
        "note": "Review before sharing. Do not share private keys, cookies, request bodies, or full URLs with tokens.",
        "checks": checks,
    }
    if args.json_out:
        args.json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    text = emit_report(report)
    print(text)
    return 2 if overall == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
