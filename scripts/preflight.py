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

EXPECTED_PORTS = [10808, 11666, 11777]
BAD_LISTEN_ADDRS = {"0.0.0.0", "::", "[::]", "*"}
LOOPBACK_ADDRS = {"127.0.0.1", "::1", "localhost"}
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
        return {"id": "key_permissions", "status": "info", "detail": "Windows ACL not evaluated; keep key private"}
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


def config_required_ports(config: Dict[str, Any]) -> List[int]:
    ports = []
    for inbound in config.get("inbounds", []) if isinstance(config.get("inbounds"), list) else []:
        port = inbound.get("port")
        if isinstance(port, int):
            ports.append(port)
    return sorted(set([p for p in ports if p in EXPECTED_PORTS] or EXPECTED_PORTS))


def udp443_policy_check(config: Dict[str, Any]) -> Dict[str, str]:
    rules = config.get("routing", {}).get("rules", []) if isinstance(config.get("routing"), dict) else []
    has_explicit_udp443 = any(
        isinstance(rule, dict)
        and rule.get("network") == "udp"
        and str(rule.get("port")) in {"443", "0-65535"}
        for rule in rules
    )
    if has_explicit_udp443:
        return {"id": "udp443_policy", "status": "pass", "detail": "explicit UDP/443 policy rule present"}
    return {"id": "udp443_policy", "status": "info", "detail": "no explicit UDP/443 rule; HTTP/3/QUIC behavior must remain documented as limited or test-required"}


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


def main() -> int:
    parser = argparse.ArgumentParser(description="Run local MITM-DomainFronting preflight checks")
    parser.add_argument("--config", type=Path, default=Path("Xray-config/MITM-DomainFronting.json"))
    parser.add_argument("--cert", type=Path, default=Path("Xray-config/mycert.crt"))
    parser.add_argument("--key", type=Path, default=Path("Xray-config/mycert.key"))
    parser.add_argument("--json-out", type=Path, default=None)
    parser.add_argument("--no-dns", action="store_true", help="skip system DNS resolution check")
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
            checks.append(udp443_policy_check(config))
    else:
        checks.append({"id": "validator_import", "status": "warn", "detail": "validate_config.py could not be imported"})

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
    text = json.dumps(report, indent=2, ensure_ascii=False)
    if args.json_out:
        args.json_out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 2 if overall == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
