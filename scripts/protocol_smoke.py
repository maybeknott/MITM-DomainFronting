#!/usr/bin/env python3
"""Small standard-library protocol smoke probes for release evidence."""
from __future__ import annotations

import argparse
import json
import socket
import ssl
import time
from pathlib import Path
from typing import Dict, List

from transport_profile_validate import EXPECTED_PROFILE_POLICIES, catchall_rule, first_udp443_rule, load_config


def status_report(scenario: str, status: str, detail: Dict[str, object]) -> int:
    payload = {"scenario": scenario, "status": status, **detail}
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if status == "pass" else 1


def tcp_connect(host: str, port: int, timeout: float) -> int:
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed_ms = int((time.time() - start) * 1000)
            return status_report("tcp-connect", "pass", {"host": host, "port": port, "elapsed_ms": elapsed_ms})
    except OSError as exc:
        elapsed_ms = int((time.time() - start) * 1000)
        return status_report("tcp-connect", "warn", {"host": host, "port": port, "elapsed_ms": elapsed_ms, "error": str(exc)})


def ipv6_connect(host: str, port: int, timeout: float) -> int:
    start = time.time()
    try:
        infos = socket.getaddrinfo(host, port, family=socket.AF_INET6, type=socket.SOCK_STREAM)
        if not infos:
            return status_report("ipv6-connect", "warn", {"host": host, "port": port, "error": "no IPv6 addresses"})
        last_error = None
        for family, socktype, proto, _, sockaddr in infos:
            try:
                with socket.socket(family, socktype, proto) as sock:
                    sock.settimeout(timeout)
                    sock.connect(sockaddr)
                    elapsed_ms = int((time.time() - start) * 1000)
                    return status_report("ipv6-connect", "pass", {"host": host, "port": port, "address": sockaddr[0], "elapsed_ms": elapsed_ms})
            except OSError as exc:
                last_error = str(exc)
        elapsed_ms = int((time.time() - start) * 1000)
        return status_report("ipv6-connect", "warn", {"host": host, "port": port, "elapsed_ms": elapsed_ms, "error": last_error})
    except OSError as exc:
        elapsed_ms = int((time.time() - start) * 1000)
        return status_report("ipv6-connect", "warn", {"host": host, "port": port, "elapsed_ms": elapsed_ms, "error": str(exc)})


def tls_alpn(host: str, port: int, protocols: List[str], timeout: float, scenario: str) -> int:
    start = time.time()
    context = ssl.create_default_context()
    context.set_alpn_protocols(protocols)
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                selected = tls.selected_alpn_protocol()
                elapsed_ms = int((time.time() - start) * 1000)
                status = "pass" if selected in protocols else "warn"
                return status_report(
                    scenario,
                    status,
                    {"host": host, "port": port, "requested_alpn": protocols, "selected_alpn": selected, "elapsed_ms": elapsed_ms},
                )
    except OSError as exc:
        elapsed_ms = int((time.time() - start) * 1000)
        return status_report(scenario, "warn", {"host": host, "port": port, "elapsed_ms": elapsed_ms, "error": str(exc)})


def websocket_handshake(host: str, port: int, path: str, timeout: float, tls: bool) -> int:
    start = time.time()
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
        with raw:
            conn = ssl.create_default_context().wrap_socket(raw, server_hostname=host) if tls else raw
            with conn:
                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                    "Sec-WebSocket-Version: 13\r\n\r\n"
                ).encode("ascii")
                conn.sendall(request)
                response = conn.recv(512).decode("iso-8859-1", errors="replace")
        elapsed_ms = int((time.time() - start) * 1000)
        status = "pass" if " 101 " in response.splitlines()[0:1][0] else "warn"
        return status_report(
            "websocket-handshake",
            status,
            {"host": host, "port": port, "path": path, "tls": tls, "elapsed_ms": elapsed_ms, "status_line": response.splitlines()[0] if response else ""},
        )
    except (OSError, IndexError) as exc:
        elapsed_ms = int((time.time() - start) * 1000)
        return status_report("websocket-handshake", "warn", {"host": host, "port": port, "elapsed_ms": elapsed_ms, "error": str(exc)})


def fragment_policy(root: Path) -> int:
    fragment = root / "config-src" / "fragments" / "tls-fragment-overlay.json"
    if not fragment.exists():
        return status_report("fragment-policy", "fail", {"error": "missing tls-fragment-overlay.json"})
    data = json.loads(fragment.read_text(encoding="utf-8"))
    outbounds = data.get("outbounds") if isinstance(data.get("outbounds"), list) else []
    fragment_hits = 0
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        stream = outbound.get("streamSettings") if isinstance(outbound.get("streamSettings"), dict) else {}
        sockopt = stream.get("sockopt") if isinstance(stream.get("sockopt"), dict) else {}
        fragment_cfg = sockopt.get("fragment") if isinstance(sockopt.get("fragment"), dict) else {}
        if fragment_cfg.get("packets") == "tlshello":
            fragment_hits += 1
    status = "pass" if fragment_hits else "fail"
    return status_report("fragment-policy", status, {"fragment_outbounds": fragment_hits})


def reality_stub(root: Path) -> int:
    stub = root / "config-src" / "fragments" / "reality-outbound-stub.json"
    if not stub.exists():
        return status_report("reality-stub", "fail", {"error": "missing reality-outbound-stub.json"})
    data = json.loads(stub.read_text(encoding="utf-8"))
    outbounds = data.get("outbounds") if isinstance(data.get("outbounds"), list) else []
    reality_hits = 0
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        stream = outbound.get("streamSettings") if isinstance(outbound.get("streamSettings"), dict) else {}
        if stream.get("security") == "reality":
            reality_hits += 1
    status = "pass" if reality_hits else "fail"
    return status_report("reality-stub", status, {"reality_outbounds": reality_hits})


def fakedns_policy(root: Path) -> int:
    fragment = root / "config-src" / "fragments" / "fakedns-19818-trap.json"
    base = root / "Xray-config" / "MITM-DomainFronting.json"
    checks: dict[str, object] = {"fragment_present": fragment.exists(), "runtime_fakedns": False, "ip_pool": ""}
    if base.exists():
        data = json.loads(base.read_text(encoding="utf-8"))
        servers = data.get("dns", {}).get("servers", []) if isinstance(data.get("dns"), dict) else []
        checks["runtime_fakedns"] = any(isinstance(item, dict) and item.get("address") == "fakedns" for item in servers)
    if fragment.exists():
        frag = json.loads(fragment.read_text(encoding="utf-8"))
        pool = frag.get("dns", {}).get("fakedns", {}) if isinstance(frag.get("dns"), dict) else {}
        if isinstance(pool, dict):
            checks["ip_pool"] = pool.get("ipPool", "")
    status = "pass" if checks["fragment_present"] and checks["runtime_fakedns"] and checks["ip_pool"] == "198.18.0.0/15" else "warn"
    return status_report("fakedns-policy", status, checks)


def udp443_policy(config_dir: Path) -> int:
    checks: List[Dict[str, object]] = []
    for profile, expected in EXPECTED_PROFILE_POLICIES.items():
        path = config_dir / f"MITM-DomainFronting.{profile}.json"
        config = load_config(path)
        udp = first_udp443_rule(config)
        catchall = catchall_rule(config)
        checks.append({
            "profile": profile,
            "udp443": udp.get("outboundTag") if udp else None,
            "expected_udp443": expected["udp"],
            "catchall": catchall.get("outboundTag") if catchall else None,
            "expected_catchall": expected["catchall"],
            "status": "pass"
            if udp and catchall and udp.get("outboundTag") == expected["udp"] and catchall.get("outboundTag") == expected["catchall"]
            else "fail",
        })
    status = "pass" if all(check["status"] == "pass" for check in checks) else "fail"
    return status_report("udp443-policy", status, {"checks": checks})


def main() -> int:
    parser = argparse.ArgumentParser(description="Run protocol smoke probes and emit redacted JSON")
    parser.add_argument("--scenario", choices=["tcp-connect", "websocket-handshake", "grpc-alpn", "http2-alpn", "ipv6-connect", "udp443-policy", "fragment-policy", "reality-stub", "fakedns-policy"], required=True)
    parser.add_argument("--host", default="example.com")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--path", default="/")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--plain", action="store_true", help="use plain TCP for websocket-handshake")
    parser.add_argument("--config-dir", type=Path, default=Path("Xray-config"))
    args = parser.parse_args()

    if args.scenario == "tcp-connect":
        return tcp_connect(args.host, args.port, args.timeout)
    if args.scenario == "websocket-handshake":
        return websocket_handshake(args.host, args.port, args.path, args.timeout, tls=not args.plain)
    if args.scenario == "grpc-alpn":
        return tls_alpn(args.host, args.port, ["h2"], args.timeout, "grpc-alpn")
    if args.scenario == "http2-alpn":
        return tls_alpn(args.host, args.port, ["h2", "http/1.1"], args.timeout, "http2-alpn")
    if args.scenario == "ipv6-connect":
        return ipv6_connect(args.host, args.port, args.timeout)
    if args.scenario == "fragment-policy":
        return fragment_policy(Path("."))
    if args.scenario == "reality-stub":
        return reality_stub(Path("."))
    if args.scenario == "fakedns-policy":
        return fakedns_policy(Path("."))
    return udp443_policy(args.config_dir)


if __name__ == "__main__":
    raise SystemExit(main())
