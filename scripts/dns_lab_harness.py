#!/usr/bin/env python3
"""Manual DNS lab harness that emits redacted scenario evidence."""
from __future__ import annotations

import argparse
import json
import socket
import struct
import threading
import time
import urllib.request
from typing import Dict, List, Optional

from check_dns import build_query, query_udp, system_resolve


def _overall_from_checks(checks: List[Dict[str, object]]) -> str:
    statuses = {str(c.get("status", "info")) for c in checks}
    if "fail" in statuses:
        return "fail"
    if "warn" in statuses:
        return "warn"
    return "pass"


def build_dns_a_response(query_packet: bytes, ipv4: str) -> bytes:
    if len(query_packet) < 12:
        raise ValueError("query too short")
    tid = query_packet[:2]
    header = tid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    idx = 12
    while idx < len(query_packet) and query_packet[idx] != 0:
        idx += query_packet[idx] + 1
    idx += 5
    question = query_packet[12:idx]
    rdata = socket.inet_aton(ipv4)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, len(rdata)) + rdata
    return header + question + answer


def extract_first_a_ipv4(response: bytes) -> Optional[str]:
    if len(response) < 12:
        return None
    _, _, qd, an, _, _ = struct.unpack("!HHHHHH", response[:12])
    if an < 1:
        return None
    offset = 12
    for _ in range(qd):
        while offset < len(response) and response[offset] != 0:
            offset += response[offset] + 1
        offset += 5
    while offset < len(response) and an > 0:
        if offset >= len(response):
            return None
        if response[offset] & 0xC0 == 0xC0:
            offset += 2
        else:
            while offset < len(response) and response[offset] != 0:
                offset += response[offset] + 1
            offset += 1
        if offset + 10 > len(response):
            return None
        rtype, _, _, rdlength = struct.unpack("!HHIH", response[offset : offset + 10])
        offset += 10
        if rtype == 1 and rdlength == 4 and offset + 4 <= len(response):
            return socket.inet_ntoa(response[offset : offset + 4])
        offset += rdlength
        an -= 1
    return None


class FakeDnsServer:
    def __init__(self, bind_host: str, bind_port: int, answer_ipv4: str) -> None:
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.answer_ipv4 = answer_ipv4
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((self.bind_host, self.bind_port))
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(512)
                response = build_dns_a_response(data, self.answer_ipv4)
                self._sock.sendto(response, addr)
            except (TimeoutError, OSError):
                if self._stop.is_set():
                    break
                continue

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2.0)


def scenario_resolver_timeout(domain: str, primary: str, fallback: str, timeout: float) -> Dict[str, object]:
    checks: List[Dict[str, object]] = []
    primary_result = query_udp(primary, domain, "A", timeout)
    checks.append(primary_result)
    fallback_result = query_udp(fallback, domain, "A", timeout)
    checks.append(fallback_result)
    fallback_attempted = True
    return {
        "scenario": "resolver-timeout",
        "checks": checks,
        "observations": {
            "fallback_attempted": fallback_attempted,
            "primary_status": primary_result.get("status"),
            "fallback_status": fallback_result.get("status"),
        },
        "overall": _overall_from_checks(checks),
    }


def scenario_fallback_order(domain: str, resolvers: List[str], timeout: float) -> Dict[str, object]:
    checks: List[Dict[str, object]] = []
    first_pass_index = None
    for index, resolver in enumerate(resolvers, start=1):
        result = query_udp(resolver, domain, "A", timeout)
        result["order"] = index
        checks.append(result)
        if first_pass_index is None and result.get("status") == "pass":
            first_pass_index = index
    return {
        "scenario": "fallback-order",
        "checks": checks,
        "observations": {
            "resolver_count": len(resolvers),
            "first_success_order": first_pass_index,
        },
        "overall": _overall_from_checks(checks),
    }


def scenario_dns_hijack(domain: str, trusted_resolver: str, suspect_resolver: str, timeout: float) -> Dict[str, object]:
    trusted = query_udp(trusted_resolver, domain, "A", timeout)
    suspect = query_udp(suspect_resolver, domain, "A", timeout)
    checks = [trusted, suspect]
    suspicious = (
        trusted.get("status") == "pass"
        and suspect.get("status") == "pass"
        and trusted.get("rcode") != suspect.get("rcode")
    ) or (
        trusted.get("status") == "pass"
        and suspect.get("status") == "pass"
        and int(trusted.get("answers", 0)) != int(suspect.get("answers", 0))
    )
    return {
        "scenario": "dns-hijack",
        "checks": checks,
        "observations": {
            "trusted_resolver": trusted_resolver,
            "suspect_resolver": suspect_resolver,
            "suspicious_difference_detected": bool(suspicious),
            "note": "A/AAAA answer content parsing is intentionally minimal in this redacted harness.",
        },
        "overall": "warn" if suspicious else _overall_from_checks(checks),
    }


def scenario_fake_dns_lab(
    domain: str,
    trusted_resolver: str,
    bind_host: str,
    bind_port: int,
    fake_ipv4: str,
    timeout: float,
) -> Dict[str, object]:
    server = FakeDnsServer(bind_host, bind_port, fake_ipv4)
    checks: List[Dict[str, object]] = []
    try:
        server.start()
        time.sleep(0.15)
        trusted = query_udp(trusted_resolver, domain, "A", timeout)
        checks.append(trusted)
        fake = query_udp(bind_host, domain, "A", timeout, port=bind_port)
        checks.append(fake)
        observed_ip = None
        if fake.get("status") == "pass":
            tid, packet = build_query(domain, "A")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, (bind_host, bind_port))
                data, _ = sock.recvfrom(4096)
            observed_ip = extract_first_a_ipv4(data)
        hijack_confirmed = observed_ip == fake_ipv4
        return {
            "scenario": "fake-dns-lab",
            "checks": checks,
            "observations": {
                "fake_dns_bind": f"{bind_host}:{bind_port}",
                "configured_fake_ipv4": fake_ipv4,
                "observed_fake_ipv4": observed_ip,
                "controlled_hijack_confirmed": hijack_confirmed,
                "trusted_resolver": trusted_resolver,
                "note": "Local fake DNS server returns a known wrong A record for lab evidence only.",
            },
            "overall": "pass" if hijack_confirmed else "warn",
        }
    finally:
        server.stop()


def scenario_split_dns(private_domain: str, resolvers: List[str], timeout: float) -> Dict[str, object]:
    checks: List[Dict[str, object]] = [system_resolve(private_domain, timeout)]
    for resolver in resolvers:
        checks.append(query_udp(resolver, private_domain, "A", timeout))
    system_ok = checks[0].get("status") == "pass"
    external_answers = [c for c in checks[1:] if int(c.get("answers", 0)) > 0]
    return {
        "scenario": "split-dns",
        "checks": checks,
        "observations": {
            "system_private_resolution_ok": system_ok,
            "external_answer_count": len(external_answers),
            "warning_if_external_answers_present": len(external_answers) > 0,
        },
        "overall": "warn" if external_answers else _overall_from_checks(checks),
    }


def _classify_nat64(a_check: Dict[str, object], aaaa_check: Dict[str, object]) -> str:
    a_ok = a_check.get("status") == "pass" and int(a_check.get("answers", 0)) > 0
    aaaa_ok = aaaa_check.get("status") == "pass" and int(aaaa_check.get("answers", 0)) > 0
    if a_ok and aaaa_ok:
        return "dual_stack"
    if aaaa_ok and not a_ok:
        return "ipv6_only_or_dns64_likely"
    if a_ok and not aaaa_ok:
        return "ipv4_preferred"
    return "unknown"


def _system_a_probe(domain: str, timeout: float) -> Dict[str, object]:
    old = socket.getdefaulttimeout()
    start = time.time()
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(domain, 443, family=socket.AF_INET, type=socket.SOCK_STREAM)
        return {
            "resolver": "system",
            "domain": domain,
            "qtype": "A",
            "status": "pass",
            "elapsed_ms": int((time.time() - start) * 1000),
            "answers": 1,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "resolver": "system",
            "domain": domain,
            "qtype": "A",
            "status": "warn",
            "elapsed_ms": int((time.time() - start) * 1000),
            "error": str(exc),
            "answers": 0,
        }
    finally:
        socket.setdefaulttimeout(old)


def scenario_nat64_dns64(domain: str, resolvers: List[str], timeout: float) -> Dict[str, object]:
    checks: List[Dict[str, object]] = [system_resolve(domain, timeout), _system_a_probe(domain, timeout)]
    for resolver in resolvers:
        a_result = query_udp(resolver, domain, "A", timeout)
        aaaa_result = query_udp(resolver, domain, "AAAA", timeout)
        a_result["record_type"] = "A"
        aaaa_result["record_type"] = "AAAA"
        checks.extend([a_result, aaaa_result])
    resolver_a = next((c for c in checks if c.get("record_type") == "A" and c.get("resolver") != "system"), checks[-2] if len(checks) >= 2 else {})
    resolver_aaaa = next((c for c in checks if c.get("record_type") == "AAAA"), checks[-1] if checks else {})
    classification = _classify_nat64(
        resolver_a if isinstance(resolver_a, dict) else {},
        resolver_aaaa if isinstance(resolver_aaaa, dict) else {},
    )
    synthesized_like = [c for c in checks if c.get("status") == "pass" and int(c.get("answers", 0)) > 0 and c.get("record_type") == "AAAA"]
    system_has_v4 = checks[1].get("status") == "pass" if len(checks) > 1 else False
    return {
        "scenario": "nat64-dns64",
        "checks": checks,
        "observations": {
            "aaaa_answers_seen": len(synthesized_like),
            "dns64_possible": len(synthesized_like) > 0,
            "network_classification": classification,
            "system_ipv4_reachable": system_has_v4,
            "note": "Use an IPv4-only lab domain (default ipv4only.arpa) for stronger DNS64 signal.",
        },
        "overall": _overall_from_checks(checks),
    }


def scenario_captive_portal(timeout: float) -> Dict[str, object]:
    checks: List[Dict[str, object]] = [system_resolve("connectivitycheck.gstatic.com", timeout)]
    start = time.time()
    http_result: Dict[str, object]
    try:
        req = urllib.request.Request(
            "http://connectivitycheck.gstatic.com/generate_204",
            headers={"User-Agent": "mitm-domainfronting-dns-lab"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            code = int(response.getcode())
            elapsed_ms = int((time.time() - start) * 1000)
            http_result = {
                "id": "captive_http_probe",
                "status": "pass" if code == 204 else "warn",
                "http_status": code,
                "elapsed_ms": elapsed_ms,
            }
    except Exception as exc:  # noqa: BLE001
        elapsed_ms = int((time.time() - start) * 1000)
        http_result = {
            "id": "captive_http_probe",
            "status": "warn",
            "elapsed_ms": elapsed_ms,
            "error": str(exc),
        }
    checks.append(http_result)
    captive_likely = http_result.get("status") == "warn" and http_result.get("http_status") not in {None, 204}
    return {
        "scenario": "captive-portal",
        "checks": checks,
        "observations": {
            "captive_portal_likely": bool(captive_likely),
            "advice": "Complete captive login before enabling strict profile checks.",
        },
        "overall": _overall_from_checks(checks),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run manual DNS lab scenarios and emit redacted JSON evidence")
    parser.add_argument(
        "--scenario",
        choices=[
            "resolver-timeout",
            "fallback-order",
            "dns-hijack",
            "fake-dns-lab",
            "split-dns",
            "nat64-dns64",
            "captive-portal",
        ],
        required=True,
    )
    parser.add_argument("--domain", default="example.com")
    parser.add_argument("--private-domain", default="router.local")
    parser.add_argument("--primary-resolver", default="203.0.113.1")
    parser.add_argument("--fallback-resolver", default="1.1.1.1")
    parser.add_argument("--resolver", action="append", default=[])
    parser.add_argument("--trusted-resolver", default="1.1.1.1")
    parser.add_argument("--suspect-resolver", default="8.8.8.8")
    parser.add_argument("--nat64-domain", default="ipv4only.arpa")
    parser.add_argument("--fake-dns-bind-host", default="127.0.0.1")
    parser.add_argument("--fake-dns-bind-port", type=int, default=5533)
    parser.add_argument("--fake-ipv4", default="203.0.113.99")
    parser.add_argument("--timeout", type=float, default=1.5)
    args = parser.parse_args()

    resolvers = args.resolver or [args.primary_resolver, args.fallback_resolver]
    if args.scenario == "resolver-timeout":
        report = scenario_resolver_timeout(args.domain, args.primary_resolver, args.fallback_resolver, args.timeout)
    elif args.scenario == "fallback-order":
        report = scenario_fallback_order(args.domain, resolvers, args.timeout)
    elif args.scenario == "dns-hijack":
        report = scenario_dns_hijack(args.domain, args.trusted_resolver, args.suspect_resolver, args.timeout)
    elif args.scenario == "fake-dns-lab":
        report = scenario_fake_dns_lab(
            args.domain,
            args.trusted_resolver,
            args.fake_dns_bind_host,
            args.fake_dns_bind_port,
            args.fake_ipv4,
            args.timeout,
        )
    elif args.scenario == "split-dns":
        report = scenario_split_dns(args.private_domain, resolvers, args.timeout)
    elif args.scenario == "nat64-dns64":
        report = scenario_nat64_dns64(args.nat64_domain, resolvers, args.timeout)
    else:
        report = scenario_captive_portal(args.timeout)

    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report.get("overall") == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
