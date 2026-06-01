#!/usr/bin/env python3
"""Small DNS reachability checker using only Python standard library.

It performs minimal UDP DNS queries to specified resolvers and also can test the
system resolver. It is intended for diagnostics, not for bypassing network
policy.
"""
from __future__ import annotations

import argparse
import json
import random
import socket
import struct
import time
from typing import Dict, List, Tuple

QTYPE = {"A": 1, "AAAA": 28, "HTTPS": 65, "SVCB": 64}


def encode_name(name: str) -> bytes:
    parts = name.rstrip(".").split(".")
    out = b""
    for part in parts:
        b = part.encode("ascii")
        if len(b) > 63:
            raise ValueError("DNS label too long")
        out += bytes([len(b)]) + b
    return out + b"\x00"


def build_query(domain: str, qtype: str) -> Tuple[int, bytes]:
    tid = random.randint(0, 65535)
    flags = 0x0100  # recursion desired
    header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0)
    question = encode_name(domain) + struct.pack("!HH", QTYPE[qtype], 1)
    return tid, header + question


def parse_response(data: bytes, expected_tid: int) -> Dict[str, int | str]:
    if len(data) < 12:
        return {"rcode": -1, "answers": 0, "error": "short response"}
    tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    if tid != expected_tid:
        return {"rcode": -1, "answers": 0, "error": "transaction id mismatch"}
    rcode = flags & 0x000F
    return {"rcode": rcode, "answers": an, "authority": ns, "additional": ar}


def query_udp(resolver: str, domain: str, qtype: str, timeout: float, port: int = 53) -> Dict[str, object]:
    tid, packet = build_query(domain, qtype)
    start = time.time()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(packet, (resolver, port))
            data, _ = s.recvfrom(4096)
        elapsed = int((time.time() - start) * 1000)
        parsed = parse_response(data, tid)
        return {"resolver": resolver, "domain": domain, "qtype": qtype, "port": port, "status": "pass", "elapsed_ms": elapsed, **parsed}
    except Exception as exc:  # noqa: BLE001
        elapsed = int((time.time() - start) * 1000)
        return {"resolver": resolver, "domain": domain, "qtype": qtype, "port": port, "status": "warn", "elapsed_ms": elapsed, "error": str(exc)}


def system_resolve(domain: str, timeout: float) -> Dict[str, object]:
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    start = time.time()
    try:
        result = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
        addrs = sorted({r[4][0] for r in result})
        return {"resolver": "system", "domain": domain, "status": "pass", "elapsed_ms": int((time.time() - start) * 1000), "addresses": addrs[:8], "address_count": len(addrs)}
    except Exception as exc:  # noqa: BLE001
        return {"resolver": "system", "domain": domain, "status": "warn", "elapsed_ms": int((time.time() - start) * 1000), "error": str(exc)}
    finally:
        socket.setdefaulttimeout(old_timeout)


def main() -> int:
    parser = argparse.ArgumentParser(description="DNS resolver diagnostic checker")
    parser.add_argument("--domain", default="example.com")
    parser.add_argument("--resolver", action="append", default=[], help="resolver IPv4 address; repeatable")
    parser.add_argument("--qtype", choices=sorted(QTYPE), default="A")
    parser.add_argument("--all-types", action="store_true", help="query A, AAAA, HTTPS, and SVCB")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--skip-system", action="store_true")
    args = parser.parse_args()

    checks: List[Dict[str, object]] = []
    qtypes = sorted(QTYPE) if args.all_types else [args.qtype]
    if not args.skip_system:
        checks.append(system_resolve(args.domain, args.timeout))
    for resolver in args.resolver:
        for qtype in qtypes:
            checks.append(query_udp(resolver, args.domain, qtype, args.timeout))
    if not checks:
        checks.append({
            "resolver": "none",
            "domain": args.domain,
            "status": "warn",
            "error": "no DNS checks were requested; remove --skip-system or add --resolver",
        })

    overall = "pass" if all(c.get("status") == "pass" for c in checks) else "warn"
    print(json.dumps({"overall": overall, "checks": checks}, indent=2, ensure_ascii=False))
    return 0 if overall == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
