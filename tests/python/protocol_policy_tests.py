#!/usr/bin/env python3
"""Validate protocol support metadata and documentation coverage."""
from __future__ import annotations

from pathlib import Path

REQUIRED_PROTOCOLS = {
    "tcp_443_https": "TCP/443",
    "http_1_1_tls": "HTTP/1.1",
    "http_2_tls": "HTTP/2",
    "http_3_quic_udp_443": "HTTP/3",
    "dns_udp_tcp_53": "DNS UDP/TCP",
    "doh": "DoH",
    "dot": "DoT",
    "doq": "DoQ",
    "websocket": "WebSocket",
    "grpc": "gRPC",
    "webrtc_stun_turn": "WebRTC",
    "ipv6": "IPv6",
    "nat64_dns64": "NAT64",
    "private_lan": "Private LAN",
}

REQUIRED_STATUS_LABELS = {
    "supported",
    "degraded",
    "pass_through",
    "unsupported",
    "unknown",
}


def main() -> int:
    errors: list[str] = []
    protocols_path = Path("configs/protocols.yml")
    docs_path = Path("docs/protocol-coverage.md")
    if not protocols_path.exists():
        errors.append(f"{protocols_path}: missing")
        protocols_text = ""
    else:
        protocols_text = protocols_path.read_text(encoding="utf-8")
    if not docs_path.exists():
        errors.append(f"{docs_path}: missing")
        docs_text = ""
    else:
        docs_text = docs_path.read_text(encoding="utf-8")

    for protocol_id, docs_marker in REQUIRED_PROTOCOLS.items():
        if f"  {protocol_id}:" not in protocols_text:
            errors.append(f"{protocols_path}: missing protocol {protocol_id}")
        if docs_marker not in docs_text:
            errors.append(f"{docs_path}: missing docs marker {docs_marker}")

    for label in REQUIRED_STATUS_LABELS:
        if label not in docs_text:
            errors.append(f"{docs_path}: missing status label {label}")

    for required_fragment in [
        "udp_443_route",
        "browser_http3_enabled_disabled",
        "resolver_timeout",
        "private_domain",
        "websocket_upgrade",
        "grpc",
        "protocol_smoke.py --scenario websocket-handshake",
        "protocol_smoke.py --scenario grpc-alpn",
        "protocol_smoke.py --scenario ipv6-connect",
        "dns_lab_harness.py --scenario nat64-dns64",
    ]:
        if required_fragment not in protocols_text:
            errors.append(f"{protocols_path}: missing test/edge-case {required_fragment}")

    for required_doc_fragment in [
        "scripts/protocol_smoke.py",
        "--scenario udp443-policy",
        "--scenario websocket-handshake",
        "--scenario grpc-alpn",
        "--scenario ipv6-connect",
    ]:
        if required_doc_fragment not in docs_text:
            errors.append(f"{docs_path}: missing smoke-probe docs fragment {required_doc_fragment}")

    if errors:
        for error in errors:
            print(error)
        return 2
    print("protocol policy tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
