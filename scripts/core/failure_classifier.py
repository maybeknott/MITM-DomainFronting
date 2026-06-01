#!/usr/bin/env python3
"""Phase-aware network probe for local diagnostics."""
from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable


@dataclass
class ProbeResult:
    dns_ms: int | None = None
    tcp_connect_ms: int | None = None
    tls_server_hello_ms: int | None = None
    alpn_negotiated: str | None = None
    http_status: str | int | None = None
    phase_classification: str = "unknown"
    confidence_score: float = 0.0
    error_detail: str = ""
    resolved_ip: str | None = None
    resolved_family: str | None = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase_classification": self.phase_classification,
            "confidence_score": round(self.confidence_score, 3),
            "telemetry": {
                "dns_resolution_ms": self.dns_ms,
                "tcp_connect_ms": self.tcp_connect_ms,
                "tls_server_hello_ms": self.tls_server_hello_ms,
                "alpn_negotiated": self.alpn_negotiated,
                "http_status": self.http_status,
                "resolved_ip": self.resolved_ip,
                "resolved_family": self.resolved_family,
                "error_detail": self.error_detail,
            },
        }


def _elapsed_ms(start: float) -> int:
    return int((time.perf_counter() - start) * 1000)


def _iter_addrinfo(host: str, port: int) -> Iterable[tuple[int, int, int, str, tuple[Any, ...]]]:
    # AF_UNSPEC lets us try both IPv4 and IPv6 paths when available.
    return socket.getaddrinfo(host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)


def _family_label(family: int) -> str:
    if family == socket.AF_INET6:
        return "ipv6"
    if family == socket.AF_INET:
        return "ipv4"
    return str(family)


def run_staged_probe(host: str, port: int = 443, timeout: float = 5.0) -> ProbeResult:
    """Execute staged DNS/TCP/TLS/L7 checks and classify where failure occurred."""
    result = ProbeResult()

    # Phase 1: DNS resolution
    dns_start = time.perf_counter()
    try:
        addr_infos = list(_iter_addrinfo(host, port))
        result.dns_ms = _elapsed_ms(dns_start)
    except socket.gaierror as exc:
        result.phase_classification = "dns_poisoned_or_failed"
        result.confidence_score = 0.96
        result.error_detail = f"{exc.__class__.__name__}: {exc}"
        return result
    except Exception as exc:  # noqa: BLE001
        result.phase_classification = "dns_poisoned_or_failed"
        result.confidence_score = 0.9
        result.error_detail = f"{exc.__class__.__name__}: {exc}"
        return result

    connected_sock: socket.socket | None = None
    tcp_timeout_seen = False
    tcp_refused_seen = False
    tcp_last_error: str | None = None

    # Phase 2: TCP connect over each resolved address
    for family, socktype, proto, _, sockaddr in addr_infos:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        connect_start = time.perf_counter()
        try:
            sock.connect(sockaddr)
            connected_sock = sock
            result.tcp_connect_ms = _elapsed_ms(connect_start)
            result.resolved_ip = str(sockaddr[0])
            result.resolved_family = _family_label(family)
            break
        except TimeoutError as exc:
            tcp_timeout_seen = True
            tcp_last_error = str(exc)
            sock.close()
        except ConnectionRefusedError as exc:
            tcp_refused_seen = True
            tcp_last_error = str(exc)
            sock.close()
        except OSError as exc:
            tcp_last_error = f"{exc.__class__.__name__}: {exc}"
            sock.close()

    if connected_sock is None:
        if tcp_timeout_seen:
            result.phase_classification = "tcp_timeout_blackhole"
            result.confidence_score = 0.95
            result.error_detail = tcp_last_error or "TCP connect timed out"
            return result
        if tcp_refused_seen:
            result.phase_classification = "tcp_refused"
            result.confidence_score = 0.98
            result.error_detail = tcp_last_error or "TCP connection refused"
            return result
        result.phase_classification = "tcp_failed"
        result.confidence_score = 0.9
        result.error_detail = tcp_last_error or "TCP connection failed"
        return result

    # Phase 3: TLS + ALPN negotiation
    tls_start = time.perf_counter()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2", "http/1.1"])

    tls_sock: ssl.SSLSocket | None = None
    try:
        tls_sock = ctx.wrap_socket(connected_sock, server_hostname=host)
        result.tls_server_hello_ms = _elapsed_ms(tls_start)
        result.alpn_negotiated = tls_sock.selected_alpn_protocol()
    except ssl.SSLError as exc:
        result.phase_classification = "tls_alert_or_rst"
        result.confidence_score = 0.95
        result.error_detail = f"{exc.__class__.__name__}: {exc}"
        connected_sock.close()
        return result
    except TimeoutError:
        result.phase_classification = "tls_silent_drop"
        result.confidence_score = 0.95
        result.error_detail = "TLS handshake timed out after TCP connect"
        connected_sock.close()
        return result
    except Exception as exc:  # noqa: BLE001
        result.phase_classification = "tls_alert_or_rst"
        result.confidence_score = 0.9
        result.error_detail = f"{exc.__class__.__name__}: {exc}"
        connected_sock.close()
        return result

    # Some server paths complete TLS but never negotiate ALPN.
    if result.alpn_negotiated is None:
        result.phase_classification = "alpn_mismatch"
        result.confidence_score = 0.88
        result.error_detail = "TLS handshake succeeded but ALPN was not negotiated"
        tls_sock.close()
        return result

    # Phase 4: minimal stream viability check
    try:
        tls_sock.settimeout(timeout)
        if result.alpn_negotiated == "http/1.1":
            request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            tls_sock.sendall(request.encode("ascii", errors="ignore"))
            response = tls_sock.recv(1024)
            if response.startswith(b"HTTP/1.1 "):
                parts = response.split(b" ", 2)
                if len(parts) > 1 and parts[1].isdigit():
                    result.http_status = int(parts[1].decode("ascii"))
                else:
                    result.http_status = "http1_response"
            else:
                result.http_status = "http1_unexpected"
        elif result.alpn_negotiated == "h2":
            # Client connection preface + empty SETTINGS frame.
            preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            empty_settings = b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
            tls_sock.sendall(preface + empty_settings)
            frame_header = tls_sock.recv(9)
            if len(frame_header) >= 9:
                result.http_status = "h2_frame_received"
            else:
                result.http_status = "h2_no_frame"
        else:
            result.http_status = f"unsupported_alpn:{result.alpn_negotiated}"

        result.phase_classification = "healthy"
        result.confidence_score = 1.0
    except TimeoutError:
        result.phase_classification = "throughput_stall"
        result.confidence_score = 0.86
        result.error_detail = "Connected but timed out during stream viability check"
    except Exception as exc:  # noqa: BLE001
        result.phase_classification = "throughput_stall"
        result.confidence_score = 0.82
        result.error_detail = f"{exc.__class__.__name__}: {exc}"
    finally:
        tls_sock.close()

    return result

