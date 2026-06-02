#!/usr/bin/env python3
"""Regression tests for DNS lab harness packet parsing."""
from __future__ import annotations

import _path  # noqa: F401

from dns_lab_harness import build_dns_a_response, extract_first_a_ipv4
from check_dns import build_query


def test_valid_a_response() -> None:
    _, query = build_query("example.com", "A")
    response = build_dns_a_response(query, "203.0.113.99")
    assert extract_first_a_ipv4(response) == "203.0.113.99"


def test_truncated_header() -> None:
    assert extract_first_a_ipv4(b"\x00\x01") is None


def test_oversized_label_does_not_raise() -> None:
    # Header says one question and one answer, but the question label length
    # walks beyond the packet. The parser should reject it, not raise.
    packet = b"\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + b"\x3fabc"
    assert extract_first_a_ipv4(packet) is None


def test_truncated_compression_pointer_does_not_raise() -> None:
    packet = b"\x00\x01\x81\x80\x00\x00\x00\x01\x00\x00\x00\x00\xc0"
    assert extract_first_a_ipv4(packet) is None


def main() -> int:
    tests = [
        test_valid_a_response,
        test_truncated_header,
        test_oversized_label_does_not_raise,
        test_truncated_compression_pointer_does_not_raise,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
