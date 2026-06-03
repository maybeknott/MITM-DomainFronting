#!/usr/bin/env python3
"""Tests for scripts/core/sni_camouflage.py (legitimate SNI-spoofing inspection)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import _path  # noqa: F401

from core.sni_camouflage import (  # noqa: E402
    CamouflageReport,
    extract_bindings,
    hostname_plausible,
    inspect_config,
    inspect_path,
)

ROOT = Path(__file__).resolve().parents[2]
PRIMARY = ROOT / "Xray-config" / "MITM-DomainFronting.json"


def expect(name: str, actual: object, expected: object) -> bool:
    if actual != expected:
        print(f"FAIL {name}: expected={expected!r} actual={actual!r}")
        return False
    print(f"PASS {name}")
    return True


def test_hostname_plausible_basic() -> bool:
    return expect("hostname_plausible_basic", hostname_plausible("www.microsoft.com"), True)


def test_hostname_plausible_sub() -> bool:
    return expect("hostname_plausible_sub", hostname_plausible("cdn.example.co.uk"), True)


def test_hostname_trailing_dot_ok() -> bool:
    return expect("hostname_trailing_dot_ok", hostname_plausible("www.google.com."), True)


def test_hostname_rejects_empty() -> bool:
    return expect("hostname_rejects_empty", hostname_plausible(""), False)


def test_extract_tls_binding() -> bool:
    config = {
        "outbounds": [
            {
                "tag": "tls-repack-google",
                "protocol": "direct",
                "streamSettings": {
                    "security": "tls",
                    "tlsSettings": {"serverName": "www.google.com", "fingerprint": "chrome"},
                },
            }
        ]
    }
    bindings = extract_bindings(config)
    ok = len(bindings) == 1 and bindings[0].server_name == "www.google.com"
    return expect("extract_tls_binding", ok, True)


def test_reality_missing_server_name_is_error() -> bool:
    config = {
        "outbounds": [
            {
                "tag": "reality-out",
                "protocol": "vless",
                "streamSettings": {"security": "reality", "realitySettings": {"publicKey": "x"}},
            }
        ]
    }
    report = inspect_config(config)
    codes = {issue.code for issue in report.issues}
    return expect("reality_missing_server_name_is_error", "reality_server_name_required" in codes, True)


def test_tls_repack_missing_server_name_warns() -> bool:
    config = {
        "outbounds": [
            {
                "tag": "tls-repack-meta",
                "protocol": "direct",
                "streamSettings": {"security": "tls", "tlsSettings": {"fingerprint": "chrome"}},
            }
        ]
    }
    report = inspect_config(config)
    codes = {issue.code for issue in report.issues}
    return expect("tls_repack_missing_server_name_warns", "tls_server_name_recommended" in codes, True)


def test_non_tls_outbound_skipped() -> bool:
    config = {"outbounds": [{"tag": "direct", "protocol": "freedom"}]}
    return expect("non_tls_outbound_skipped", extract_bindings(config), [])


def test_implausible_hostname_warns() -> bool:
    config = {
        "outbounds": [
            {
                "tag": "tls-repack-google",
                "protocol": "direct",
                "streamSettings": {
                    "security": "tls",
                    "tlsSettings": {"serverName": "not a hostname!!!"},
                },
            }
        ]
    }
    report = inspect_config(config)
    return expect(
        "implausible_hostname_warns",
        any(issue.code == "hostname_implausible" for issue in report.issues),
        True,
    )


def test_malformed_config_root() -> bool:
    report = inspect_config({"outbounds": "nope"})
    return expect(
        "malformed_config_root",
        any(issue.code == "invalid_config" for issue in report.issues),
        True,
    )


def test_primary_config_has_camouflage() -> bool:
    if not PRIMARY.exists():
        print("SKIP primary_config_has_camouflage (config missing)")
        return True
    report = inspect_path(PRIMARY)
    tls_bindings = [b for b in report.bindings if b.transport == "tls"]
    ok = len(tls_bindings) >= 5 and report.ok
    if not ok:
        print(f"FAIL primary_config_has_camouflage: bindings={len(tls_bindings)} ok={report.ok}")
        return False
    print("PASS primary_config_has_camouflage")
    return True


def test_primary_config_to_dict_serializable() -> bool:
    if not PRIMARY.exists():
        print("SKIP primary_config_to_dict_serializable")
        return True
    report = inspect_path(PRIMARY)
    payload = json.dumps(report.to_dict())
    return expect("primary_config_to_dict_serializable", isinstance(payload, str) and len(payload) > 10, True)


def main() -> int:
    tests = [
        test_hostname_plausible_basic,
        test_hostname_plausible_sub,
        test_hostname_trailing_dot_ok,
        test_hostname_rejects_empty,
        test_extract_tls_binding,
        test_reality_missing_server_name_is_error,
        test_tls_repack_missing_server_name_warns,
        test_non_tls_outbound_skipped,
        test_implausible_hostname_warns,
        test_malformed_config_root,
        test_primary_config_has_camouflage,
        test_primary_config_to_dict_serializable,
    ]
    failed = sum(1 for test in tests if not test())
    if failed:
        print(f"\n{failed} failed, {len(tests) - failed} passed")
        return 1
    print(f"\n{len(tests)} passed, 0 failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
