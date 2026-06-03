#!/usr/bin/env python3
"""Tiny script-level regression checks for browser probe success semantics."""
from __future__ import annotations

import _path  # noqa: F401

from browser_common import (  # noqa: E402
    _ja3_from_mapping,
    base_telemetry,
    navigation_succeeded,
    verify_ja3_against_oracle,
)


class _DummyResponse:
    def __init__(self, ok: bool, json_body: object = None) -> None:
        self.ok = ok
        self._json_body = json_body

    def json(self) -> object:
        if self._json_body is None:
            raise ValueError("no json body")
        return self._json_body


class _DummyPage:
    def __init__(self, response: object, content: str = "") -> None:
        self._response = response
        self._content = content

    def goto(self, url: str, **kwargs: object) -> object:  # noqa: ARG002
        return self._response

    def content(self) -> str:
        return self._content


def main() -> int:
    checks = [
        (
            "about_blank_success_without_response",
            navigation_succeeded("about:blank", "about:blank", None),
            True,
        ),
        (
            "file_url_success_without_response",
            navigation_succeeded("file:///tmp/test.html", "file:///tmp/test.html", None),
            True,
        ),
        (
            "https_requires_ok_response_pass",
            navigation_succeeded("https://example.com", "https://example.com", _DummyResponse(True)),
            True,
        ),
        (
            "https_requires_ok_response_fail_missing",
            navigation_succeeded("https://example.com", "https://example.com", None),
            False,
        ),
        (
            "https_requires_ok_response_fail_not_ok",
            navigation_succeeded("https://example.com", "https://example.com", _DummyResponse(False)),
            False,
        ),
    ]

    checks.extend(
        [
            ("ja3_mapping_top_level_hash", _ja3_from_mapping({"ja3_hash": "ABCD"}), "ABCD"),
            ("ja3_mapping_nested", _ja3_from_mapping({"tls": {"ja3": "771,4-5"}}), "771,4-5"),
            ("ja3_mapping_absent", _ja3_from_mapping({"unrelated": 1}), None),
        ]
    )

    match_page = _DummyPage(_DummyResponse(True, {"ja3_hash": "deadbeef"}))
    match_result = verify_ja3_against_oracle(
        match_page, "https://oracle.example/json", expected_ja3="DEADBEEF"
    )
    checks.append(
        ("ja3_oracle_match_true", match_result["tls_fingerprint_ja3_matches_browser"], True)
    )
    checks.append(("ja3_oracle_records_observed", match_result["observed_ja3"], "deadbeef"))

    mismatch_page = _DummyPage(_DummyResponse(True, {"ja3_hash": "0011"}))
    mismatch_result = verify_ja3_against_oracle(
        mismatch_page, "https://oracle.example/json", expected_ja3="ffff"
    )
    checks.append(
        ("ja3_oracle_mismatch_false", mismatch_result["tls_fingerprint_ja3_matches_browser"], False)
    )

    empty_page = _DummyPage(_DummyResponse(True, {"unrelated": 1}), content="no fingerprint here")
    empty_result = verify_ja3_against_oracle(
        empty_page, "https://oracle.example/json", expected_ja3="ffff"
    )
    checks.append(
        ("ja3_oracle_no_value_stays_none", empty_result["tls_fingerprint_ja3_matches_browser"], None)
    )

    tele = base_telemetry(
        "stealth",
        proxy_url="socks5://127.0.0.1:10808",
        url="https://example.com",
        browser_flavor="test",
        headless=True,
    )
    checks.append(("telemetry_has_engine_capabilities", "engine_capabilities" in tele, True))
    checks.append(
        (
            "telemetry_tls_match_defaults_none",
            tele["fingerprint_validation"]["tls_fingerprint_ja3_matches_browser"],
            None,
        )
    )
    checks.append(
        (
            "telemetry_verification_method_not_measured",
            tele["fingerprint_validation"]["verification_method"],
            "not_measured",
        )
    )

    # The diagnostics probe must expose JA3 oracle parameters and only populate
    # fingerprint_validation when an oracle is supplied. We verify the public
    # signature so the verified-session command can rely on it.
    import inspect

    from browser_diagnostics import run_diagnostics_probe

    sig = inspect.signature(run_diagnostics_probe)
    checks.append(("probe_accepts_ja3_oracle", "ja3_oracle_url" in sig.parameters, True))
    checks.append(("probe_accepts_expected_ja3", "expected_ja3" in sig.parameters, True))

    failed = False
    for name, actual, expected in checks:
        if actual != expected:
            failed = True
            print(f"FAIL {name}: expected={expected} actual={actual}")
        else:
            print(f"PASS {name}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
