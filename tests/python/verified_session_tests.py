#!/usr/bin/env python3
"""Regression checks for the verified-session evidence bundle."""
from __future__ import annotations

from pathlib import Path

import _path  # noqa: F401

from verified_session import build_bundle  # noqa: E402

ROOT = Path(_path.ROOT)


def _bundle() -> dict:
    return build_bundle(
        root=ROOT,
        config_path=ROOT / "Xray-config" / "MITM-DomainFronting.json",
        cert_path=ROOT / "Xray-config" / "mycert.crt",
        key_path=ROOT / "Xray-config" / "mycert.key",
        skip_trust=True,
        skip_runtime=True,
        run_page_check=False,
        page_url="https://example.com",
        proxy_url=None,
        timeout_ms=1000,
        headless=True,
        ja3_oracle_url=None,
        expected_ja3=None,
    )


def main() -> int:
    bundle = _bundle()
    checks = []

    checks.append(("schema_versioned", bundle.get("schema"), "mitm-domainfronting/verified-session/1"))
    checks.append(("redaction_status", bundle.get("redaction_status"), "redacted"))
    checks.append(("root_redacted", bundle["project_state"].get("root"), "<redacted>"))
    checks.append(("no_pid_in_state", "listener_pid" in bundle["project_state"], False))

    # JA3 must stay honestly unmeasured without an oracle.
    checks.append(
        ("ja3_not_measured", bundle["ja3_result"].get("verification_method"), "not_measured")
    )
    checks.append(("ja3_no_match", bundle["ja3_result"].get("tls_fingerprint_ja3_matches_browser"), None))

    # Page check must stay "not_run" when not requested.
    checks.append(("page_check_not_run", bundle["page_check_result"].get("status"), "not_run"))

    # Config hash is a 64-char hex sha256 when the config exists.
    config_hash = bundle.get("config_hash")
    checks.append(
        (
            "config_hash_sha256",
            isinstance(config_hash, str) and len(config_hash) == 64,
            True,
        )
    )

    # Check results are serialized as dicts with the standard fields.
    first_check = bundle["check_results"][0] if bundle["check_results"] else {}
    checks.append(("check_has_id", "id" in first_check, True))
    checks.append(("check_has_status", "status" in first_check, True))

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
