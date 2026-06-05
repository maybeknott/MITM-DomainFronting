#!/usr/bin/env python3
"""Run a verified runtime session and save one redacted evidence bundle.

This command closes the gap between "config is valid" and "runtime is proven".
It composes the shared readiness model (`scripts/core/readiness.py`) with the
existing browser diagnostics probe and the opt-in JA3 echo-oracle helper, then
writes a single redacted JSON bundle that can be attached to release evidence.

Design rules (kept deliberately honest):
- Only local, redacted facts are collected. Process paths are basename-only and
  PIDs are dropped from the saved bundle.
- The page check and JA3 oracle steps are opt-in. When the page check is not
  run, page_check stays "not_run"; when no JA3 oracle is supplied, the JA3
  result stays "not_measured". We never fabricate a measured fingerprint.
- The bundle records config/profile hashes so reviewers can tie evidence to an
  exact compiled config.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from core.readiness import (  # noqa: E402
    ProjectState,
    build_project_state,
    state_to_dict,
)

PROFILE_NAMES = ("strict", "balanced", "compatibility", "debug")


def _sha256_file(path: Path) -> Optional[str]:
    if not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _redact_state(state: ProjectState) -> Dict[str, Any]:
    """Drop locally-identifying fields from the saved state.

    The live ProjectState keeps full process paths and PIDs so the GUI/CLI can
    show actionable evidence, but the persisted bundle should not leak local
    filesystem layout. We keep the process *name* and the listener exposure
    classification, which is what reviewers actually need.
    """
    data = state_to_dict(state)
    data.pop("listener_pid", None)
    process_path = data.get("listener_process_path") or ""
    if process_path:
        data["listener_process_path"] = Path(process_path).name
    data["root"] = "<redacted>"
    return data


def _config_hash(root: Path, config_path: Path) -> Dict[str, Any]:
    profile_hashes: Dict[str, Optional[str]] = {}
    for name in PROFILE_NAMES:
        profile_path = root / "Xray-config" / f"Xray-Cooperative-Overlay.{name}.json"
        profile_hashes[name] = _sha256_file(profile_path)
    return {
        "config_sha256": _sha256_file(config_path),
        "profile_sha256": profile_hashes,
    }


def _run_page_check(
    *,
    url: str,
    proxy_url: Optional[str],
    cert_path: Path,
    timeout_ms: int,
    headless: bool,
    ja3_oracle_url: Optional[str],
    expected_ja3: Optional[str],
) -> Dict[str, Any]:
    """Run the stock-Chromium diagnostics probe and reduce it to evidence fields."""
    try:
        from browser_diagnostics import run_diagnostics_probe
    except Exception as exc:  # noqa: BLE001
        return {
            "status": "skipped",
            "reason": f"browser diagnostics unavailable: {exc}",
        }

    try:
        telemetry = run_diagnostics_probe(
            url,
            proxy_url=proxy_url,
            headless=headless,
            navigation_timeout_ms=timeout_ms,
            cert_path=cert_path,
            ja3_oracle_url=ja3_oracle_url,
            expected_ja3=expected_ja3,
        )
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "reason": str(exc)}

    exec_state = telemetry.get("execution_state", {})
    net = telemetry.get("network_telemetry", {})
    success = bool(exec_state.get("page_load_success"))
    return {
        "status": "pass" if success else "fail",
        "target_url": exec_state.get("target_url"),
        "resolved_url": exec_state.get("resolved_url"),
        "page_load_success": success,
        "handshake_latency_ms": net.get("handshake_latency_ms"),
        "certificate_chain_state": net.get("certificate_chain_state"),
        "local_mitm_decryption_verified": net.get("local_mitm_decryption_verified"),
        "execution_exception": exec_state.get("execution_exception"),
        "fingerprint_validation": telemetry.get("fingerprint_validation", {}),
    }


def build_bundle(
    *,
    root: Path,
    config_path: Path,
    cert_path: Path,
    key_path: Path,
    skip_trust: bool,
    skip_runtime: bool,
    run_page_check: bool,
    page_url: str,
    proxy_url: Optional[str],
    timeout_ms: int,
    headless: bool,
    ja3_oracle_url: Optional[str],
    expected_ja3: Optional[str],
) -> Dict[str, Any]:
    state = build_project_state(
        root=root,
        config_path=config_path,
        cert_path=cert_path,
        key_path=key_path,
        skip_trust=skip_trust,
        skip_runtime=skip_runtime,
    )

    page_check: Dict[str, Any] = {"status": "not_run"}
    ja3_result: Dict[str, Any] = {
        "verification_method": "not_measured",
        "observed_ja3": None,
        "expected_ja3": expected_ja3,
        "tls_fingerprint_ja3_matches_browser": None,
    }
    if run_page_check:
        page_check = _run_page_check(
            url=page_url,
            proxy_url=proxy_url,
            cert_path=cert_path,
            timeout_ms=timeout_ms,
            headless=headless,
            ja3_oracle_url=ja3_oracle_url,
            expected_ja3=expected_ja3,
        )
        fv = page_check.get("fingerprint_validation")
        if isinstance(fv, dict) and fv.get("verification_method"):
            ja3_result = fv

    hashes = _config_hash(root, config_path)

    blockers: List[str] = list(state.release_blockers)
    if run_page_check and page_check.get("status") not in {"pass", "skipped"}:
        blockers.append("page_check")

    bundle: Dict[str, Any] = {
        "schema": "xray-cooperative-overlay/verified-session/1",
        "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "generated_by": "scripts/verified_session.py",
        "note": "Review before sharing. Local, redacted runtime evidence only.",
        "redaction_status": "redacted",
        "overall": state.overall,
        "next_action": state.next_action,
        "xray_version": state.xray_version,
        "config_hash": hashes["config_sha256"],
        "profile_hashes": hashes["profile_sha256"],
        "listener_evidence": {
            "status": state.listener_status,
            "exposure": state.listener_exposure,
            "host": state.listener_host,
            "port": state.listener_port,
            "owner": state.xray_owner,
            "process_name": state.listener_process_name,
        },
        "trust_evidence": {
            "status": state.trust_status,
            "windows_user": state.trust_windows_user,
            "windows_machine": state.trust_windows_machine,
        },
        "cert_evidence": {
            "cert_exists": state.cert_exists,
            "key_exists": state.key_exists,
            "cert_key_match": state.cert_key_match,
            "cert_expiry_status": state.cert_expiry_status,
            "key_permission_status": state.key_permission_status,
        },
        "page_check_result": page_check,
        "ja3_result": ja3_result,
        "project_state": _redact_state(state),
        "check_results": [asdict(check) for check in state.checks],
        "release_blockers": blockers,
    }
    return bundle


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run a verified runtime session and save one redacted evidence bundle."
    )
    parser.add_argument("--config", type=Path, default=ROOT / "Xray-config" / "Xray-Cooperative-Overlay.json")
    parser.add_argument("--cert", type=Path, default=ROOT / "Xray-config" / "mycert.crt")
    parser.add_argument("--key", type=Path, default=ROOT / "Xray-config" / "mycert.key")
    parser.add_argument("--skip-trust", action="store_true", help="skip local trust-store matching")
    parser.add_argument("--skip-runtime", action="store_true", help="skip live listener/process checks")
    parser.add_argument(
        "--page-check",
        action="store_true",
        help="run the stock-Chromium page check through the local proxy (opt-in)",
    )
    parser.add_argument("--page-url", default="https://example.com", help="URL for the optional page check")
    parser.add_argument("--proxy", default=None, help="proxy URL override for the page check")
    parser.add_argument("--timeout-ms", type=int, default=30000)
    parser.add_argument("--headless", action="store_true", help="run the page check headless")
    parser.add_argument(
        "--ja3-oracle",
        default=None,
        help="optional JA3 echo oracle URL; only used when --page-check is set",
    )
    parser.add_argument("--expected-ja3", default=None, help="optional expected JA3/JA3 hash")
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / ".local-state" / "runtime-evidence.json",
        help="path to write the redacted evidence bundle",
    )
    parser.add_argument("--no-write", action="store_true", help="print the bundle but do not write a file")
    args = parser.parse_args(argv)

    bundle = build_bundle(
        root=ROOT,
        config_path=args.config,
        cert_path=args.cert,
        key_path=args.key,
        skip_trust=args.skip_trust,
        skip_runtime=args.skip_runtime,
        run_page_check=args.page_check,
        page_url=args.page_url,
        proxy_url=args.proxy,
        timeout_ms=args.timeout_ms,
        headless=args.headless,
        ja3_oracle_url=args.ja3_oracle,
        expected_ja3=args.expected_ja3,
    )

    text = json.dumps(bundle, indent=2, ensure_ascii=False)
    if not args.no_write:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n", encoding="utf-8")
        print(f"wrote {args.out}")
    print(text)
    return 2 if bundle["overall"] == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
