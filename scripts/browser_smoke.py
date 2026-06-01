#!/usr/bin/env python3
"""Optional local browser smoke check that runs diagnostics and stealth probes."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict

from browser_diagnostics import run_diagnostics_probe
from browser_stealth import run_stealth_probe


def _status(payload: Dict[str, object]) -> str:
    execution = payload.get("execution_state", {})
    if isinstance(execution, dict) and execution.get("page_load_success") is True:
        return "pass"
    if isinstance(execution, dict) and execution.get("execution_exception"):
        return "warn"
    return "warn"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run optional diagnostics + stealth browser smoke checks")
    parser.add_argument("--url", default="https://example.com")
    parser.add_argument("--proxy", default="socks5://127.0.0.1:10808")
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--cert", type=Path, default=Path("Xray-config/mycert.crt"))
    parser.add_argument("--timeout-ms", type=int, default=30000)
    args = parser.parse_args()

    diagnostics = run_diagnostics_probe(
        args.url,
        proxy_url=args.proxy,
        headless=args.headless,
        navigation_timeout_ms=args.timeout_ms,
        cert_path=args.cert,
    )
    stealth = run_stealth_probe(
        args.url,
        proxy_url=args.proxy,
        headless=args.headless,
        navigation_timeout_ms=args.timeout_ms,
        cert_path=args.cert,
    )
    result = {
        "target_url": args.url,
        "proxy": args.proxy,
        "diagnostics": diagnostics,
        "stealth": stealth,
        "summary": {
            "diagnostics": _status(diagnostics),
            "stealth": _status(stealth),
        },
    }
    result["summary"]["overall"] = (
        "pass"
        if result["summary"]["diagnostics"] == "pass" and result["summary"]["stealth"] == "pass"
        else "warn"
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["summary"]["overall"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
