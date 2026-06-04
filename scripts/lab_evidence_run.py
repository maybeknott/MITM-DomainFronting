#!/usr/bin/env python3
"""Run local DNS/lab harness scenarios and emit one redacted evidence bundle."""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]

SCENARIOS = [
    ("resolver-timeout", ["--scenario", "resolver-timeout", "--domain", "example.com", "--primary-resolver", "203.0.113.1", "--fallback-resolver", "1.1.1.1"]),
    ("fallback-order", ["--scenario", "fallback-order", "--domain", "example.com", "--resolver", "1.1.1.1", "--resolver", "8.8.8.8"]),
    ("dns-hijack", ["--scenario", "dns-hijack", "--domain", "example.com", "--trusted-resolver", "1.1.1.1", "--suspect-resolver", "8.8.8.8"]),
    ("fake-dns-lab", ["--scenario", "fake-dns-lab", "--domain", "example.com", "--trusted-resolver", "1.1.1.1"]),
    ("split-dns", ["--scenario", "split-dns", "--private-domain", "router.local", "--resolver", "1.1.1.1", "--resolver", "8.8.8.8"]),
    ("nat64-dns64", ["--scenario", "nat64-dns64", "--nat64-domain", "ipv4only.arpa", "--resolver", "1.1.1.1", "--resolver", "8.8.8.8"]),
    ("captive-portal", ["--scenario", "captive-portal"]),
]

PROTOCOL_SCENARIOS = [
    ("udp443-policy", ["--scenario", "udp443-policy"]),
    ("fragment-policy", ["--scenario", "fragment-policy"]),
    ("reality-stub", ["--scenario", "reality-stub"]),
    ("fakedns-policy", ["--scenario", "fakedns-policy"]),
    ("tun-stub", ["--scenario", "tun-stub"]),
    ("ttl-spin-policy", ["--scenario", "ttl-spin-policy"]),
]


def run_script(script: str, extra: List[str], root: Path, timeout: float) -> Dict[str, Any]:
    cmd = [sys.executable, str(root / "scripts" / script), *extra]
    try:
        proc = subprocess.run(cmd, cwd=str(root), text=True, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return {"status": "warn", "error": f"timeout after {timeout}s", "command": script}
    stdout = (proc.stdout or "").strip()
    payload: Dict[str, Any] = {"status": "pass" if proc.returncode == 0 else "warn", "returncode": proc.returncode}
    if stdout:
        try:
            payload["report"] = json.loads(stdout)
        except json.JSONDecodeError:
            payload["stdout"] = stdout[-2000:]
    if proc.stderr:
        payload["stderr"] = proc.stderr.strip()[-1000:]
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate local lab harness evidence")
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--json-out", type=Path, default=None)
    parser.add_argument(
        "--allow-warn",
        action="store_true",
        help="exit 0 when overall is warn (for CI/lab desktops without full network conditions)",
    )
    args = parser.parse_args()

    bundle: Dict[str, Any] = {
        "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "generated_by": "scripts/lab_evidence_run.py",
        "note": "Review before sharing. Attach to release evidence when run in real lab environments.",
        "scenarios": {},
    }
    for name, extra in SCENARIOS:
        bundle["scenarios"][name] = run_script("dns_lab_harness.py", extra, ROOT, args.timeout)
    bundle["scenarios"]["fakedns_recovery"] = run_script("fakedns_recovery_check.py", [], ROOT, args.timeout)
    for name, extra in PROTOCOL_SCENARIOS:
        bundle["scenarios"][name] = run_script("protocol_smoke.py", extra, ROOT, args.timeout)

    statuses = [item.get("status") for item in bundle["scenarios"].values()]
    bundle["overall"] = "pass" if all(status == "pass" for status in statuses) else "warn"

    text = json.dumps(bundle, indent=2, ensure_ascii=False)
    if args.json_out:
        args.json_out.write_text(text + "\n", encoding="utf-8")
    print(text)
    if bundle["overall"] == "pass":
        return 0
    return 0 if args.allow_warn else 1


if __name__ == "__main__":
    raise SystemExit(main())
