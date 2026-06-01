#!/usr/bin/env python3
"""FakeDNS cache recovery helper with optional safe cache flush execution."""
from __future__ import annotations

import argparse
import json
import platform
import shutil
import socket
import subprocess
import time
from typing import Dict, List


def _run(cmd: List[str], timeout: int = 10) -> Dict[str, object]:
    try:
        proc = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        return {
            "command": " ".join(cmd),
            "status": "pass" if proc.returncode == 0 else "warn",
            "returncode": proc.returncode,
            "output": (proc.stdout or "").strip()[-1000:],
        }
    except Exception as exc:  # noqa: BLE001
        return {"command": " ".join(cmd), "status": "warn", "error": str(exc)}


def flush_plan() -> Dict[str, object]:
    system = platform.system().lower()
    if system == "windows":
        return {"platform": "windows", "commands": [["ipconfig", "/flushdns"]], "safe_to_auto_run": True}
    if system == "darwin":
        return {
            "platform": "macos",
            "commands": [["sudo", "dscacheutil", "-flushcache"], ["sudo", "killall", "-HUP", "mDNSResponder"]],
            "safe_to_auto_run": False,
            "note": "requires sudo; run manually",
        }
    return {
        "platform": "linux",
        "commands": [["resolvectl", "flush-caches"], ["systemd-resolve", "--flush-caches"]],
        "safe_to_auto_run": True,
    }


def resolve_check(domain: str, timeout: float) -> Dict[str, object]:
    start = time.time()
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        rows = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
        addrs = sorted({r[4][0] for r in rows})
        return {
            "id": "post_flush_resolution",
            "status": "pass",
            "domain": domain,
            "elapsed_ms": int((time.time() - start) * 1000),
            "address_count": len(addrs),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "id": "post_flush_resolution",
            "status": "warn",
            "domain": domain,
            "elapsed_ms": int((time.time() - start) * 1000),
            "error": str(exc),
        }
    finally:
        socket.setdefaulttimeout(old)


def main() -> int:
    parser = argparse.ArgumentParser(description="FakeDNS cache recovery check helper")
    parser.add_argument("--domain", default="example.com")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--yes", action="store_true", help="execute safe local DNS cache flush commands when possible")
    args = parser.parse_args()

    plan = flush_plan()
    checks: List[Dict[str, object]] = []
    executed = False
    if args.yes:
        commands = plan.get("commands", [])
        safe_to_auto_run = bool(plan.get("safe_to_auto_run"))
        if safe_to_auto_run:
            for cmd in commands:
                if not cmd:
                    continue
                if shutil.which(cmd[0]) is None:
                    checks.append({"command": " ".join(cmd), "status": "info", "detail": "command not found"})
                    continue
                checks.append(_run(cmd))
                executed = True
        else:
            checks.append({
                "id": "flush_skipped",
                "status": "info",
                "detail": "auto-run skipped; platform requires elevated manual commands",
            })

    checks.append(resolve_check(args.domain, args.timeout))
    report = {
        "scenario": "fakedns-recovery-check",
        "plan": plan,
        "executed_flush_commands": executed,
        "checks": checks,
        "next_steps": [
            "Stop Xray before final recovery validation.",
            "Flush browser DNS cache in addition to OS cache when needed.",
            "If resolution still fails, restart browser and network adapter.",
        ],
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    statuses = {str(item.get("status", "info")) for item in checks}
    return 0 if "warn" not in statuses and "fail" not in statuses else 1


if __name__ == "__main__":
    raise SystemExit(main())
