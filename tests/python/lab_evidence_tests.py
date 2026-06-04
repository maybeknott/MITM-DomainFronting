#!/usr/bin/env python3
"""Tests for lab evidence bundle validation."""
from __future__ import annotations

import _path  # noqa: F401

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_lab_evidence_validate_accepts_minimal_bundle() -> None:
    bundle = {
        "overall": "warn",
        "scenarios": {
            name: {"status": "pass", "report": {"scenario": name, "status": "pass"}}
            for name in (
                "resolver-timeout",
                "fallback-order",
                "dns-hijack",
                "fake-dns-lab",
                "split-dns",
                "nat64-dns64",
                "captive-portal",
                "fakedns_recovery",
                "udp443-policy",
                "fragment-policy",
                "reality-stub",
                "fakedns-policy",
                "tun-stub",
                "ttl-spin-policy",
                "firewall-checklist",
                "evasion-lab-profiles",
            )
        },
    }
    bundle["scenarios"]["fakedns_recovery"] = {"status": "pass", "report": {"overall": "pass"}}
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "bundle.json"
        path.write_text(json.dumps(bundle), encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "lab_evidence_validate.py"), str(path), "--allow-warn"],
            cwd=str(ROOT),
            text=True,
            capture_output=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr


def test_protocol_smoke_firewall_checklist_passes() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "protocol_smoke.py"), "--scenario", "firewall-checklist"],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    assert data["scenario"] == "firewall-checklist"
    assert data["status"] == "pass"


def main() -> int:
    test_lab_evidence_validate_accepts_minimal_bundle()
    print("PASS test_lab_evidence_validate_accepts_minimal_bundle")
    test_protocol_smoke_firewall_checklist_passes()
    print("PASS test_protocol_smoke_firewall_checklist_passes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
