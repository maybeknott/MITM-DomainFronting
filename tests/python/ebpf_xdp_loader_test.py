#!/usr/bin/env python3
"""Tests for eBPF/XDP production loader consent and simulate mode."""
from __future__ import annotations

import _path  # noqa: F401

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_loader_rejects_without_consent() -> None:
    env = {k: v for k, v in os.environ.items() if k != "MITM_EBPF_CONSENT"}
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "ebpf_xdp_loader.py"), "--simulate", "--interface", "eth0"],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )
    assert proc.returncode != 0
    data = json.loads(proc.stdout)
    assert data.get("consent_granted") is False


def test_loader_simulate_with_consent() -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "ebpf_xdp_loader.py"), "--simulate", "--interface", "eth0"],
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "MITM_EBPF_CONSENT": "1"},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    data = json.loads(proc.stdout)
    assert data.get("attached") is True
    assert data.get("mode") == "simulated_attach"
    state = ROOT / ".local-state" / "ebpf-xdp-loader.json"
    assert state.is_file()
    state.unlink(missing_ok=True)


def main() -> int:
    test_loader_rejects_without_consent()
    print("PASS test_loader_rejects_without_consent")
    test_loader_simulate_with_consent()
    print("PASS test_loader_simulate_with_consent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
