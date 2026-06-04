#!/usr/bin/env python3
"""Tests for automatic JA3 pool-id attach on generated profiles."""
from __future__ import annotations

import _path  # noqa: F401

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from core.ja3_pool_attach import attach_for_operating_profile, validate_all_profiles_have_pool_metadata  # noqa: E402


def test_attach_sets_pool_id_on_repack_outbounds() -> None:
    base = json.loads((ROOT / "config-src" / "base.json").read_text(encoding="utf-8"))
    summary = attach_for_operating_profile(base, "strict", ROOT)
    assert summary["pool_id"] == "chrome-baseline-v1"
    assert base["mitm"]["ja3_pool_id"] == "chrome-baseline-v1"
    repack = [o for o in base["outbounds"] if str(o.get("tag", "")).startswith("tls-repack")]
    assert repack
    for outbound in repack:
        assert outbound["mitmMeta"]["ja3_pool_id"] == "chrome-baseline-v1"
        assert outbound["streamSettings"]["tlsSettings"]["fingerprint"] == "chrome"


def test_generate_profiles_emits_pool_metadata() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)
        proc = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "generate_profiles.py"),
                "--base",
                str(ROOT / "config-src" / "base.json"),
                "--out-dir",
                str(out),
            ],
            cwd=str(ROOT),
            text=True,
            capture_output=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        errors = validate_all_profiles_have_pool_metadata(out, ("strict", "balanced"))
        assert not errors, errors


def main() -> int:
    test_attach_sets_pool_id_on_repack_outbounds()
    print("PASS test_attach_sets_pool_id_on_repack_outbounds")
    test_generate_profiles_emits_pool_metadata()
    print("PASS test_generate_profiles_emits_pool_metadata")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
