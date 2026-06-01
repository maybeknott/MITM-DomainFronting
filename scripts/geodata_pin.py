#!/usr/bin/env python3
"""Locate geosite/geoip files, hash them, and optionally verify/write a lock file."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Optional


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def locate(root: Path, name: str) -> Optional[Path]:
    matches = sorted(path for path in root.rglob(name) if ".git" not in path.parts)
    return matches[0] if matches else None


def xray_version(xray_bin: str) -> str:
    try:
        proc = subprocess.run(
            [xray_bin, "version"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=8,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001
        return f"unknown ({exc})"
    output = (proc.stdout or "").strip().splitlines()
    return output[0] if output else "unknown"


def build_report(root: Path, xray_bin: str) -> Dict[str, object]:
    geosite = locate(root, "geosite.dat")
    geoip = locate(root, "geoip.dat")
    return {
        "root": str(root),
        "xray_version": xray_version(xray_bin),
        "geosite_path": str(geosite) if geosite else None,
        "geosite_sha256": sha256_file(geosite) if geosite else None,
        "geoip_path": str(geoip) if geoip else None,
        "geoip_sha256": sha256_file(geoip) if geoip else None,
    }


def verify_against_lock(lock: Dict[str, object], current: Dict[str, object]) -> List[str]:
    errors: List[str] = []
    for key in ("geosite_sha256", "geoip_sha256"):
        expected = lock.get(key)
        actual = current.get(key)
        if expected is None:
            continue
        if actual is None:
            errors.append(f"{key}: expected hash in lock but file not found locally")
            continue
        if str(expected).lower() != str(actual).lower():
            errors.append(f"{key}: lock mismatch expected={expected} actual={actual}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Pin or verify geodata file hashes")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--lock-file", type=Path, default=Path("release-geodata-lock.json"))
    parser.add_argument("--xray-bin", default="xray")
    parser.add_argument("--write-lock", action="store_true")
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()

    root = args.root.resolve()
    lock_file = args.lock_file if args.lock_file.is_absolute() else (root / args.lock_file)
    report = build_report(root, args.xray_bin)
    output: Dict[str, object] = {"current": report, "verification": {"status": "info", "errors": []}}

    if args.write_lock:
        lock_file.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        output["write_lock"] = str(lock_file)

    if args.verify:
        if not lock_file.exists():
            output["verification"] = {
                "status": "info",
                "errors": [],
                "detail": f"lock file not present: {lock_file}",
            }
        else:
            lock = json.loads(lock_file.read_text(encoding="utf-8"))
            errors = verify_against_lock(lock, report)
            output["verification"] = {
                "status": "pass" if not errors else "fail",
                "errors": errors,
                "lock_file": str(lock_file),
            }

    print(json.dumps(output, indent=2, ensure_ascii=False))
    verification = output.get("verification", {})
    if isinstance(verification, dict) and verification.get("status") == "fail":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
