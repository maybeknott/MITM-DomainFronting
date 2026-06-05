#!/usr/bin/env python3
"""Verify the packaged Windows GUI release artifact shape."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path
from typing import Iterable

APP_EXE = "Xray-Cooperative-Overlay-Control-Center.exe"

REQUIRED_SUFFIXES = (
    APP_EXE,
    "PRODUCT-BUNDLE.txt",
    "README.md",
    "scripts/gui.py",
    "scripts/core/readiness.py",
    "scripts/core/gui_readiness.py",
    "tests/python/repository_structure_tests.py",
    "tests/python/readiness_tests.py",
    "configs/browser-integration.json",
    "config-src/manifest.json",
    "providers/google.yml",
    "providers/fastly.yml",
    "providers/meta.yml",
    "Xray-config/Xray-Cooperative-Overlay.json",
    "Xray-config/Xray-Cooperative-Overlay.strict.json",
    "Xray-config/Xray-Cooperative-Overlay.balanced.json",
    "Xray-config/Xray-Cooperative-Overlay.compatibility.json",
    "Xray-config/Xray-Cooperative-Overlay.debug.json",
    "xray/xray.exe",
    "xray/geoip.dat",
    "xray/geosite.dat",
)

FORBIDDEN_SUFFIXES = (
    ".git/",
    ".github/",
    "patches/",
    "Xray-config/mycert.key",
    "Xray-config/mycert.crt",
    "mycert.key",
    "mycert.crt",
    "validation-report.json",
    "checksums.txt",
)


def normalize_entry(name: str) -> str:
    return name.replace("\\", "/").strip("/")


def entry_matches(entries: Iterable[str], suffix: str) -> bool:
    suffix = normalize_entry(suffix)
    return any(entry == suffix or entry.endswith("/" + suffix) for entry in entries)


def forbidden_matches(entries: Iterable[str], suffix: str) -> list[str]:
    suffix = normalize_entry(suffix)
    if suffix.endswith("/"):
        return [entry for entry in entries if entry.startswith(suffix) or ("/" + suffix) in entry]
    return [entry for entry in entries if entry == suffix or entry.endswith("/" + suffix)]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_checksum(zip_path: Path, checksum_path: Path | None) -> tuple[bool, str]:
    if checksum_path is None:
        return True, "checksum check skipped"
    if not checksum_path.exists():
        return False, f"checksum file missing: {checksum_path}"
    expected = checksum_path.read_text(encoding="utf-8").strip().split()
    if not expected:
        return False, f"checksum file is empty: {checksum_path}"
    actual = sha256_file(zip_path)
    if expected[0].lower() != actual.lower():
        return False, f"checksum mismatch: expected {expected[0]}, got {actual}"
    if len(expected) > 1 and expected[1] != zip_path.name:
        return False, f"checksum filename mismatch: expected {expected[1]}, got {zip_path.name}"
    return True, "checksum matches"


def verify_zip(zip_path: Path, checksum_path: Path | None = None) -> dict[str, object]:
    errors: list[str] = []
    warnings: list[str] = []
    if not zip_path.exists():
        return {"status": "fail", "errors": [f"zip not found: {zip_path}"], "warnings": warnings}
    if not zipfile.is_zipfile(zip_path):
        return {"status": "fail", "errors": [f"not a zip file: {zip_path}"], "warnings": warnings}

    with zipfile.ZipFile(zip_path) as archive:
        entries = sorted(normalize_entry(info.filename) for info in archive.infolist() if not info.is_dir())

    for suffix in REQUIRED_SUFFIXES:
        if not entry_matches(entries, suffix):
            errors.append(f"missing required artifact entry: {suffix}")
    for suffix in FORBIDDEN_SUFFIXES:
        matches = forbidden_matches(entries, suffix)
        if matches:
            errors.append(f"forbidden artifact entry present: {suffix} ({matches[0]})")
    checksum_ok, checksum_detail = verify_checksum(zip_path, checksum_path)
    if not checksum_ok:
        errors.append(checksum_detail)
    elif checksum_path is None:
        warnings.append(checksum_detail)

    return {
        "status": "fail" if errors else "pass",
        "zip": str(zip_path),
        "checksum": str(checksum_path) if checksum_path else "",
        "entry_count": len(entries),
        "required_entries": list(REQUIRED_SUFFIXES),
        "errors": errors,
        "warnings": warnings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify Xray-Cooperative-Overlay GUI release ZIP contents")
    parser.add_argument("zip", type=Path, help="release ZIP to inspect")
    parser.add_argument("--checksum", type=Path, help="optional .sha256 file to verify")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)
    report = verify_zip(args.zip, args.checksum)
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"release artifact verification: {report['status']}")
        for error in report["errors"]:
            print(f"FAIL: {error}")
        for warning in report["warnings"]:
            print(f"WARN: {warning}")
    return 0 if report["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
