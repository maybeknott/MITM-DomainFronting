#!/usr/bin/env python3
"""Regression tests for release ZIP verification."""
from __future__ import annotations

import hashlib
import tempfile
import zipfile
from pathlib import Path

import _path  # noqa: F401

from verify_release_artifact import REQUIRED_SUFFIXES, verify_zip  # noqa: E402


def write_zip(path: Path, entries: list[str]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for entry in entries:
            archive.writestr(f"MITM-DomainFronting-Control-Center/{entry}", "x")


def write_checksum(zip_path: Path, checksum_path: Path) -> None:
    digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    checksum_path.write_text(f"{digest}  {zip_path.name}\n", encoding="utf-8")


def test_complete_zip_passes() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        zip_path = root / "bundle.zip"
        checksum_path = root / "bundle.zip.sha256"
        write_zip(zip_path, list(REQUIRED_SUFFIXES))
        write_checksum(zip_path, checksum_path)
        report = verify_zip(zip_path, checksum_path)
        assert report["status"] == "pass"
        assert report["errors"] == []


def test_missing_required_entry_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        zip_path = root / "bundle.zip"
        entries = [entry for entry in REQUIRED_SUFFIXES if entry != "xray/xray.exe"]
        write_zip(zip_path, entries)
        report = verify_zip(zip_path)
        assert report["status"] == "fail"
        assert any("xray/xray.exe" in error for error in report["errors"])


def test_forbidden_certificate_key_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        zip_path = root / "bundle.zip"
        entries = list(REQUIRED_SUFFIXES) + ["Xray-config/mycert.key"]
        write_zip(zip_path, entries)
        report = verify_zip(zip_path)
        assert report["status"] == "fail"
        assert any("mycert.key" in error for error in report["errors"])


def test_checksum_mismatch_fails() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        zip_path = root / "bundle.zip"
        checksum_path = root / "bundle.zip.sha256"
        write_zip(zip_path, list(REQUIRED_SUFFIXES))
        checksum_path.write_text(f"{'0' * 64}  {zip_path.name}\n", encoding="utf-8")
        report = verify_zip(zip_path, checksum_path)
        assert report["status"] == "fail"
        assert any("checksum mismatch" in error for error in report["errors"])


def main() -> int:
    tests = [
        test_complete_zip_passes,
        test_missing_required_entry_fails,
        test_forbidden_certificate_key_fails,
        test_checksum_mismatch_fails,
    ]
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
