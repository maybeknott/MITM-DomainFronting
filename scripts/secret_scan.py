#!/usr/bin/env python3
"""Fail if tracked files contain private-key material or unsafe key filenames."""
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

PRIVATE_KEY_MARKERS = tuple(
    "BEGIN " + key_type
    for key_type in (
        "PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
    )
)
SENSITIVE_SUFFIXES = {".key", ".pem", ".p12", ".pfx"}
SENSITIVE_NAMES = {"mycert.key"}


def git_ls_files(root: Path) -> list[Path]:
    proc = subprocess.run(
        ["git", "ls-files"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return [root / line for line in proc.stdout.splitlines() if line.strip()]


def looks_binary(data: bytes) -> bool:
    return b"\0" in data[:4096]


def scan_file(path: Path) -> list[str]:
    errors: list[str] = []
    name = path.name.lower()
    suffix = path.suffix.lower()
    if name in SENSITIVE_NAMES or suffix in SENSITIVE_SUFFIXES:
        errors.append(f"{path}: tracked private-key-like filename")
    try:
        data = path.read_bytes()
    except OSError as exc:
        return [f"{path}: cannot read: {exc}"]
    if looks_binary(data):
        return errors
    text = data.decode("utf-8", errors="ignore")
    for marker in PRIVATE_KEY_MARKERS:
        if marker in text:
            errors.append(f"{path}: contains PEM private key marker {marker!r}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan tracked files for local private keys")
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args()
    root = args.root.resolve()
    errors: list[str] = []
    for path in git_ls_files(root):
        errors.extend(scan_file(path))
    if errors:
        for error in errors:
            print(error)
        return 2
    print("secret scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
