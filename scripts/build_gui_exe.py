#!/usr/bin/env python3
"""Build the Windows desktop GUI executable with PyInstaller."""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_NAME = "MITM-DomainFronting-Control-Center"
DIST_ROOT = ROOT / "dist"
APP_DIR = DIST_ROOT / APP_NAME
BUILD_RUN_ROOT = ROOT / "build" / "pyinstaller-runs"

EXCLUDED_TRACKED_PREFIXES = (
    ".github/",
    "patches/",
)
EXCLUDED_TRACKED_FILES = {
    ".gitignore",
}
FALLBACK_DIRS = ("scripts", "configs", "docs", "providers", "Xray-config", "config-src")
FALLBACK_TOP_FILES = (
    "README.md",
    "SECURITY.md",
    "PRIVACY.md",
    "CHANGELOG.md",
    "SUPPORT_MATRIX.md",
    "KNOWN_ISSUES.md",
    "THREAT_MODEL.md",
    "LICENSE",
)
EXCLUDED_OUTPUT_PARTS = {"build", "dist", ".git", "__pycache__"}
EXCLUDED_RUNTIME_NAMES = {"mycert.crt", "mycert.key", "validation-report.json", "checksums.txt"}
BACKEND_HIDDEN_IMPORTS = (
    "copy",
    "datetime",
    "hashlib",
    "platform",
    "random",
    "re",
    "shutil",
    "socket",
    "stat",
    "struct",
    "time",
    "urllib.request",
    "zipfile",
)


def run(cmd: list[str], *, timeout: int = 300) -> None:
    print("$ " + " ".join(cmd))
    subprocess.run(cmd, cwd=str(ROOT), timeout=timeout, check=True)


def has_pyinstaller() -> bool:
    proc = subprocess.run(
        [sys.executable, "-m", "PyInstaller", "--version"],
        cwd=str(ROOT),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.returncode == 0


def ensure_pyinstaller(skip_install: bool) -> None:
    if has_pyinstaller():
        return
    if skip_install:
        raise SystemExit("PyInstaller is not installed. Re-run without --skip-install or install pyinstaller first.")
    run([sys.executable, "-m", "pip", "install", "--upgrade", "pyinstaller"], timeout=600)


def tracked_files() -> list[Path]:
    proc = subprocess.run(
        ["git", "ls-files"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        return fallback_source_files()
    files: list[Path] = []
    seen: set[Path] = set()
    for line in proc.stdout.splitlines():
        rel = line.strip().replace("\\", "/")
        if not rel:
            continue
        if rel in EXCLUDED_TRACKED_FILES:
            continue
        if any(rel.startswith(prefix) for prefix in EXCLUDED_TRACKED_PREFIXES):
            continue
        path = ROOT / rel
        files.append(path)
        seen.add(path.resolve())
    for path in fallback_source_files():
        resolved = path.resolve()
        if resolved not in seen:
            files.append(path)
            seen.add(resolved)
    return files


def fallback_source_files() -> list[Path]:
    files: list[Path] = []
    for name in FALLBACK_TOP_FILES:
        path = ROOT / name
        if path.exists():
            files.append(path)
    for dirname in FALLBACK_DIRS:
        base = ROOT / dirname
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            rel_parts = set(path.relative_to(ROOT).parts)
            if rel_parts & EXCLUDED_OUTPUT_PARTS:
                continue
            if path.name in EXCLUDED_RUNTIME_NAMES or path.suffix == ".pyc":
                continue
            files.append(path)
    return files


def copy_runtime_files() -> None:
    for src in tracked_files():
        rel = src.relative_to(ROOT)
        dst = APP_DIR / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def build_run_dirs() -> tuple[Path, Path]:
    run_id = f"{int(time.time())}-{os.getpid()}"
    work_dir = BUILD_RUN_ROOT / run_id / "work"
    spec_dir = BUILD_RUN_ROOT / run_id / "spec"
    work_dir.mkdir(parents=True, exist_ok=True)
    spec_dir.mkdir(parents=True, exist_ok=True)
    return work_dir, spec_dir


def build_exe(skip_install: bool) -> Path:
    ensure_pyinstaller(skip_install)
    shutil.rmtree(APP_DIR, ignore_errors=True)
    work_dir, spec_dir = build_run_dirs()
    run([
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--windowed",
        "--name",
        APP_NAME,
        "--distpath",
        str(DIST_ROOT),
        "--workpath",
        str(work_dir),
        "--specpath",
        str(spec_dir),
        *[item for module in BACKEND_HIDDEN_IMPORTS for item in ("--hidden-import", module)],
        str(ROOT / "scripts" / "gui.py"),
    ], timeout=900)
    copy_runtime_files()
    exe = APP_DIR / f"{APP_NAME}.exe"
    if not exe.exists():
        raise SystemExit(f"Expected executable was not created: {exe}")
    return exe


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the MITM-DomainFronting GUI executable")
    parser.add_argument("--skip-install", action="store_true", help="do not install PyInstaller if it is missing")
    args = parser.parse_args()
    exe = build_exe(args.skip_install)
    print()
    print(f"Built: {exe}")
    print("Open the dist folder and double-click the executable:")
    print(f"  {APP_DIR}")
    print()
    print("Build outputs are local artifacts and should not be committed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
