#!/usr/bin/env python3
"""Beginner-friendly local workspace bootstrapper."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def run(cmd: list[str], label: str, required: bool = True) -> bool:
    print(f"[...] {label}")
    proc = subprocess.run(cmd, cwd=str(ROOT), check=False)
    if proc.returncode == 0:
        print(f"[OK ] {label}")
        return True
    print(f"[WARN] {label} failed with exit code {proc.returncode}")
    if required:
        raise SystemExit(proc.returncode)
    return False


def venv_python(venv_dir: Path) -> Path:
    return venv_dir / ("Scripts" if os.name == "nt" else "bin") / ("python.exe" if os.name == "nt" else "python")


def main() -> int:
    parser = argparse.ArgumentParser(description="Set up Xray-Cooperative-Overlay local tooling")
    parser.add_argument("--skip-browser-tools", action="store_true", help="do not install browser diagnostic dependencies")
    parser.add_argument("--skip-xray", action="store_true", help="do not download local Xray runtime")
    args = parser.parse_args()

    print("=" * 72)
    print(" Xray-Cooperative-Overlay Bootstrap")
    print("=" * 72)
    for rel in ("Xray-config", "providers", ".local-state", "browser-profiles"):
        (ROOT / rel).mkdir(exist_ok=True)
    venv_dir = ROOT / ".venv"
    if not venv_dir.exists():
        print("[...] Creating .venv")
        venv.create(venv_dir, with_pip=True)
        print("[OK ] Created .venv")
    py = venv_python(venv_dir)
    run([str(py), "-m", "pip", "install", "--upgrade", "pip"], "Upgrade pip", required=False)
    req = ROOT / "requirements-browser-diagnostics.txt"
    if req.exists() and not args.skip_browser_tools:
        run([str(py), "-m", "pip", "install", "-r", str(req)], "Install browser diagnostics requirements", required=False)
    xray_name = "xray.exe" if os.name == "nt" else "xray"
    if not args.skip_xray and not (ROOT / "xray" / xray_name).exists():
        run([str(py), str(ROOT / "scripts" / "install_xray.py"), "--out-dir", str(ROOT / "xray")], "Install local Xray runtime", required=False)
    print("=" * 72)
    print("Bootstrap complete")
    print(f"Run GUI: {py} scripts/gui.py")
    print(f"Run audit: {py} main.py audit")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
