#!/usr/bin/env python3
"""Simple local certificate/key lifecycle helper.

This preserves the easy Xray certificate generation flow while adding status,
fingerprint, rotate, remove-local, and emergency helpers. It never uploads files
and never prints private-key contents.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional


def sha256_file(path: Path) -> Optional[str]:
    if not path.exists():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def find_xray() -> Optional[str]:
    candidates: List[str] = []
    env = os.environ.get("XRAY_BIN")
    if env:
        candidates.append(env)
    candidates.extend([
        "./xray",
        "./xray.exe",
        "./xray/xray",
        "./xray/xray.exe",
        "xray",
        "xray.exe",
    ])
    for candidate in candidates:
        path = shutil.which(candidate) if candidate in {"xray", "xray.exe"} else candidate
        if path and Path(path).exists():
            return path
    return None


def openssl_info(cert: Path) -> str:
    if not cert.exists():
        return "certificate missing"
    try:
        p = subprocess.run(
            ["openssl", "x509", "-in", str(cert), "-noout", "-subject", "-issuer", "-enddate", "-fingerprint", "-sha256"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001
        return f"openssl unavailable: {exc}"
    if p.returncode != 0:
        return f"openssl failed: {p.stderr.strip()}"
    return p.stdout.strip()


def key_permission_text(key: Path) -> str:
    if not key.exists():
        return "missing"
    if os.name == "nt":
        return "Windows ACL not evaluated; keep file private"
    mode = stat.S_IMODE(key.stat().st_mode)
    advice = []
    if mode & stat.S_IROTH:
        advice.append("world-readable; run chmod 600")
    if mode & stat.S_IRGRP:
        advice.append("group-readable; chmod 600 is stricter")
    return f"{oct(mode)}" + (" (" + "; ".join(advice) + ")" if advice else "")


def status(cert: Path, key: Path) -> int:
    print(f"cert: {cert}")
    print(f"cert_exists: {cert.exists()}")
    cert_hash = sha256_file(cert)
    if cert_hash:
        print(f"cert_sha256: {cert_hash}")
        print("cert_sha256_prefix_for_issues: " + cert_hash[:12])
    print(f"key: {key}")
    print(f"key_exists: {key.exists()}")
    print(f"key_permissions: {key_permission_text(key)}")
    print("certificate_info:")
    print(openssl_info(cert))
    return 0 if cert.exists() and key.exists() else 2


def backup_existing(out_dir: Path) -> None:
    backup = out_dir / "cert-backups" / time.strftime("%Y%m%d%H%M%S")
    active = [out_dir / "mycert.crt", out_dir / "mycert.key"]
    if any(p.exists() for p in active):
        backup.mkdir(parents=True, exist_ok=True)
        for p in active:
            if p.exists():
                shutil.copy2(p, backup / p.name)
        print(f"backed_up_existing_files: {backup}")


def generate(out_dir: Path, backup: bool = False) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    if backup:
        backup_existing(out_dir)
    xray = find_xray()
    if not xray:
        print("ERROR: xray binary not found. Put this script near xray or set XRAY_BIN=/path/to/xray", file=sys.stderr)
        return 2
    cmd = [xray, "tls", "cert", "-ca", "-file=mycert"]
    print("running: " + " ".join(cmd))
    p = subprocess.run(cmd, cwd=str(out_dir), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if p.returncode != 0:
        print(p.stdout)
        print(p.stderr, file=sys.stderr)
        return p.returncode or 1
    cert = out_dir / "mycert.crt"
    key = out_dir / "mycert.key"
    if os.name != "nt" and key.exists():
        key.chmod(0o600)
    print("created:")
    print(f"  {cert}")
    print(f"  {key}")
    cert_hash = sha256_file(cert)
    if cert_hash:
        print(f"cert_sha256: {cert_hash}")
    print("Keep mycert.key private. Do not post it in issues or send it to anyone.")
    return 0


def remove_local(cert: Path, key: Path, yes: bool) -> int:
    if not yes:
        print("Refusing to remove without --yes")
        return 2
    for path in [cert, key]:
        if path.exists():
            path.unlink()
            print(f"removed: {path}")
        else:
            print(f"not_found: {path}")
    print("Also remove the trusted CA from OS/browser trust stores if you are uninstalling.")
    return 0


def emergency(out_dir: Path) -> int:
    print("Emergency rotation: treat the old CA as compromised.")
    print("1. Remove the old trusted CA from OS/browser stores.")
    print("2. Generate a new local CA now.")
    code = generate(out_dir, backup=True)
    print("3. Install the new mycert.crt and verify its fingerprint.")
    print("4. Do not reuse the old mycert.key.")
    return code


def main() -> int:
    parser = argparse.ArgumentParser(description="Local CA helper for MITM-DomainFronting")
    sub = parser.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("status")
    s.add_argument("--cert", type=Path, default=Path("Xray-config/mycert.crt"))
    s.add_argument("--key", type=Path, default=Path("Xray-config/mycert.key"))

    g = sub.add_parser("generate")
    g.add_argument("--out-dir", type=Path, default=Path("Xray-config"))

    r = sub.add_parser("rotate")
    r.add_argument("--out-dir", type=Path, default=Path("Xray-config"))

    rm = sub.add_parser("remove-local")
    rm.add_argument("--cert", type=Path, default=Path("Xray-config/mycert.crt"))
    rm.add_argument("--key", type=Path, default=Path("Xray-config/mycert.key"))
    rm.add_argument("--yes", action="store_true")

    e = sub.add_parser("emergency")
    e.add_argument("--out-dir", type=Path, default=Path("Xray-config"))

    args = parser.parse_args()
    if args.cmd == "status":
        return status(args.cert, args.key)
    if args.cmd == "generate":
        return generate(args.out_dir, backup=False)
    if args.cmd == "rotate":
        return generate(args.out_dir, backup=True)
    if args.cmd == "remove-local":
        return remove_local(args.cert, args.key, args.yes)
    if args.cmd == "emergency":
        return emergency(args.out_dir)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
