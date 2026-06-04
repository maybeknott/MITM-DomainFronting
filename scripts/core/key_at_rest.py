#!/usr/bin/env python3
"""At-rest helpers for the local CA private key (ACL tighten; DPAPI reserved)."""
from __future__ import annotations

import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class KeyAtRestReport:
    path: str
    platform: str
    action: str
    status: str
    detail: str
    dpapi_available: bool = False


def dpapi_available() -> bool:
    return os.name == "nt"


def restrict_key_permissions(key_path: Path) -> KeyAtRestReport:
    key_path = key_path.expanduser().resolve()
    if not key_path.exists():
        return KeyAtRestReport(
            path=str(key_path),
            platform=os.name,
            action="restrict",
            status="fail",
            detail="private key file not found",
            dpapi_available=dpapi_available(),
        )
    if os.name == "nt":
        username = os.environ.get("USERNAME") or os.environ.get("USER") or ""
        if not username:
            return KeyAtRestReport(
                path=str(key_path),
                platform="nt",
                action="restrict",
                status="warn",
                detail="current Windows user unknown; run icacls manually",
                dpapi_available=False,
            )
        grant = f"{username}:(F)"
        commands = [
            ["icacls", str(key_path), "/inheritance:r"],
            ["icacls", str(key_path), "/grant:r", grant],
        ]
        for cmd in commands:
            proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
            if proc.returncode != 0:
                detail = (proc.stderr or proc.stdout or "icacls failed").strip()
                return KeyAtRestReport(
                    path=str(key_path),
                    platform="nt",
                    action="restrict",
                    status="fail",
                    detail=detail,
                    dpapi_available=False,
                )
        return KeyAtRestReport(
            path=str(key_path),
            platform="nt",
            action="restrict",
            status="pass",
            detail=f"ACL reset to current user only ({username})",
            dpapi_available=False,
        )
    mode = stat.S_IMODE(key_path.stat().st_mode)
    key_path.chmod(0o600)
    return KeyAtRestReport(
        path=str(key_path),
        platform="posix",
        action="restrict",
        status="pass",
        detail=f"mode {oct(mode)} -> 0o600",
        dpapi_available=False,
    )
