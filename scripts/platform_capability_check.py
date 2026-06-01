#!/usr/bin/env python3
"""Best-effort platform and browser capability report with ECH compatibility warning."""
from __future__ import annotations

import argparse
import platform
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

VPN_INTERFACE_KEYWORDS = {
    "tailscale",
    "tun",
    "tap",
    "vpn",
    "wireguard",
    "wintun",
    "openvpn",
    "zerotier",
    "cloudflare warp",
}


def _run(cmd: List[str], timeout: int = 8) -> str:
    try:
        proc = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        return (proc.stdout or "").strip()
    except Exception:
        return ""


def _detect_windows_browsers() -> List[Dict[str, str]]:
    paths = [
        ("chrome", Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")),
        ("chrome", Path(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe")),
        ("edge", Path(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe")),
        ("firefox", Path(r"C:\Program Files\Mozilla Firefox\firefox.exe")),
        ("firefox", Path(r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe")),
    ]
    result: List[Dict[str, str]] = []
    seen = set()
    for family, path in paths:
        if not path.exists():
            continue
        key = str(path).lower()
        if key in seen:
            continue
        seen.add(key)
        result.append({"family": family, "path": str(path), "version": _run([str(path), "--version"])})
    return result


def _detect_macos_browsers() -> List[Dict[str, str]]:
    paths = [
        ("chrome", Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")),
        ("edge", Path("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge")),
        ("firefox", Path("/Applications/Firefox.app/Contents/MacOS/firefox")),
    ]
    result: List[Dict[str, str]] = []
    for family, path in paths:
        if path.exists():
            result.append({"family": family, "path": str(path), "version": _run([str(path), "--version"])})
    return result


def _detect_linux_browsers() -> List[Dict[str, str]]:
    commands = [
        ("chrome", ["google-chrome", "--version"]),
        ("chrome", ["chromium", "--version"]),
        ("edge", ["microsoft-edge", "--version"]),
        ("firefox", ["firefox", "--version"]),
    ]
    result: List[Dict[str, str]] = []
    for family, cmd in commands:
        version = _run(cmd)
        if version:
            result.append({"family": family, "path": cmd[0], "version": version})
    return result


def detect_browsers() -> List[Dict[str, str]]:
    system = platform.system().lower()
    if system == "windows":
        return _detect_windows_browsers()
    if system == "darwin":
        return _detect_macos_browsers()
    return _detect_linux_browsers()


def parse_major(version_text: str) -> Optional[int]:
    match = re.search(r"(\d{2,3})\.", version_text)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def ech_warning(browsers: List[Dict[str, str]]) -> Dict[str, object]:
    reasons: List[str] = []
    ech_capable = False
    for browser in browsers:
        family = browser.get("family", "unknown")
        major = parse_major(browser.get("version", ""))
        if major is None:
            continue
        if family in {"chrome", "edge"} and major >= 117:
            ech_capable = True
            reasons.append(f"{family} {major}")
        if family == "firefox" and major >= 118:
            ech_capable = True
            reasons.append(f"{family} {major}")
    return {
        "status": "warn" if ech_capable else "info",
        "ech_capable_browser_detected": ech_capable,
        "detected_versions": reasons,
        "detail": (
            "ECH-capable browser versions detected; SNI-dependent behavior may vary by profile/network."
            if ech_capable
            else "No obvious ECH-capable browser version detected from local probes."
        ),
    }


def interface_probe() -> Dict[str, object]:
    system = platform.system().lower()
    if system == "windows":
        output = _run(["netsh", "interface", "show", "interface"])
    else:
        output = _run(["ip", "link", "show"]) or _run(["ifconfig"])
    if not output:
        return {
            "status": "info",
            "vpn_like_interfaces_detected": False,
            "matches": [],
            "detail": "interface list unavailable",
        }
    lowered = output.lower()
    matches = sorted({keyword for keyword in VPN_INTERFACE_KEYWORDS if keyword in lowered})
    return {
        "status": "warn" if matches else "pass",
        "vpn_like_interfaces_detected": bool(matches),
        "matches": matches,
        "detail": "possible VPN/TUN interfaces detected" if matches else "no common VPN/TUN keywords observed",
    }


def build_report() -> Dict[str, object]:
    browsers = detect_browsers()
    return {
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "browsers": browsers,
        "ech": ech_warning(browsers),
        "network_interfaces": interface_probe(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect local platform/browser capabilities with ECH warning")
    parser.parse_args()
    print(__import__("json").dumps(build_report(), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
