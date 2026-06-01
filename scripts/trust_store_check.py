#!/usr/bin/env python3
"""Best-effort local trust-store matching for the MITM CA certificate."""
from __future__ import annotations

import argparse
import base64
import hashlib
import platform
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

CERT_BLOCK_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----",
    re.DOTALL,
)


def _normalize_hex(value: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", value).upper()


def _read_cert_der_blobs(path: Path) -> List[bytes]:
    raw = path.read_bytes()
    blocks = CERT_BLOCK_RE.findall(raw)
    if blocks:
        ders: List[bytes] = []
        for block in blocks:
            b64 = re.sub(rb"\s+", b"", block)
            try:
                ders.append(base64.b64decode(b64, validate=True))
            except Exception:
                continue
        if ders:
            return ders
    return [raw]


def certificate_hashes(cert_path: Path) -> Tuple[Optional[str], Optional[str]]:
    if not cert_path.exists():
        return None, None
    ders = _read_cert_der_blobs(cert_path)
    if not ders:
        return None, None
    primary = ders[0]
    return hashlib.sha256(primary).hexdigest().upper(), hashlib.sha1(primary).hexdigest().upper()


def _run(cmd: List[str], timeout: int = 10) -> Tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout or ""
    except Exception as exc:  # noqa: BLE001
        return 1, str(exc)


def _powershell_thumbprints(scope: str) -> Tuple[bool, List[str], str]:
    script = f'Get-ChildItem "Cert:\\{scope}\\Root" | Select-Object -ExpandProperty Thumbprint'
    code, out = _run(["powershell", "-NoProfile", "-Command", script], timeout=15)
    if code != 0:
        return False, [], out.strip()
    values = [_normalize_hex(line) for line in out.splitlines() if _normalize_hex(line)]
    return True, values, ""


def _certutil_thumbprints(scope: str) -> Tuple[bool, List[str], str]:
    cmd = ["certutil"]
    if scope == "CurrentUser":
        cmd.append("-user")
    cmd.extend(["-store", "Root"])
    code, out = _run(cmd, timeout=20)
    if code != 0:
        return False, [], out.strip()
    values = [
        _normalize_hex(match.group(1))
        for match in re.finditer(r"Cert Hash\(sha1\):\s*([0-9A-Fa-f ]+)", out)
    ]
    return True, [value for value in values if value], ""


def _windows_store_checks(cert_sha1: str) -> List[Dict[str, object]]:
    checks: List[Dict[str, object]] = []
    for scope in ("CurrentUser", "LocalMachine"):
        ok, thumbprints, error = _powershell_thumbprints(scope)
        source = "powershell"
        if not ok:
            certutil_ok, certutil_thumbprints, certutil_error = _certutil_thumbprints(scope)
            if certutil_ok:
                ok = True
                thumbprints = certutil_thumbprints
                error = ""
                source = "certutil"
            elif certutil_error:
                error = f"{error}; certutil fallback failed: {certutil_error}" if error else certutil_error
        if not ok:
            checks.append({
                "store": f"windows:{scope}:Root",
                "status": "unknown",
                "matched": False,
                "error": error or "unable to query store",
            })
            continue
        matched = cert_sha1 in thumbprints
        checks.append({
            "store": f"windows:{scope}:Root",
            "status": "pass" if matched else "mismatch",
            "matched": matched,
            "entries_seen": len(thumbprints),
            "source": source,
        })
    return checks


def _macos_store_checks(cert_sha256: str) -> List[Dict[str, object]]:
    checks: List[Dict[str, object]] = []
    code, out = _run(["security", "find-certificate", "-a", "-Z"], timeout=20)
    if code != 0:
        return [{
            "store": "macos:keychain-search-list",
            "status": "unknown",
            "matched": False,
            "error": out.strip() or "security command failed",
        }]
    hashes = [_normalize_hex(m.group(1)) for m in re.finditer(r"SHA-256 hash:\s*([0-9A-Fa-f: ]+)", out)]
    matched = cert_sha256 in hashes
    checks.append({
        "store": "macos:keychain-search-list",
        "status": "pass" if matched else "mismatch",
        "matched": matched,
        "entries_seen": len(hashes),
    })
    return checks


def _iter_linux_candidate_certs() -> List[Path]:
    roots = [
        Path("/etc/ssl/certs"),
        Path("/usr/local/share/ca-certificates"),
        Path("/etc/pki/ca-trust/source/anchors"),
        Path("/etc/pki/tls/certs"),
    ]
    files: List[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".crt", ".pem", ".cer"}:
                files.append(path)
            if len(files) >= 2000:
                break
    return files


def _linux_store_checks(cert_sha256: str) -> List[Dict[str, object]]:
    files = _iter_linux_candidate_certs()
    if not files:
        return [{
            "store": "linux:system-trust",
            "status": "unknown",
            "matched": False,
            "error": "no common trust certificate files found",
        }]
    scanned = 0
    matched = False
    for file_path in files:
        scanned += 1
        try:
            for der in _read_cert_der_blobs(file_path):
                digest = hashlib.sha256(der).hexdigest().upper()
                if digest == cert_sha256:
                    matched = True
                    break
        except Exception:
            continue
        if matched:
            break
    return [{
        "store": "linux:system-trust",
        "status": "pass" if matched else "mismatch",
        "matched": matched,
        "entries_seen": scanned,
    }]


def firefox_profiles_hint() -> Dict[str, object]:
    system = platform.system().lower()
    roots: List[Path] = []
    if system == "windows":
        appdata = Path.home() / "AppData" / "Roaming" / "Mozilla" / "Firefox"
        roots.append(appdata)
    elif system == "darwin":
        roots.append(Path.home() / "Library" / "Application Support" / "Firefox")
    else:
        roots.append(Path.home() / ".mozilla" / "firefox")
    profile_count = 0
    for root in roots:
        if not root.exists():
            continue
        profile_count += len([p for p in root.glob("*.default*") if p.is_dir()])
    return {
        "profiles_detected": profile_count,
        "separate_trust_store_possible": profile_count > 0,
        "note": "Firefox may use separate trust behavior; verify browser-specific CA settings.",
    }


def evaluate_status(cert_exists: bool, store_checks: List[Dict[str, object]], platform_name: str) -> str:
    if not cert_exists:
        return "missing"
    if platform_name.startswith("android"):
        return "not_supported"
    statuses = {str(item.get("status", "unknown")) for item in store_checks}
    if "pass" in statuses:
        return "pass"
    if "mismatch" in statuses and "unknown" not in statuses:
        return "mismatch"
    if "unknown" in statuses:
        return "unknown"
    return "unknown"


def build_report(cert_path: Path) -> Dict[str, object]:
    system = platform.system().lower()
    sha256_hex, sha1_hex = certificate_hashes(cert_path)
    cert_exists = cert_path.exists()
    store_checks: List[Dict[str, object]] = []
    if cert_exists and sha256_hex and sha1_hex:
        if system == "windows":
            store_checks = _windows_store_checks(sha1_hex)
        elif system == "darwin":
            store_checks = _macos_store_checks(sha256_hex)
        elif system == "linux":
            store_checks = _linux_store_checks(sha256_hex)
        else:
            store_checks = [{
                "store": f"{system}:unknown",
                "status": "not_supported",
                "matched": False,
                "error": "platform trust-store checks not implemented",
            }]
    status = evaluate_status(cert_exists, store_checks, system)
    return {
        "status": status,
        "platform": system,
        "cert": {
            "path": str(cert_path),
            "exists": cert_exists,
            "sha256": sha256_hex,
            "sha1": sha1_hex,
        },
        "store_checks": store_checks,
        "firefox": firefox_profiles_hint(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Check whether MITM CA certificate appears in local trust stores")
    parser.add_argument("--cert", type=Path, default=Path("Xray-config/mycert.crt"))
    args = parser.parse_args()
    report = build_report(args.cert)
    print(__import__("json").dumps(report, indent=2, ensure_ascii=False))
    status = str(report.get("status"))
    return 0 if status in {"pass", "unknown", "not_supported"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
