#!/usr/bin/env python3
"""Shared readiness model for Xray-Cooperative-Overlay.

This module is the first common "truth layer" for CLI, GUI, health probes, and
future release checks. It intentionally gathers only local, redacted facts.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parents[1]
ROOT = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from core.ja3_evidence import load_evidence  # noqa: E402


STATUS_ORDER = {"fail": 4, "warn": 3, "info": 2, "pass": 1}
EXPECTED_PORTS = [10808, 11666, 11777, 11888, 11999]
PROFILE_NAMES = ("strict", "balanced", "compatibility", "debug")


@dataclass(frozen=True)
class CheckResult:
    id: str
    category: str
    status: str
    summary: str
    evidence: str = ""
    impact: str = ""
    recommended_action: str = ""
    fix_command: str = ""
    safe_to_auto_fix: bool = False
    requires_admin: bool = False
    docs_url_or_path: str = ""


@dataclass(frozen=True)
class RepairAction:
    id: str
    label: str
    description: str
    risk: str = "low"
    requires_admin: bool = False
    changes_files: bool = False
    changes_system: bool = False
    reversible: bool = True
    command: str = ""
    confirmation_required: bool = False


@dataclass
class ProjectState:
    generated_at: str
    root: str
    overall: str
    next_action: str
    next_action_detail: str

    config_ok: bool
    config_path: str
    config_remarks: str = ""
    config_min_xray_version: str = ""

    profiles_present: bool = False
    profiles_synced: bool = False
    active_profile: str = "base"

    xray_available: bool = False
    xray_path: str = ""
    xray_owner: str = "none"
    xray_version: str = ""

    listener_status: str = "unknown"
    listener_host: str = ""
    listener_port: int = 10808
    listener_exposure: str = "unknown"
    listener_process_name: str = ""
    listener_process_path: str = ""
    listener_pid: str = ""

    cert_exists: bool = False
    key_exists: bool = False
    cert_key_match: str = "unknown"
    cert_expiry_status: str = "unknown"
    key_permission_status: str = "unknown"

    trust_status: str = "unknown"
    trust_windows_user: str = "unknown"
    trust_windows_machine: str = "unknown"
    trust_browser_status: str = "unknown"

    browser_deps_ok: bool = False
    playwright_ok: bool = False
    cloakbrowser_ok: bool = False
    browser_path: str = ""

    page_check_status: str = "not_run"
    last_page_check_url: str = ""
    last_page_check_result: str = ""

    ja3_validation_status: str = "not_measured"
    ja3_configured: bool = False
    ja3_measured: bool = False
    ja3_oracle_url: str = ""
    ja3_expected: str = ""
    ja3_observed: str = ""

    telemetry_source: str = "system_counters"
    telemetry_confidence: str = "medium"
    network_status: str = "unknown"

    release_ready: bool = False
    release_blockers: List[str] = field(default_factory=list)

    checks: List[CheckResult] = field(default_factory=list)
    repairs: List[RepairAction] = field(default_factory=list)


def hidden_subprocess_kwargs() -> dict[str, object]:
    if os.name != "nt":
        return {}
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = 0
    return {
        "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0),
        "startupinfo": startupinfo,
    }


def run_cmd(cmd: List[str], *, cwd: Path = ROOT, timeout: float = 8.0) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
            **hidden_subprocess_kwargs(),
        )
        return proc.returncode, proc.stdout or ""
    except Exception as exc:  # noqa: BLE001
        return 1, str(exc)


def status_from_checks(checks: Iterable[CheckResult]) -> str:
    statuses = {check.status for check in checks}
    if "fail" in statuses:
        return "fail"
    if "warn" in statuses:
        return "warn"
    if "pass" in statuses:
        return "pass"
    return "info"


def _check(
    check_id: str,
    category: str,
    status: str,
    summary: str,
    *,
    evidence: str = "",
    impact: str = "",
    recommended_action: str = "",
    fix_command: str = "",
    safe_to_auto_fix: bool = False,
    requires_admin: bool = False,
    docs_url_or_path: str = "",
) -> CheckResult:
    return CheckResult(
        id=check_id,
        category=category,
        status=status,
        summary=summary,
        evidence=evidence,
        impact=impact,
        recommended_action=recommended_action,
        fix_command=fix_command,
        safe_to_auto_fix=safe_to_auto_fix,
        requires_admin=requires_admin,
        docs_url_or_path=docs_url_or_path,
    )


def _repair(
    action_id: str,
    label: str,
    description: str,
    *,
    risk: str = "low",
    requires_admin: bool = False,
    changes_files: bool = False,
    changes_system: bool = False,
    reversible: bool = True,
    command: str = "",
    confirmation_required: bool = False,
) -> RepairAction:
    return RepairAction(
        id=action_id,
        label=label,
        description=description,
        risk=risk,
        requires_admin=requires_admin,
        changes_files=changes_files,
        changes_system=changes_system,
        reversible=reversible,
        command=command,
        confirmation_required=confirmation_required,
    )


def load_config(config_path: Path) -> tuple[dict[str, Any] | None, CheckResult]:
    if not config_path.exists():
        return None, _check(
            "config.exists",
            "config",
            "fail",
            "Primary Xray config is missing.",
            evidence=str(config_path),
            impact="Xray cannot be started from the expected runtime config.",
            recommended_action="Regenerate or restore Xray-config/Xray-Cooperative-Overlay.json.",
            fix_command="py -3 scripts\\build_config.py --check-runtime-sync --generate-profiles --check-profile-sync",
            safe_to_auto_fix=True,
        )
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return None, _check(
            "config.json",
            "config",
            "fail",
            "Primary Xray config is not valid JSON.",
            evidence=str(exc),
            impact="Xray and validation tools cannot load the config.",
            recommended_action="Fix JSON syntax or regenerate from config-src.",
        )
    return data, _check(
        "config.json",
        "config",
        "pass",
        "Primary Xray config is present and valid JSON.",
        evidence=str(config_path),
    )


def proxy_port_from_config(config: dict[str, Any] | None) -> int:
    if not isinstance(config, dict):
        return 10808
    for inbound in config.get("inbounds", []) if isinstance(config.get("inbounds"), list) else []:
        if not isinstance(inbound, dict):
            continue
        if inbound.get("tag") == "mixed-in" and isinstance(inbound.get("port"), int):
            return int(inbound["port"])
    return 10808


def config_metadata(config: dict[str, Any] | None) -> tuple[str, str, bool]:
    if not isinstance(config, dict):
        return "", "", False
    remarks = str(config.get("remarks", ""))
    version = config.get("version", {})
    min_version = str(version.get("min", "")) if isinstance(version, dict) else ""
    ja3_configured = False
    for outbound in config.get("outbounds", []) if isinstance(config.get("outbounds"), list) else []:
        if not isinstance(outbound, dict):
            continue
        stream = outbound.get("streamSettings", {})
        tls = stream.get("tlsSettings", {}) if isinstance(stream, dict) else {}
        if isinstance(tls, dict) and tls.get("fingerprint"):
            ja3_configured = True
            break
    return remarks, min_version, ja3_configured


def profile_checks(root: Path) -> tuple[bool, bool, List[CheckResult]]:
    checks: List[CheckResult] = []
    profile_paths = [
        root / "Xray-config" / f"Xray-Cooperative-Overlay.{name}.json"
        for name in PROFILE_NAMES
    ]
    missing = [path.name for path in profile_paths if not path.exists()]
    profiles_present = not missing
    checks.append(
        _check(
            "profiles.present",
            "profiles",
            "pass" if profiles_present else "warn",
            "Generated operating profiles are present." if profiles_present else "Some generated operating profiles are missing.",
            evidence=", ".join(missing) if missing else ", ".join(path.name for path in profile_paths),
            impact="Users may not have strict/balanced/compatibility/debug choices." if missing else "",
            recommended_action="Regenerate profiles from the base config." if missing else "",
            fix_command="py -3 scripts\\generate_profiles.py --base Xray-config\\Xray-Cooperative-Overlay.json" if missing else "",
            safe_to_auto_fix=bool(missing),
        )
    )
    code, output = run_cmd(["git", "diff", "--quiet", "--", "Xray-config/Xray-Cooperative-Overlay.*.json"], timeout=6)
    if code == 0:
        profiles_synced = True
        checks.append(_check("profiles.git_sync", "profiles", "pass", "Generated profiles have no working-tree diff."))
    else:
        profiles_synced = False
        checks.append(
            _check(
                "profiles.git_sync",
                "profiles",
                "warn",
                "Generated profiles may be out of sync or modified.",
                evidence=output.strip(),
                impact="CI profile-sync checks may fail until generated files are refreshed and committed.",
                recommended_action="Regenerate profiles and review the diff.",
                fix_command="py -3 scripts\\generate_profiles.py --base Xray-config\\Xray-Cooperative-Overlay.json",
                safe_to_auto_fix=True,
            )
        )
    return profiles_present, profiles_synced, checks


def find_local_xray(root: Path) -> Path | None:
    candidates = [
        root / "xray" / ("xray.exe" if os.name == "nt" else "xray"),
        root / "Xray-config" / ("xray.exe" if os.name == "nt" else "xray"),
        root / "Xray-config" / "xray" / ("xray.exe" if os.name == "nt" else "xray"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def xray_version(xray_path: Path | None) -> str:
    if xray_path is None:
        return ""
    code, out = run_cmd([str(xray_path), "version"], timeout=5)
    if code != 0:
        return "unknown"
    return (out.splitlines()[0] if out.splitlines() else "unknown").strip()


def listener_lines() -> List[str]:
    if platform.system().lower() == "windows":
        _, out = run_cmd(["netstat", "-ano", "-p", "tcp"], timeout=6)
    else:
        code, out = run_cmd(["ss", "-ltnp"], timeout=6)
        if code != 0 or not out.strip():
            _, out = run_cmd(["netstat", "-an"], timeout=6)
    return [line.strip() for line in out.splitlines() if line.strip()]


def parse_listener_line(line: str, port: int) -> tuple[str, str] | None:
    if f":{port}" not in line and f".{port}" not in line:
        return None
    parts = line.split()
    if not parts:
        return None
    local = ""
    pid = ""
    if platform.system().lower() == "windows" and len(parts) >= 5 and parts[0].upper() == "TCP":
        local = parts[1]
        pid = parts[-1]
    elif len(parts) >= 4:
        local = parts[3] if parts[0].lower().startswith("netid") is False else ""
        pid = parts[-1] if "pid=" in parts[-1] else ""
    if not local:
        return None
    return local, pid


def process_info(pid: str) -> tuple[str, str]:
    if not pid or not pid.isdigit():
        return "", ""
    if platform.system().lower() == "windows":
        code, out = run_cmd(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                f"Get-Process -Id {pid} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName; "
                f"Get-Process -Id {pid} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path",
            ],
            timeout=8,
        )
        if code == 0:
            lines = [line.strip() for line in out.splitlines() if line.strip()]
            return (lines[0] if lines else "", lines[1] if len(lines) > 1 else "")
    return "", ""


def can_connect_loopback(port: int, timeout: float = 0.3) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def listener_state(port: int, root: Path) -> tuple[str, str, str, str, str, str, CheckResult]:
    matches: List[tuple[str, str]] = []
    for line in listener_lines():
        parsed = parse_listener_line(line, port)
        if parsed:
            matches.append(parsed)

    loopback_open = can_connect_loopback(port)
    if not matches and not loopback_open:
        return (
            "closed",
            "",
            "closed",
            "",
            "",
            "",
            _check(
                "listener.closed",
                "runtime",
                "warn",
                f"No local listener is currently accepting 127.0.0.1:{port}.",
                impact="Browser checks cannot use the local proxy until Xray or v2rayN is running.",
                recommended_action="Start app Xray core or open the external client that owns the profile.",
                fix_command="py -3 main.py gui",
            ),
        )

    bad = []
    good = []
    ambiguous = []
    pid = ""
    host = ""
    for local, item_pid in matches:
        normalized = local.replace("[::]", "::")
        host_part = normalized.rsplit(":", 1)[0] if ":" in normalized else normalized.rsplit(".", 1)[0]
        if "0.0.0.0" in normalized or normalized.startswith(":::") or normalized.startswith("::"):
            bad.append(local)
        elif "127.0.0.1" in normalized or "localhost" in normalized or "::1" in normalized:
            good.append(local)
        else:
            ambiguous.append(local)
        if not pid and item_pid:
            pid = item_pid
        if not host and host_part:
            host = host_part

    process_name, process_path = process_info(pid)
    owner = "external"
    if process_path:
        try:
            Path(process_path).resolve().relative_to(root.resolve())
            owner = "app"
        except Exception:
            owner = "external"

    if bad:
        return (
            "open",
            host or bad[0],
            "exposed",
            process_name,
            process_path,
            pid,
            _check(
                "listener.exposed",
                "runtime",
                "fail",
                f"Runtime listener is exposed on non-loopback address for port {port}.",
                evidence=" | ".join(bad[:3]) + (f" pid={pid} {process_path}" if pid else ""),
                impact="The local proxy may be reachable from other network interfaces.",
                recommended_action="Configure the external Xray/v2rayN inbound listen address to 127.0.0.1.",
                docs_url_or_path="docs/listener-binding.md",
            ),
        )
    if good or loopback_open:
        return (
            "open",
            host or "127.0.0.1",
            "loopback",
            process_name,
            process_path,
            pid,
            _check(
                "listener.loopback",
                "runtime",
                "pass",
                f"Runtime listener is reachable on 127.0.0.1:{port}.",
                evidence=" | ".join(good[:3]) if good else "loopback TCP connect succeeded",
            ),
        )
    return (
        "open",
        host or (ambiguous[0] if ambiguous else ""),
        "unknown",
        process_name,
        process_path,
        pid,
        _check(
            "listener.ambiguous",
            "runtime",
            "warn",
            f"Listener for port {port} was observed, but binding could not be classified.",
            evidence=" | ".join(ambiguous[:3]),
            recommended_action="Verify listener binding manually with netstat/ss.",
            docs_url_or_path="docs/listener-binding.md",
        ),
    )


def cert_state(cert: Path, key: Path) -> tuple[str, str, str, List[CheckResult]]:
    checks: List[CheckResult] = []
    cert_exists = cert.exists()
    key_exists = key.exists()
    checks.append(
        _check(
            "cert.exists",
            "certificate",
            "pass" if cert_exists else "warn",
            "Local CA certificate exists." if cert_exists else "Local CA certificate is missing.",
            evidence=str(cert),
            recommended_action="Generate local CA files." if not cert_exists else "",
            fix_command="py -3 scripts\\mitm_trust.py generate --out-dir Xray-config" if not cert_exists else "",
            safe_to_auto_fix=not cert_exists,
        )
    )
    checks.append(
        _check(
            "key.exists",
            "certificate",
            "pass" if key_exists else "warn",
            "Local CA private key exists." if key_exists else "Local CA private key is missing.",
            evidence=str(key),
            impact="MITM certificate generation cannot work without the matching private key." if not key_exists else "",
            recommended_action="Generate local CA files." if not key_exists else "",
            fix_command="py -3 scripts\\mitm_trust.py generate --out-dir Xray-config" if not key_exists else "",
            safe_to_auto_fix=not key_exists,
        )
    )

    match_status = "unknown"
    expiry_status = "unknown"
    key_permission_status = "unknown"
    try:
        import mitm_trust  # type: ignore

        match = mitm_trust.cert_key_match(cert, key)
        if match is True:
            match_status = "match"
            checks.append(_check("cert.key_match", "certificate", "pass", "Certificate and private key match."))
        elif match is False:
            match_status = "mismatch"
            checks.append(
                _check(
                    "cert.key_match",
                    "certificate",
                    "fail",
                    "Certificate and private key do not match.",
                    impact="Browser MITM will fail or generate invalid leaf certificates.",
                    recommended_action="Regenerate the local CA pair.",
                    fix_command="py -3 scripts\\mitm_trust.py generate --out-dir Xray-config --force",
                    safe_to_auto_fix=False,
                )
            )
        else:
            checks.append(_check("cert.key_match", "certificate", "info", "Certificate/key match could not be verified."))

        end_date = mitm_trust.cert_end_date(cert)
        if end_date is None:
            expiry_status = "unknown"
            checks.append(_check("cert.expiry", "certificate", "info", "Certificate expiry could not be parsed."))
        else:
            days = int((end_date - datetime.now(timezone.utc)).total_seconds() // 86400)
            if days < 0:
                expiry_status = "expired"
                status = "fail"
                summary = "Local CA certificate is expired."
            elif days < 30:
                expiry_status = "expires_soon"
                status = "warn"
                summary = "Local CA certificate expires soon."
            else:
                expiry_status = "valid"
                status = "pass"
                summary = "Local CA certificate is within its validity window."
            checks.append(_check("cert.expiry", "certificate", status, summary, evidence=f"days_remaining={days}"))

        key_ok = mitm_trust.key_permissions_ok(key)
        if key_ok is True:
            key_permission_status = "restricted"
            checks.append(_check("key.permissions", "certificate", "pass", "Private key permissions do not appear broad."))
        elif key_ok is False:
            key_permission_status = "broad"
            checks.append(
                _check(
                    "key.permissions",
                    "certificate",
                    "warn",
                    "Private key permissions appear broad or key is missing.",
                    impact="The local CA private key should be readable only by the current user.",
                    recommended_action="Restrict permissions on Xray-config/mycert.key.",
                    requires_admin=False,
                )
            )
        else:
            checks.append(_check("key.permissions", "certificate", "info", "Private key permissions could not be classified."))
    except Exception as exc:  # noqa: BLE001
        checks.append(_check("cert.helpers", "certificate", "info", f"Certificate helper checks unavailable: {exc}"))
    return match_status, expiry_status, key_permission_status, checks


def trust_state(cert: Path, *, skip_trust: bool) -> tuple[str, str, str, str, List[CheckResult]]:
    if skip_trust:
        return "skipped", "skipped", "skipped", "unknown", [
            _check("trust.skipped", "trust", "info", "Trust-store check skipped.")
        ]
    try:
        from trust_store_check import build_report  # type: ignore

        report = build_report(cert)
    except Exception as exc:  # noqa: BLE001
        return "unknown", "unknown", "unknown", "unknown", [
            _check("trust.status", "trust", "info", f"Trust-store check unavailable: {exc}")
        ]

    status = str(report.get("status", "unknown"))
    user = "unknown"
    machine = "unknown"
    for item in report.get("store_checks", []) if isinstance(report.get("store_checks"), list) else []:
        if not isinstance(item, dict):
            continue
        store = str(item.get("store", ""))
        item_status = str(item.get("status", "unknown"))
        if "CurrentUser" in store:
            user = item_status
        if "LocalMachine" in store:
            machine = item_status
    check_status = "pass" if status in {"pass", "not_supported"} else "warn"
    return status, user, machine, "unknown", [
        _check(
            "trust.status",
            "trust",
            check_status,
            f"Trust-store status is {status}.",
            evidence=f"CurrentUser={user}; LocalMachine={machine}",
            impact="Browser MITM tests may rely on ignore_https_errors until the CA is trusted." if check_status == "warn" else "",
            recommended_action="Install mycert.crt into the intended OS/browser trust store." if check_status == "warn" else "",
            requires_admin=(machine != "pass" and platform.system().lower() == "windows"),
            docs_url_or_path="docs/ca-install-guide.md",
        )
    ]


def browser_state(root: Path) -> tuple[bool, bool, bool, str, List[CheckResult]]:
    playwright_ok = importlib.util.find_spec("playwright") is not None
    cloakbrowser_ok = importlib.util.find_spec("cloakbrowser") is not None
    browser_path = ""
    try:
        from browser_common import find_windows_chrome  # type: ignore

        found = find_windows_chrome()
        browser_path = found or ""
    except Exception:
        browser_path = ""
    scripts_ok = (root / "scripts" / "browser_diagnostics.py").exists() and (root / "scripts" / "browser_stealth.py").exists()
    browser_deps_ok = playwright_ok and scripts_ok
    checks = [
        _check(
            "browser.diagnostics",
            "browser",
            "pass" if playwright_ok else "warn",
            "Playwright diagnostics dependency is available." if playwright_ok else "Playwright diagnostics dependency is missing.",
            recommended_action="Install page-check tools." if not playwright_ok else "",
            fix_command="py -3 -m pip install -r requirements-browser-diagnostics.txt && py -3 -m playwright install chromium" if not playwright_ok else "",
            safe_to_auto_fix=not playwright_ok,
        ),
        _check(
            "browser.cloakbrowser",
            "browser",
            "pass" if cloakbrowser_ok else "info",
            "CloakBrowser dependency is available." if cloakbrowser_ok else "CloakBrowser dependency is not installed.",
            recommended_action="Install fingerprint tools only if you need the advanced fingerprint check." if not cloakbrowser_ok else "",
            fix_command="py -3 -m pip install -r requirements-browser-stealth.txt && py -3 -m cloakbrowser install" if not cloakbrowser_ok else "",
            safe_to_auto_fix=not cloakbrowser_ok,
        ),
        _check(
            "browser.executable",
            "browser",
            "pass" if browser_path else "info",
            "System Chromium browser was detected." if browser_path else "No system Chrome/Edge path was detected; bundled Playwright may still work.",
            evidence=browser_path,
        ),
    ]
    return browser_deps_ok, playwright_ok, cloakbrowser_ok, browser_path, checks


def build_repairs(state: ProjectState) -> List[RepairAction]:
    repairs: List[RepairAction] = []
    if not state.config_ok or not state.profiles_present or not state.profiles_synced:
        repairs.append(
            _repair(
                "repair.config_profiles",
                "Repair generated config/profile files",
                "Regenerate compiled config and operating profiles from config-src.",
                changes_files=True,
                command="py -3 scripts\\build_config.py --check-runtime-sync --generate-profiles --check-profile-sync",
            )
        )
    if not state.cert_exists or not state.key_exists or state.cert_key_match == "mismatch":
        repairs.append(
            _repair(
                "repair.local_ca",
                "Generate local CA",
                "Create or replace local mycert.crt/mycert.key files. Trust installation remains manual.",
                risk="medium",
                changes_files=True,
                command="py -3 scripts\\mitm_trust.py generate --out-dir Xray-config",
                confirmation_required=state.cert_exists or state.key_exists,
            )
        )
    if state.key_permission_status == "broad":
        repairs.append(
            _repair(
                "repair.key_permissions",
                "Restrict private key permissions",
                "Limit Xray-config/mycert.key access to the current user.",
                risk="medium",
                changes_system=True,
                command="Review ACL/permissions for Xray-config\\mycert.key",
                confirmation_required=True,
            )
        )
    if not state.xray_available:
        repairs.append(
            _repair(
                "repair.download_xray",
                "Download Xray Core",
                "Download local Xray runtime and geodata into xray/.",
                changes_files=True,
                command="py -3 scripts\\install_xray.py --out-dir xray",
            )
        )
    if state.listener_exposure == "exposed":
        repairs.append(
            _repair(
                "repair.listener_binding",
                "Fix exposed listener",
                "Configure the external Xray/v2rayN inbound to listen on 127.0.0.1 only.",
                risk="medium",
                changes_system=True,
                reversible=True,
                command="See docs/listener-binding.md",
                confirmation_required=True,
            )
        )
    if state.trust_status not in {"pass", "not_supported", "skipped"}:
        repairs.append(
            _repair(
                "repair.trust_ca",
                "Trust local CA manually",
                "Install Xray-config/mycert.crt in the intended OS or browser trust store.",
                risk="medium",
                requires_admin=True,
                changes_system=True,
                command="py -3 scripts\\trust_assistant.py --cert Xray-config\\mycert.crt",
                confirmation_required=True,
            )
        )
    if not state.playwright_ok:
        repairs.append(
            _repair(
                "repair.playwright",
                "Install page-check tools",
                "Install Playwright and Chromium for the stock browser page check.",
                changes_files=True,
                command="py -3 -m pip install -r requirements-browser-diagnostics.txt && py -3 -m playwright install chromium",
            )
        )
    if not state.cloakbrowser_ok:
        repairs.append(
            _repair(
                "repair.cloakbrowser",
                "Install fingerprint tools",
                "Install CloakBrowser for the optional advanced fingerprint check.",
                changes_files=True,
                command="py -3 -m pip install -r requirements-browser-stealth.txt && py -3 -m cloakbrowser install",
            )
        )
    return repairs


def derive_next_action(state: ProjectState) -> tuple[str, str]:
    if not state.config_ok:
        return "Repair Config", "Primary config is missing or invalid."
    if not state.profiles_present or not state.profiles_synced:
        return "Regenerate Profiles", "Generated profile files need attention."
    if not state.cert_exists or not state.key_exists:
        return "Generate Local CA", "Certificate and key are required before browser MITM testing."
    if state.cert_key_match == "mismatch":
        return "Regenerate Local CA", "Certificate and private key do not match."
    if not state.xray_available:
        return "Download Xray Core", "The bundled local runtime is missing."
    if state.listener_exposure == "exposed":
        return "Fix Exposed Listener", "The active local proxy is not loopback-only."
    if state.listener_status == "closed":
        return "Start Core", "No local proxy listener is currently active."
    if state.key_permission_status == "broad":
        return "Restrict Private Key", "The local CA private key permissions appear broader than recommended."
    if state.trust_status not in {"pass", "not_supported", "skipped"}:
        return "Trust Certificate", "The local CA is not matched in the target trust store."
    if not state.playwright_ok:
        return "Install Page Check Tools", "Playwright is needed for the stock browser page check."
    if state.page_check_status != "pass":
        return "Run Page Check", "Verify a stock browser can load a page through the local proxy."
    if state.cloakbrowser_ok and state.ja3_validation_status == "not_measured":
        return "Optional JA3 Validation", "Run a JA3 oracle check only if fingerprint evidence is needed."
    try:
        from core.intelligent_advisor import load_decision_labels

        labels = load_decision_labels(Path(state.root) if state.root else root)
        if labels:
            return (
                "Review Advisor",
                f"Decision report labels: {', '.join(labels[:4])}. Run: py -3 main.py advise --text",
            )
    except Exception:
        pass
    return "Ready", "Core setup is ready for normal browser proxy testing."


def build_project_state(
    *,
    root: Path = ROOT,
    config_path: Path | None = None,
    cert_path: Path | None = None,
    key_path: Path | None = None,
    skip_trust: bool = False,
    skip_runtime: bool = False,
) -> ProjectState:
    config_path = config_path or root / "Xray-config" / "Xray-Cooperative-Overlay.json"
    cert_path = cert_path or root / "Xray-config" / "mycert.crt"
    key_path = key_path or root / "Xray-config" / "mycert.key"
    checks: List[CheckResult] = []

    config, config_check = load_config(config_path)
    checks.append(config_check)
    remarks, min_xray, ja3_configured = config_metadata(config)
    port = proxy_port_from_config(config)

    profiles_present, profiles_synced, profile_result = profile_checks(root)
    checks.extend(profile_result)

    xray_path = find_local_xray(root)
    xray_available = xray_path is not None
    checks.append(
        _check(
            "xray.available",
            "runtime",
            "pass" if xray_available else "warn",
            "Bundled Xray runtime is available." if xray_available else "Bundled Xray runtime is missing.",
            evidence=str(xray_path or ""),
            recommended_action="Download Xray Core or use an external client." if not xray_available else "",
            fix_command="py -3 scripts\\install_xray.py --out-dir xray" if not xray_available else "",
            safe_to_auto_fix=not xray_available,
        )
    )
    version = xray_version(xray_path)

    if skip_runtime:
        listener_status, listener_host, listener_exposure = "skipped", "", "unknown"
        process_name = process_path = pid = ""
        checks.append(_check("listener.skipped", "runtime", "info", "Runtime listener check skipped."))
    else:
        listener_status, listener_host, listener_exposure, process_name, process_path, pid, listener_check = listener_state(port, root)
        checks.append(listener_check)

    match_status, expiry_status, permission_status, cert_result = cert_state(cert_path, key_path)
    checks.extend(cert_result)

    trust_status, trust_user, trust_machine, trust_browser, trust_result = trust_state(cert_path, skip_trust=skip_trust)
    checks.extend(trust_result)

    browser_deps_ok, playwright_ok, cloakbrowser_ok, browser_path, browser_result = browser_state(root)
    checks.extend(browser_result)

    ja3_evidence = load_evidence(root / ".local-state" / "ja3-evidence.json")
    ja3_measured = bool(ja3_evidence and ja3_evidence.measured)
    ja3_validation_status = ja3_evidence.validation_status if ja3_evidence else "not_measured"
    ja3_oracle_url = ja3_evidence.oracle_url if ja3_evidence else ""
    ja3_expected = ja3_evidence.expected_ja3 if ja3_evidence else ""
    ja3_observed = ja3_evidence.observed_ja3 if ja3_evidence else ""
    if ja3_measured:
        checks.append(
            _check(
                "ja3.measured",
                "fingerprint",
                "pass" if ja3_validation_status == "match" else "warn" if ja3_validation_status == "measured" else "warn",
                "JA3 oracle measurement is on file."
                if ja3_validation_status != "mismatch"
                else "JA3 oracle measurement mismatched the configured expectation.",
                evidence=f"observed={ja3_observed or 'unknown'} expected={ja3_expected or 'none'}",
            )
        )
    elif ja3_configured:
        checks.append(
            _check(
                "ja3.configured_only",
                "fingerprint",
                "info",
                "TLS fingerprint is configured in Xray; wire measurement requires an opt-in JA3 oracle run.",
                evidence="configured=yes measured=no",
            )
        )

    checks.append(
        _check(
            "telemetry.source",
            "telemetry",
            "info",
            "Network telemetry source is system counters unless a later probe provides narrower evidence.",
            evidence="source=system_counters; scope=whole_system; confidence=medium",
        )
    )

    overall = status_from_checks(checks)
    release_blockers = [check.id for check in checks if check.status in {"fail", "warn"}]
    state = ProjectState(
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        root=str(root),
        overall=overall,
        next_action="",
        next_action_detail="",
        config_ok=config_check.status == "pass",
        config_path=str(config_path),
        config_remarks=remarks,
        config_min_xray_version=min_xray,
        profiles_present=profiles_present,
        profiles_synced=profiles_synced,
        xray_available=xray_available,
        xray_path=str(xray_path or ""),
        xray_owner="app" if process_path and _is_under_root(process_path, root) else "external" if listener_status == "open" else "none",
        xray_version=version,
        listener_status=listener_status,
        listener_host=listener_host,
        listener_port=port,
        listener_exposure=listener_exposure,
        listener_process_name=process_name,
        listener_process_path=process_path,
        listener_pid=pid,
        cert_exists=cert_path.exists(),
        key_exists=key_path.exists(),
        cert_key_match=match_status,
        cert_expiry_status=expiry_status,
        key_permission_status=permission_status,
        trust_status=trust_status,
        trust_windows_user=trust_user,
        trust_windows_machine=trust_machine,
        trust_browser_status=trust_browser,
        browser_deps_ok=browser_deps_ok,
        playwright_ok=playwright_ok,
        cloakbrowser_ok=cloakbrowser_ok,
        browser_path=browser_path,
        ja3_validation_status=ja3_validation_status,
        ja3_configured=ja3_configured,
        ja3_measured=ja3_measured,
        ja3_oracle_url=ja3_oracle_url,
        ja3_expected=ja3_expected,
        ja3_observed=ja3_observed,
        network_status="unknown",
        release_ready=overall == "pass" and not release_blockers,
        release_blockers=release_blockers,
        checks=checks,
    )
    state.repairs = build_repairs(state)
    state.next_action, state.next_action_detail = derive_next_action(state)
    return state


def _is_under_root(path: str, root: Path) -> bool:
    try:
        Path(path).resolve().relative_to(root.resolve())
        return True
    except Exception:
        return False


def state_to_dict(state: ProjectState) -> dict[str, Any]:
    return asdict(state)


def emit_json(state: ProjectState) -> str:
    payload = state_to_dict(state)
    try:
        from core.intelligent_advisor import build_advisor_plan

        payload["intelligent"] = build_advisor_plan(
            root=Path(state.root) if state.root else ROOT,
            state=state,
        )
    except Exception as exc:  # noqa: BLE001
        payload["intelligent"] = {"error": str(exc)}
    return json.dumps(payload, indent=2, ensure_ascii=False)


def emit_text(state: ProjectState) -> str:
    lines = [
        "Xray-Cooperative-Overlay Readiness",
        "=" * 72,
        f"Overall: {state.overall}",
        f"Next action: {state.next_action}",
        f"Why: {state.next_action_detail}",
        "",
        "State:",
        f"  Config: {'ready' if state.config_ok else 'needs attention'} ({state.config_path})",
        f"  Profiles: {'ready' if state.profiles_present and state.profiles_synced else 'needs attention'}",
        f"  Xray: {'available' if state.xray_available else 'missing'} {state.xray_path}",
        f"  Listener: {state.listener_status} / {state.listener_exposure} on {state.listener_host or '?'}:{state.listener_port}",
        f"  Certificate: cert={'yes' if state.cert_exists else 'no'} key={'yes' if state.key_exists else 'no'} match={state.cert_key_match}",
        f"  Trust: {state.trust_status}",
        f"  Browser deps: playwright={'yes' if state.playwright_ok else 'no'} cloakbrowser={'yes' if state.cloakbrowser_ok else 'no'}",
        f"  TLS fingerprint: configured={'yes' if state.ja3_configured else 'no'} measured={'yes' if state.ja3_measured else 'no'}",
        "",
        "Checks:",
    ]
    for check in sorted(state.checks, key=lambda item: (-STATUS_ORDER.get(item.status, 0), item.category, item.id)):
        lines.append(f"  [{check.status.upper():4}] {check.id}: {check.summary}")
        if check.evidence and check.status in {"fail", "warn"}:
            lines.append(f"        evidence: {check.evidence}")
        if check.recommended_action and check.status in {"fail", "warn"}:
            lines.append(f"        action: {check.recommended_action}")
    if state.repairs:
        lines.extend(["", "Suggested repair actions:"])
        for action in state.repairs:
            lines.append(f"  - {action.label}: {action.command or action.description}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Emit shared Xray-Cooperative-Overlay readiness state")
    parser.add_argument("--config", type=Path, default=ROOT / "Xray-config" / "Xray-Cooperative-Overlay.json")
    parser.add_argument("--cert", type=Path, default=ROOT / "Xray-config" / "mycert.crt")
    parser.add_argument("--key", type=Path, default=ROOT / "Xray-config" / "mycert.key")
    parser.add_argument("--skip-trust", action="store_true")
    parser.add_argument("--skip-runtime", action="store_true")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of the compact text view")
    args = parser.parse_args(argv)
    state = build_project_state(
        root=ROOT,
        config_path=args.config,
        cert_path=args.cert,
        key_path=args.key,
        skip_trust=args.skip_trust,
        skip_runtime=args.skip_runtime,
    )
    print(emit_json(state) if args.json or not sys.stdout.isatty() else emit_text(state))
    return 2 if state.overall == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
