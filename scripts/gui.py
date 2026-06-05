#!/usr/bin/env python3
"""Local desktop GUI for Xray-Cooperative-Overlay maintenance and diagnostics."""
from __future__ import annotations

import argparse
import csv
import queue
import re
import datetime as dt
import json
import os
import platform
import runpy
import socket
import subprocess
import sys
import threading
import time
import traceback
import webbrowser
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core.gui_preferences import GuiPreferences, load_preferences, save_preferences
from core.gui_readiness import GuiReadinessCache, primary_action_spec, readiness_snapshot_fields
from core.key_at_rest import ensure_key_material_available
from core.preflight_gate import blocker_messages, evaluate_startup_gate, load_cached_preflight
from core.process_supervisor import ProcessSupervisor
from core.strategy_profiles import recommend_profile
from core.trust_broker import launch_session_with_cdp_assist, prepare_chromium_session, session_manifest
from core.version_utils import version_at_least

IS_FROZEN = bool(getattr(sys, "frozen", False))
ROOT = Path(sys.executable).resolve().parent if IS_FROZEN else Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
CONFIG = ROOT / "Xray-config" / "Xray-Cooperative-Overlay.json"
CERT = ROOT / "Xray-config" / "mycert.crt"
KEY = ROOT / "Xray-config" / "mycert.key"
BROWSER_CONFIG = ROOT / "configs" / "browser-integration.json"
APP_ICON_PNG = ROOT / "assets" / "app-icon.png"
APP_ICON_ICO = ROOT / "assets" / "app-icon.ico"
LOCAL_STATE = ROOT / ".local-state"
GUI_TELEMETRY = LOCAL_STATE / "gui-telemetry.jsonl"
CLOAKBROWSER_URL = "https://github.com/CloakHQ/CloakBrowser"
XRAY_RELEASES_URL = "https://github.com/XTLS/Xray-core/releases"
APP_VERSION = "v1.0"
STATUS_REFRESH_MS = 3500
NETWORK_REFRESH_MS = 7000
HOST_PYTHON_CACHE_SECONDS = 45.0
_HOST_PYTHON_CACHE: tuple[float, list[str] | None] = (0.0, None)
XRAY_VERSION_CACHE_SECONDS = 60.0
_XRAY_VERSION_CACHE: tuple[float, Path | None, str] = (0.0, None, "Unknown")

# Design system (v1.3.2 visual refresh)
COLORS = {
    "bg": "#eef2f8",
    "panel": "#ffffff",
    "panel_alt": "#f6f8fc",
    "panel_soft": "#eef2f8",
    "ink": "#101828",
    "ink_soft": "#344054",
    "muted": "#667085",
    "muted_soft": "#98a2b3",
    "line": "#e4e9f2",
    "line_strong": "#d3dbe8",
    "shadow": "#dbe2ee",
    "blue": "#2563eb",
    "blue_dark": "#1d4ed8",
    "blue_soft": "#eaf1ff",
    "blue_ring": "#bcd2ff",
    "violet": "#6d4ce0",
    "violet_soft": "#f0ecfe",
    "cyan": "#0ea5b7",
    "green": "#15a36a",
    "green_soft": "#e6f7ef",
    "amber": "#b45309",
    "amber_soft": "#fef6e7",
    "red": "#d92d20",
    "red_soft": "#fdeceb",
    "sidebar": "#ffffff",
    "sidebar_active": "#eaf1ff",
    "sidebar_hover": "#f4f7fc",
    "sidebar_line": "#e8edf5",
    "rail": "#f7f9fd",
}


def hidden_subprocess_kwargs() -> dict[str, object]:
    """Keep child helper processes from opening console windows in the GUI build."""
    if os.name != "nt":
        return {}
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = 0
    return {"creationflags": flags, "startupinfo": startupinfo}


def _parse_int(value: str) -> int:
    return int(re.sub(r"[^0-9]", "", value) or "0")


def system_network_totals() -> tuple[int, int, str] | None:
    """Return cumulative received/sent bytes for visible system interfaces."""
    if os.name == "nt":
        native = windows_network_totals()
        if native is not None:
            return native
        try:
            proc = subprocess.run(
                ["netstat", "-e"],
                cwd=str(ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=4,
                check=False,
                **hidden_subprocess_kwargs(),
            )
        except Exception:
            return None
        if proc.returncode != 0:
            return None
        for line in proc.stdout.splitlines():
            if line.strip().lower().startswith("bytes"):
                values = re.findall(r"[\d,]+", line)
                if len(values) >= 2:
                    return _parse_int(values[0]), _parse_int(values[1]), "netstat -e"
        return None
    proc_net = Path("/proc/net/dev")
    if proc_net.exists():
        rx_total = 0
        tx_total = 0
        try:
            for line in proc_net.read_text(encoding="utf-8").splitlines()[2:]:
                if ":" not in line:
                    continue
                name, payload = line.split(":", 1)
                if name.strip() == "lo":
                    continue
                fields = payload.split()
                if len(fields) >= 16:
                    rx_total += int(fields[0])
                    tx_total += int(fields[8])
        except Exception:
            return None
        return rx_total, tx_total, "/proc/net/dev"
    return None


def windows_network_totals() -> tuple[int, int, str] | None:
    try:
        import ctypes
        from ctypes import wintypes

        class MibIfRow(ctypes.Structure):
            _fields_ = [
                ("wszName", wintypes.WCHAR * 256),
                ("dwIndex", wintypes.DWORD),
                ("dwType", wintypes.DWORD),
                ("dwMtu", wintypes.DWORD),
                ("dwSpeed", wintypes.DWORD),
                ("dwPhysAddrLen", wintypes.DWORD),
                ("bPhysAddr", ctypes.c_ubyte * 8),
                ("dwAdminStatus", wintypes.DWORD),
                ("dwOperStatus", wintypes.DWORD),
                ("dwLastChange", wintypes.DWORD),
                ("dwInOctets", wintypes.DWORD),
                ("dwInUcastPkts", wintypes.DWORD),
                ("dwInNUcastPkts", wintypes.DWORD),
                ("dwInDiscards", wintypes.DWORD),
                ("dwInErrors", wintypes.DWORD),
                ("dwInUnknownProtos", wintypes.DWORD),
                ("dwOutOctets", wintypes.DWORD),
                ("dwOutUcastPkts", wintypes.DWORD),
                ("dwOutNUcastPkts", wintypes.DWORD),
                ("dwOutDiscards", wintypes.DWORD),
                ("dwOutErrors", wintypes.DWORD),
                ("dwOutQLen", wintypes.DWORD),
                ("dwDescrLen", wintypes.DWORD),
                ("bDescr", ctypes.c_ubyte * 256),
            ]

        iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
        get_if_table = iphlpapi.GetIfTable
        get_if_table.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.ULONG), wintypes.BOOL]
        get_if_table.restype = wintypes.DWORD
        size = wintypes.ULONG(0)
        insufficient_buffer = 122
        result = get_if_table(None, ctypes.byref(size), False)
        if result != insufficient_buffer or size.value <= ctypes.sizeof(wintypes.DWORD):
            return None
        buffer = ctypes.create_string_buffer(size.value)
        result = get_if_table(buffer, ctypes.byref(size), False)
        if result != 0:
            return None
        count = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
        row_offset = ctypes.sizeof(wintypes.DWORD)
        rx_total = 0
        tx_total = 0
        loopback_type = 24
        for index in range(count):
            row = MibIfRow.from_buffer_copy(buffer, row_offset + index * ctypes.sizeof(MibIfRow))
            if row.dwType == loopback_type:
                continue
            rx_total += int(row.dwInOctets)
            tx_total += int(row.dwOutOctets)
        return rx_total, tx_total, "Windows IP Helper"
    except Exception:
        return None


def format_bytes(value: int) -> str:
    units = ("B", "KB", "MB", "GB", "TB")
    amount = float(max(0, value))
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(amount)} {unit}"
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{amount:.1f} TB"


def format_rate(bytes_per_second: float) -> str:
    return f"{format_bytes(int(max(0.0, bytes_per_second)))}/s"


def format_duration(seconds: float | None) -> str:
    if seconds is None or seconds < 1:
        return "0s"
    total = int(seconds)
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


@dataclass(frozen=True)
class CommandSpec:
    label: str
    description: str
    args: tuple[str, ...]


@dataclass(frozen=True)
class PaletteItem:
    label: str
    group: str
    detail: str
    action: Callable[[], None]


def find_host_python(*, force: bool = False) -> list[str] | None:
    global _HOST_PYTHON_CACHE
    cached_at, cached_value = _HOST_PYTHON_CACHE
    if not force and time.monotonic() - cached_at < HOST_PYTHON_CACHE_SECONDS:
        return cached_value
    candidates: list[list[str]] = []
    env_python = os.environ.get("PYTHON", "").strip()
    if env_python:
        candidates.append([env_python])
    if os.name == "nt":
        candidates.extend([["py", "-3"], ["py"]])
    candidates.append(["python"])
    if not IS_FROZEN:
        candidates.insert(0, [sys.executable])
    for candidate in candidates:
        try:
            proc = subprocess.run(
                [*candidate, "-c", "import sys; print(sys.executable)"],
                cwd=str(ROOT),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=8,
                check=False,
                **hidden_subprocess_kwargs(),
            )
        except Exception:
            continue
        if proc.returncode == 0:
            _HOST_PYTHON_CACHE = (time.monotonic(), candidate)
            return candidate
    _HOST_PYTHON_CACHE = (time.monotonic(), None)
    return None


def find_local_xray() -> Path | None:
    candidates = [
        ROOT / "xray" / "xray.exe",
        ROOT / "xray" / "xray",
        ROOT / "Xray-config" / "xray.exe",
        ROOT / "Xray-config" / "xray",
        ROOT / "Xray-config" / "xray" / "xray.exe",
        ROOT / "Xray-config" / "xray" / "xray",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def xray_runtime_status() -> dict[str, object]:
    executable = find_local_xray()
    runtime_dir = executable.parent if executable is not None else ROOT / "xray"
    geoip = runtime_dir / "geoip.dat"
    geosite = runtime_dir / "geosite.dat"
    return {
        "ready": bool(executable and geoip.exists() and geosite.exists()),
        "executable": executable,
        "runtime_dir": runtime_dir,
        "geoip": geoip,
        "geosite": geosite,
        "geoip_exists": geoip.exists(),
        "geosite_exists": geosite.exists(),
    }


def xray_core_version(executable: Path | None) -> str:
    global _XRAY_VERSION_CACHE
    if executable is None:
        return "Not installed"
    now = time.monotonic()
    cached_at, cached_path, cached_value = _XRAY_VERSION_CACHE
    if cached_path == executable and now - cached_at < XRAY_VERSION_CACHE_SECONDS:
        return cached_value
    version = "Installed"
    try:
        proc = subprocess.run(
            [str(executable), "version"],
            cwd=str(ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=5,
            check=False,
            **hidden_subprocess_kwargs(),
        )
        first_line = (proc.stdout or "").splitlines()[0].strip()
        match = re.search(r"Xray\s+([^\s]+)", first_line)
        version = match.group(1) if match else first_line or version
    except Exception:
        version = "Installed"
    _XRAY_VERSION_CACHE = (now, executable, version)
    return version


def config_proxy_endpoint(config_path: Path = CONFIG) -> dict[str, object]:
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception:
        return {"listen": "127.0.0.1", "port": 10808, "protocol": "mixed", "tag": "mixed-in"}
    inbounds = data.get("inbounds", [])
    if not isinstance(inbounds, list):
        return {"listen": "127.0.0.1", "port": 10808, "protocol": "mixed", "tag": "mixed-in"}
    preferred: dict[str, object] | None = None
    fallback: dict[str, object] | None = None
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        protocol = str(inbound.get("protocol", "")).lower()
        tag = str(inbound.get("tag", ""))
        port = inbound.get("port")
        if protocol not in {"mixed", "socks", "http"} or not isinstance(port, int):
            continue
        settings = inbound.get("settings")
        settings_ip = settings.get("ip") if isinstance(settings, dict) else ""
        item = {
            "listen": str(inbound.get("listen") or settings_ip or "127.0.0.1"),
            "port": port,
            "protocol": protocol,
            "tag": tag or protocol,
        }
        if tag == "mixed-in" or port == 10808:
            preferred = item
            break
        fallback = fallback or item
    return preferred or fallback or {"listen": "127.0.0.1", "port": 10808, "protocol": "mixed", "tag": "mixed-in"}


def config_has_tun(config_path: Path = CONFIG) -> bool:
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception:
        return False
    inbounds = data.get("inbounds", [])
    if not isinstance(inbounds, list):
        return False
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            continue
        protocol = str(inbound.get("protocol", "")).lower()
        tag = str(inbound.get("tag", "")).lower()
        if protocol == "tun" or "tun" in tag:
            return True
    return False


def browser_proxy_host(listen: object) -> str:
    host = str(listen or "127.0.0.1")
    return "127.0.0.1" if host in {"0.0.0.0", "::", "[::]"} else host


def system_proxy_status() -> dict[str, str]:
    if os.name == "nt":
        try:
            import winreg

            key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                enabled = bool(winreg.QueryValueEx(key, "ProxyEnable")[0])
                try:
                    server = str(winreg.QueryValueEx(key, "ProxyServer")[0])
                except OSError:
                    server = ""
                try:
                    pac = str(winreg.QueryValueEx(key, "AutoConfigURL")[0])
                except OSError:
                    pac = ""
            if enabled:
                return {"status": "Enabled", "detail": server or "Manual system proxy is enabled.", "level": "warn"}
            if pac:
                return {"status": "PAC", "detail": pac, "level": "warn"}
            return {"status": "Off", "detail": "Windows system proxy is not forced by this app.", "level": "pass"}
        except Exception:
            return {"status": "Unknown", "detail": "Could not read Windows proxy settings.", "level": "info"}
    env_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or os.environ.get("ALL_PROXY")
    if env_proxy:
        return {"status": "Env proxy", "detail": env_proxy, "level": "warn"}
    return {"status": "Off", "detail": "No common proxy environment variable is set.", "level": "pass"}


def port_accepts_loopback(port: int, timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def _windows_pid_name(pid: str) -> str:
    if not pid:
        return ""
    try:
        proc = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            cwd=str(ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=4,
            check=False,
            **hidden_subprocess_kwargs(),
        )
    except Exception:
        return ""
    if proc.returncode != 0:
        return ""
    for row in csv.reader(proc.stdout.splitlines()):
        if row and row[0].strip().upper() != "INFO:":
            return row[0].strip()
    return ""


def listener_process_info(port: int = 10808) -> dict[str, str]:
    """Best-effort process details for a local core listener."""
    if os.name != "nt":
        return {"pid": "", "name": "", "endpoint": ""}
    try:
        proc = subprocess.run(
            ["netstat", "-ano", "-p", "tcp"],
            cwd=str(ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=4,
            check=False,
            **hidden_subprocess_kwargs(),
        )
    except Exception:
        return {"pid": "", "name": "", "endpoint": ""}
    if proc.returncode != 0:
        return {"pid": "", "name": "", "endpoint": ""}
    port_suffix = f":{port}"
    preferred: tuple[str, str] | None = None
    fallback: tuple[str, str] | None = None
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != "TCP":
            continue
        endpoint = parts[1]
        state = parts[3].upper()
        pid = parts[4]
        if state != "LISTENING" or not endpoint.endswith(port_suffix):
            continue
        candidate = (endpoint, pid)
        if endpoint.startswith(("127.0.0.1:", "0.0.0.0:", "[::1]:", "[::]:")):
            preferred = candidate
            break
        fallback = fallback or candidate
    selected = preferred or fallback
    if not selected:
        return {"pid": "", "name": "", "endpoint": ""}
    endpoint, pid = selected
    return {"pid": pid, "name": _windows_pid_name(pid), "endpoint": endpoint}


def py_script(name: str, *args: str, prefer_host: bool = False) -> list[str]:
    if prefer_host:
        host_python = find_host_python()
        if host_python is not None:
            return [*host_python, str(SCRIPTS / name), *args]
    if IS_FROZEN:
        return [sys.executable, "--backend", name, *args]
    return [sys.executable, str(SCRIPTS / name), *args]


def py_test(name: str, *args: str) -> list[str]:
    return [sys.executable, str(ROOT / "tests" / "python" / name), *args]


def short_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def run_command(args: Iterable[str], timeout: int = 120) -> tuple[int, str]:
    proc = subprocess.run(
        list(args),
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
        **hidden_subprocess_kwargs(),
    )
    output = proc.stdout
    if proc.stderr:
        output += ("\n" if output else "") + proc.stderr
    return proc.returncode, output.strip()


def run_backend(script_name: str, args: list[str]) -> int:
    if Path(script_name).name != script_name or not script_name.endswith(".py"):
        print(f"Invalid backend script: {script_name}")
        return 2
    script = SCRIPTS / script_name
    if not script.exists():
        print(f"Backend script not found: {short_path(script)}")
        return 2
    os.chdir(ROOT)
    original_argv = sys.argv[:]
    original_path = sys.path[:]
    sys.path.insert(0, str(SCRIPTS))
    sys.path.insert(0, str(ROOT))
    sys.argv = [str(script), *args]
    try:
        runpy.run_path(str(script), run_name="__main__")
    except SystemExit as exc:
        code = exc.code
        if isinstance(code, int):
            return code
        if code:
            print(code)
            return 1
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"Backend script failed: {script_name}: {exc}", file=sys.stderr)
        traceback.print_exc()
        return 1
    finally:
        sys.argv = original_argv
        sys.path[:] = original_path
    return 0


def read_json_config() -> dict:
    try:
        data = json.loads(CONFIG.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def read_browser_integration() -> dict:
    try:
        data = json.loads(BROWSER_CONFIG.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {
            "default_proxy": "socks5://127.0.0.1:10808",
            "stealth": {"project_url": CLOAKBROWSER_URL},
        }


class LogMultiplexer:
    """Route UI output into system, proxy, and audit buffers without cross-thread writes."""

    def __init__(self, buffers: dict[str, tk.Text]) -> None:
        self.buffers = buffers
        self.queue: queue.Queue[tuple[str, str]] = queue.Queue()
        self.xray_pattern = re.compile(r"\[xray\]|proxy/|accepted|tunnel|transport|xray", re.IGNORECASE)
        self.audit_pattern = re.compile(r"\[OK\]|\[PASS\]|\[FAIL\]|\[WARN\]|validation|linter|preflight|audit|route|needs attention", re.IGNORECASE)

    def enqueue(self, text: str, stream: str | None = None) -> None:
        if not text:
            return
        target = stream or self.route(text)
        self.queue.put((target, text))

    def route(self, text: str) -> str:
        if self.xray_pattern.search(text):
            return "xray"
        if self.audit_pattern.search(text):
            return "audit"
        return "sys"

    def drain(self) -> None:
        processed = 0
        while processed < 120:
            try:
                target, text = self.queue.get_nowait()
            except queue.Empty:
                return
            widget = self.buffers.get(target) or self.buffers["sys"]
            widget.configure(state="normal")
            tag = "normal"
            lowered = text.lower()
            if "[ok]" in lowered or "[pass]" in lowered or "exited with code 0" in lowered:
                tag = "success"
            elif "[warn]" in lowered or "warning" in lowered or "needs attention" in lowered:
                tag = "warning"
            elif "[fail]" in lowered or "error" in lowered or "traceback" in lowered:
                tag = "danger"
            widget.insert("end", text, tag)
            if float(widget.index("end-1c").split(".")[0]) > 1500:
                widget.delete("1.0", "150.0")
            widget.configure(state="disabled")
            widget.see("end")
            self.queue.task_done()
            processed += 1


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Xray-Cooperative-Overlay Control Center")
        self.protocol("WM_DELETE_WINDOW", self.close_app)
        self.scaling_factor = self._query_hardware_dpi_scale()
        self.fonts = self._build_fonts()
        self._app_icon_image: tk.PhotoImage | None = None
        self._set_window_icon()
        self.geometry(f"{self._scaled(1320)}x{self._scaled(820)}")
        self.minsize(self._scaled(1040), self._scaled(640))
        self.configure(bg=COLORS["bg"])
        self.current_process_label = tk.StringVar(value="Ready")
        self.profile_offset = tk.StringVar(value="100")
        self.profile_suffix = tk.StringVar(value=".altports")
        self.dns_domain = tk.StringVar(value="example.com")
        self.dns_resolvers = tk.StringVar(value="1.1.1.1, 8.8.8.8")
        browser_cfg = read_browser_integration()
        self.browser_url = tk.StringVar(value="https://example.com")
        self.browser_proxy = tk.StringVar(value=str(browser_cfg.get("default_proxy", "socks5://127.0.0.1:10808")))
        self.last_profile_proxy_url = self.browser_proxy.get()
        self.browser_executable = tk.StringVar(value="")
        self.browser_fingerprint_seed = tk.StringVar(value="")
        ja3_cfg = browser_cfg.get("ja3_oracle") if isinstance(browser_cfg.get("ja3_oracle"), dict) else {}
        self.browser_ja3_oracle_url = tk.StringVar(value=str(ja3_cfg.get("default_url") or ""))
        self.browser_headless = tk.BooleanVar(value=False)
        self.browser_geoip = tk.BooleanVar(value=False)
        self.browser_humanize = tk.BooleanVar(value=bool((browser_cfg.get("stealth") or {}).get("default_humanize", True)))
        self.xray_supervisor: ProcessSupervisor | None = None
        self.xray_process: subprocess.Popen[str] | None = None
        self.active_config = tk.StringVar(value=str(CONFIG))
        self.profile_selection = tk.StringVar(value="")
        self.command_search = tk.StringVar(value="")
        self.palette_query = tk.StringVar(value="")
        self.focus_mode_text = tk.StringVar(value="Focus")
        self.telemetry_rail_text = tk.StringVar(value="Hide Telemetry")
        self.show_start_advanced = tk.BooleanVar(value=False)
        self.show_dashboard_profile = tk.BooleanVar(value=False)
        self.show_dashboard_browser_advanced = tk.BooleanVar(value=False)
        self.show_dashboard_activity = tk.BooleanVar(value=False)
        self.show_validation_advanced = tk.BooleanVar(value=False)
        self.show_health_advanced = tk.BooleanVar(value=False)
        self.show_repair_advanced = tk.BooleanVar(value=False)
        self.show_profiles_advanced = tk.BooleanVar(value=False)
        self.show_browser_page_advanced = tk.BooleanVar(value=False)
        self.show_browser_fingerprint = tk.BooleanVar(value=False)
        self.connection_state = tk.StringVar(value="Not connected")
        self.simple_next_step = tk.StringVar(value="Run Check Setup, then start the bundled core or open v2rayN and test the browser.")
        self.core_version_text = tk.StringVar(value="Xray Core: checking")
        self.local_proxy_text = tk.StringVar(value="Local proxy: 127.0.0.1:10808")
        self.dns_text = tk.StringVar(value="DNS: checking")
        self.system_proxy_text = tk.StringVar(value="System proxy: checking")
        self.tun_text = tk.StringVar(value="TUN: checking")
        self.screen_title = tk.StringVar(value="Dashboard")
        self.overall_status = tk.StringVar(value="Checking")
        self.overall_detail = tk.StringVar(value="Reading local config, certificates, ports, and tools.")
        self.telemetry_summary = tk.StringVar(value="Activity history: local only, 0 events")
        self.telemetry_last = tk.StringVar(value="Last activity: none")
        self.auto_refresh_state = tk.StringVar(value="Auto refresh: starting")
        self.diagnostic_title = tk.StringVar(value="Setup is being checked")
        self.diagnostic_detail = tk.StringVar(value="The app is reading local files, tool paths, and proxy state.")
        self.diagnostic_action = tk.StringVar(value="Next: wait for the first status refresh.")
        self.network_down_rate = tk.StringVar(value="Measuring")
        self.network_up_rate = tk.StringVar(value="Measuring")
        self.network_total = tk.StringVar(value="Measuring")
        self.network_duration = tk.StringVar(value="0s")
        self.network_runtime_hint = tk.StringVar(value="Core not active")
        self.telemetry_connections = tk.StringVar(value="0")
        self.telemetry_requests = tk.StringVar(value="0")
        self.telemetry_blocked = tk.StringVar(value="0")
        self.network_source = tk.StringVar(value="Counters: local system interfaces")
        self.footer_system_text = tk.StringVar(value=self._system_footer_text())
        self.footer_update_text = tk.StringVar(value="No updates available")
        self.primary_action_text = tk.StringVar(value="Check Setup")
        self.primary_action_detail = tk.StringVar(value="Start with a safe local setup check.")
        self.intelligent_hint_text = tk.StringVar(value="")
        self.output_toggle_text = tk.StringVar(value="Hide Logs")
        self.last_status_level = "unknown"
        self.last_command_failure: dict[str, object] | None = None
        self.status_refresh_count = 0
        self._status_loop_running = False
        self._primary_action: Callable[[], None] = self.run_beginner_setup_check
        self.readiness_cache = GuiReadinessCache(root=ROOT, cert_path=CERT, key_path=KEY)
        self.gui_preferences = load_preferences()
        self.opsec_telemetry_mode = tk.BooleanVar(value=self.gui_preferences.ram_only())
        self.block_connect_on_preflight_fail = tk.BooleanVar(value=self.gui_preferences.block_connect_on_preflight_fail)
        self.auto_apply_strategy_on_probe = tk.BooleanVar(value=self.gui_preferences.auto_apply_strategy_on_probe)
        self._ram_telemetry_events: list[dict[str, object]] = []
        self._proxy_active_since: float | None = None
        self._network_baseline: tuple[float, int, int, str] | None = None
        self._network_last: tuple[float, int, int, str] | None = None
        self._network_next_poll = 0.0
        self._network_last_rates: tuple[float, float] = (0.0, 0.0)
        self._network_poll_running = False
        self.output_visible = tk.BooleanVar(value=False)
        self.logs_have_unread = False
        self.sidebar_visible = True
        self.telemetry_rail_visible = True
        self.status_chip_labels: dict[str, tk.Label] = {}
        self.dashboard_stat_labels: dict[str, tuple[tk.Label, tk.Label, tk.Canvas]] = {}
        self.readiness_labels: dict[str, tuple[tk.Label, tk.Label]] = {}
        self.preflight_labels: dict[str, tuple[tk.Label, tk.Label]] = {}
        self.network_mode_labels: dict[str, tuple[tk.Label, tk.Label]] = {}
        self.traffic_summary_labels: dict[str, tuple[tk.Label, tk.Label]] = {}
        self.sparkline_canvases: dict[str, tk.Canvas] = {}
        self.sparkline_history: dict[str, deque[float]] = {
            key: deque(maxlen=20) for key in ("down", "up", "connections", "requests", "blocked")
        }
        self.nav_button_widgets: dict[str, tuple[tk.Frame, tk.Label, tk.Canvas, tk.Frame]] = {}
        self.tab_pages: dict[str, tk.Frame] = {}
        self.tab_canvases: dict[str, tk.Canvas] = {}
        self.output_buffers: dict[str, tk.Text] = {}
        self.runtime_labels: dict[str, list[tuple[tk.Label, tk.Label]]] = {}
        self.log_multiplexer: LogMultiplexer | None = None
        self.busy_controls: list[tk.Widget] = []
        self.is_busy = False
        self.stream_count = 0
        self.active_banner: tk.Frame | None = None
        self.help_topics = self._build_help_topics()
        self._configure_style()
        self._build_layout()
        self._build_menu()
        self.record_telemetry("app_started", "info", "GUI started")
        self.refresh_status()
        self._start_status_loop()

    def _system_footer_text(self) -> str:
        if os.name == "nt":
            try:
                version = sys.getwindowsversion()
                build = getattr(version, "build", 0)
                release = platform.release()
                return f"Windows {release} ({build})"
            except Exception:
                return "Windows"
        return f"{platform.system()} {platform.release()}".strip()

    def _set_window_icon(self) -> None:
        try:
            if os.name == "nt" and APP_ICON_ICO.exists():
                self.iconbitmap(str(APP_ICON_ICO))
            if APP_ICON_PNG.exists():
                self._app_icon_image = tk.PhotoImage(file=str(APP_ICON_PNG))
                self.iconphoto(True, self._app_icon_image)
        except tk.TclError:
            self._app_icon_image = None

    def _query_hardware_dpi_scale(self) -> float:
        if os.name == "nt":
            try:
                import ctypes
                ctypes.windll.shcore.SetProcessDpiAwareness(2)
                hdc = ctypes.windll.user32.GetDC(0)
                dpi = ctypes.windll.gdi32.GetDeviceCaps(hdc, 88)
                ctypes.windll.user32.ReleaseDC(0, hdc)
                return max(1.0, min(1.8, dpi / 96.0))
            except Exception:
                pass
        try:
            # Tk reports points-per-pixel; 1.333 is the usual 96-DPI baseline.
            return max(1.0, min(1.8, float(self.tk.call("tk", "scaling")) / 1.3333333333333333))
        except Exception:
            return 1.0

    def _scaled(self, value: int) -> int:
        return max(1, int(value * self.scaling_factor))

    def _preferred_font_family(self) -> str:
        if os.name == "nt":
            preferred = ("Segoe UI Variable Display", "Segoe UI", "Tahoma")
        else:
            preferred = ("Inter", "Helvetica Neue", "DejaVu Sans", "Helvetica")
        try:
            from tkinter import font as tkfont

            available = {name.lower() for name in tkfont.families(self)}
            for candidate in preferred:
                if candidate.lower() in available:
                    return candidate
        except Exception:
            pass
        return preferred[-1]

    def _build_fonts(self) -> dict[str, tuple[str, int, str]]:
        family = self._preferred_font_family()
        code_family = "Consolas" if os.name == "nt" else "DejaVu Sans Mono"
        try:
            from tkinter import font as tkfont

            if code_family.lower() not in {n.lower() for n in tkfont.families(self)}:
                code_family = "Courier"
        except Exception:
            code_family = "Consolas" if os.name == "nt" else "Courier"
        return {
            "display": (family, self._scaled(19), "bold"),
            "h1": (family, self._scaled(15), "bold"),
            "h2": (family, self._scaled(12), "bold"),
            "h3": (family, self._scaled(10), "bold"),
            "metric": (family, self._scaled(14), "bold"),
            "body": (family, self._scaled(9), "normal"),
            "body_bold": (family, self._scaled(9), "bold"),
            "caption": (family, self._scaled(8), "normal"),
            "caption_bold": (family, self._scaled(8), "bold"),
            "micro": (family, self._scaled(8), "bold"),
            "code": (code_family, self._scaled(9), "normal"),
        }

    def _build_help_topics(self) -> dict[str, str]:
        return {
            "dashboard": (
                "Dashboard\n\n"
                "What it is:\n"
                "The normal daily-use screen. Start the bundled core or use an external v2rayN/Xray listener, then run one browser page check.\n\n"
                "Recommended path:\n"
                "1. Leave Advanced profile closed unless a guide tells you to change profiles.\n"
                "2. Click Start Core, or keep your existing v2rayN/Xray client running.\n"
                "3. Run Page Check with a simple URL first, then move to Health if anything fails.\n\n"
                "What the metrics mean:\n"
                "Core shows whether 127.0.0.1:10808 is offline, running from this app, or already used by another local client.\n"
                "Connections counts accepted Xray log lines seen during this app session. It is an activity hint, not a traffic counter.\n"
                "Data reminds you that GUI logs and activity history stay local.\n"
                "Next Step points to the safest action based on current setup state (shared with CLI `main.py probe`).\n"
                "Smart Tips and the blue tip strip use the intelligent advisor when labels or lab context apply.\n\n"
                "Fallbacks:\n"
                "If Start Core cannot find a complete bundled core, use Download Xray Core in Settings. If the port is already active, stop the external client there or keep using it and run Page Check."
            ),
            "getting_started": (
                "Getting Started\n\n"
                "What it is:\n"
                "A guided first-run checklist for people who do not want to learn every internal tool before trying the project.\n\n"
                "Also read:\n"
                "docs/getting-started.md for a short English walkthrough.\n\n"
                "Use it when:\n"
                "You just cloned the repo, moved to a new machine, rotated certificates, or are unsure which button to press first.\n\n"
                "Recommended path:\n"
                "1. Check Setup: runs the smallest useful local validation set.\n"
                "2. Generate Local CA: creates your personal certificate and key files only.\n"
                "3. Start Core: launches the bundled Xray Core if runtime files are available.\n"
                "4. Run Page Check: verifies that a browser can load a page through the local proxy.\n\n"
                "Smart Tips:\n"
                "Opens the same local advisor as `main.py advise` — profile and lab suggestions from your machine only.\n\n"
                "Safety boundaries:\n"
                "This screen does not upload reports, install trust silently, change system proxy settings, or commit generated files."
            ),
            "checks": (
                "Routing\n\n"
                "What it is:\n"
                "A local validation workbench for deeper setup checks. Most people only need it when a guide or support helper asks for more detail.\n\n"
                "Start with:\n"
                "Validate Config, Static Preflight, Health Probe, and Secret Scan. These catch the common local setup and repository hygiene issues.\n\n"
                "Extra checks:\n"
                "Route, provider, generated-config, transport, lab evidence, and decision-report checks are more detailed. They are hidden by default because first-time users should not need to read them.\n\n"
                "Fallbacks:\n"
                "If a check reports Needs attention, copy the output or issue summary before changing files. Most messages name the missing file, dependency, route, port, or rule that needs attention."
            ),
            "health_report": (
                "Logs & Health\n\n"
                "What it is:\n"
                "A support-safe snapshot of the local environment. It is the best next step after a browser check fails.\n\n"
                "Run Health Probe checks:\n"
                "Ports, certificate files, trust alignment, DNS reachability, provider freshness, geodata lock state, and local runtime hints.\n\n"
                "Advanced reports:\n"
                "Lab Evidence runs DNS and FakeDNS harness scenarios. Decision Report creates a compact redacted summary for support triage.\n\n"
                "Privacy boundary:\n"
                "Reports stay local unless you choose to share them. They omit private keys, cookies, request bodies, and full browsing history."
            ),
            "fix_tools": (
                "Settings\n\n"
                "What it is:\n"
                "A local repair shelf for generated files, optional tools, and runtime downloads.\n\n"
                "Use Repair Setup when:\n"
                "Profiles are missing, route or metadata checks are noisy, or you want the project to regenerate local derived files in a predictable way.\n\n"
                "Advanced setup tools:\n"
                "Installers, alternate-port generation, Xray download, and packaging helpers stay hidden until opened.\n\n"
                "Safety boundary:\n"
                "Setup tools do not install certificate trust, change system proxy settings, delete browser profiles, or upload diagnostics."
            ),
            "profiles_dns": (
                "Profiles & DNS\n\n"
                "What it is:\n"
                "A focused area for operating modes and DNS checks.\n\n"
                "Profiles:\n"
                "Use the standard profile for normal browsing tests. Strict is more cautious, balanced is a middle path, compatibility is for difficult networks, debug is for detailed troubleshooting, and alternate ports are for machines where another app already uses the defaults.\n\n"
                "DNS Check:\n"
                "Queries A, AAAA, HTTPS, and SVCB records against selected resolvers so resolver drift is easier to spot.\n\n"
                "Fallbacks:\n"
                "If default ports are occupied, generate alternate-port profiles instead of hand-editing only one listener."
            ),
            "certificates": (
                "Certificates\n\n"
                "What it is:\n"
                "The local certificate lifecycle screen.\n\n"
                "Use it when:\n"
                "The browser shows certificate errors, local CA files are missing, or you need manual trust-store instructions.\n\n"
                "What happens:\n"
                "Certificate Status inspects local CA files. Check Cert/Key Pair verifies that the certificate and key match. Generate Local CA creates or replaces Xray-config/mycert.crt and mycert.key.\n\n"
                "Safety boundary:\n"
                "The GUI never installs trust silently and never uploads keys. Keep mycert.key private."
            ),
            "browser_tests": (
                "Proxy\n\n"
                "What it is:\n"
                "A browser verification screen with the beginner path first and fingerprint testing hidden by default.\n\n"
                "Recommended path:\n"
                "Run Page Check first. It verifies proxy wiring, local CA behavior, and page loading with stock Chromium.\n\n"
                "Advanced settings:\n"
                "Proxy is usually socks5://127.0.0.1:10808. Browser path is optional; leave it blank to use Playwright's browser when available. Fingerprint Check uses CloakBrowser and should be used only after Page Check passes.\n\n"
                "Fallbacks:\n"
                "If browser dependencies are missing, use Install Page Check Tools in Settings or read the install hint."
            ),
            "network_mode": (
                "Network Mode\n\n"
                "What it is:\n"
                "A clear view of how traffic is expected to enter Xray.\n\n"
                "Recommended mode:\n"
                "Use the browser proxy field for tests. It keeps routing explicit and avoids changing system-wide network settings.\n\n"
                "External clients:\n"
                "If v2rayN or another Xray process already owns the selected local port, this app uses it for checks and will not stop it.\n\n"
                "System proxy:\n"
                "The app detects system proxy state to warn about loops, but it does not change Windows or OS proxy settings automatically.\n\n"
                "TUN:\n"
                "TUN affects OS-wide routing and usually needs administrator privileges. Use it only with a config that explicitly includes a TUN inbound and after reviewing routes."
            ),
            "docs": (
                "About\n\n"
                "What it is:\n"
                "A local documentation launcher. It opens files from this repository and does not use the network.\n\n"
                "Use it when:\n"
                "You need the focused guide for operating profiles, browser integration, certificates, DNS, local activity history, platform compatibility, or provider status."
            ),
            "1_proxy_control": (
                "Core Control\n\n"
                "What it is:\n"
                "The start/stop controls for the GUI-managed Xray process.\n\n"
                "Normal use:\n"
                "Leave Advanced profile closed and click Start Core. Stop App Core stops only the process launched by this GUI.\n\n"
                "Fallbacks:\n"
                "If another app already owns 127.0.0.1:10808, this GUI will not kill it. Stop it in v2rayN/Xray or keep it running and use Page Check."
            ),
            "2_browser_check": (
                "Browser Proxy Check\n\n"
                "What it is:\n"
                "A one-page browser test from the Dashboard screen.\n\n"
                "Normal use:\n"
                "Enter a simple HTTPS URL and click Run Page Check.\n\n"
                "Advanced use:\n"
                "Open advanced browser settings only when you need a custom proxy, a specific Chrome or Edge executable, or reset controls."
            ),
            "3_quick_actions": (
                "Quick Actions\n\n"
                "What it is:\n"
                "A compact set of common recovery actions.\n\n"
                "Use in this order:\n"
                "Check Setup first, Repair Setup if local generated files are outdated, Generate Local CA if certificate files are missing, and Copy Issue Summary when you need a redacted support summary."
            ),
            "4_activity_history": (
                "Activity History\n\n"
                "What it is:\n"
                "A local activity trail for GUI actions only.\n\n"
                "What it records:\n"
                "Command labels, result codes, durations, and status snapshots. It does not record request bodies, private keys, cookies, or browsing payloads.\n\n"
                "Actions:\n"
                "Run Full Status records a local snapshot. Show Activity displays recent events. Export Activity writes a redacted local JSON file. Clear Activity removes the GUI event history."
            ),
            "status_summary": (
                "Status Summary\n\n"
                "These tiles summarize the selected config, certificate files, generated profiles, health tool availability, dependencies, browser setup, and privacy boundaries."
            ),
            "can_i_use_it_now": (
                "Can I Use It Now?\n\n"
                "This is the shortest readiness view. Green means that part is ready, yellow means setup is still needed, and red means the app cannot continue safely.\n\n"
                "Read it left to right: config, runtime, certificate, then active core listener. When all four are ready, run Page Check."
            ),
            "live_network": (
                "Live Network\n\n"
                "Shown in the right telemetry rail. Running Time at the top tracks how long the local core session has been active. "
                "Each live metric includes a small inline sparkline beside its value, sampled from local counters during the GUI auto-refresh loop: "
                "download rate, upload rate, connections, requests, and blocked events.\n\n"
                "Privacy boundary:\n"
                "These are byte counters from the operating system. The GUI does not inspect payloads, request bodies, cookies, or browser history."
            ),
            "live_diagnostic_guidance": (
                "Live Diagnostic Guidance\n\n"
                "Shows the current reason the app thinks setup is ready or needs attention, plus the safest next action.\n\n"
                "After a command fails, this card keeps the last failure visible so newcomers do not have to search through the log pane."
            ),
            "choose_your_path": (
                "Choose Your Path\n\n"
                "Use this when you are not sure which screen or button matters.\n\n"
                "New setup runs the first safe checks. Core already running skips straight to the browser check. Something failed collects a local health report before you change settings."
            ),
            "setup_map": (
                "Setup Map\n\n"
                "A compact overview of the normal app flow: check, create CA, connect, verify.\n\n"
                "Use this as orientation. The Best Next Action bar and Can I Use It Now panel update live as the machine state changes."
            ),
            "command_search": (
                "Command Search\n\n"
                "Filters checks by label, description, or command arguments. Use Ctrl+F from anywhere in the app to jump here.\n\n"
                "This is useful when you remember a word like DNS, browser, provider, route, or certificate but do not remember which tab or advanced section contains the check."
            ),
            "command_palette": (
                "Command Palette\n\n"
                "Use Ctrl+K or Find Action to search screens, common actions, setup tools, docs, and view controls from one place.\n\n"
                "Type a word like health, core, proxy, cert, logs, browser, docs, settings, or focus. Press Enter to run the selected action."
            ),
            "keyboard_shortcuts": (
                "Keyboard Shortcuts\n\n"
                "F5 refreshes live status.\n"
                "Ctrl+R runs the Best Next Action.\n"
                "Ctrl+K opens Find Action.\n"
                "Ctrl+F jumps to Command Search.\n"
                "Ctrl+L shows or hides the Log Drawer.\n"
                "Ctrl+B toggles Focus mode.\n"
                "Ctrl+T toggles the Telemetry rail.\n"
                "Escape hides the Log Drawer."
            ),
            "1_check_setup": (
                "Check Setup\n\n"
                "Runs the smallest useful local check set for first-time setup. It validates the main config, static preflight shape, transport profile policy, UDP/443 profile policy, and tracked-file secret hygiene.\n\n"
                "Fallbacks:\n"
                "If this reports Needs attention, read the last failing step first and use Repair Setup only after the message names generated files or local metadata as the problem."
            ),
            "2_create_local_ca": (
                "Create Local CA\n\n"
                "Creates your personal mycert.crt and mycert.key files under Xray-config.\n\n"
                "Safety boundary:\n"
                "This does not install certificate trust. After generation, use Trust Instructions or the certificate docs to install trust manually in the intended OS or browser store."
            ),
            "3_start_proxy": (
                "Start Core\n\n"
                "Starts the bundled Xray Core with the standard profile. If another client already owns 127.0.0.1:10808, the GUI leaves it alone.\n\n"
                "Fallbacks:\n"
                "If the bundled core is missing, use Download Xray Core in Repair. If an external client is active, stop it there or continue using it."
            ),
            "4_test_a_page": (
                "Test A Page\n\n"
                "Runs the stock Chromium page check through the local proxy. Use a simple HTTPS URL first.\n\n"
                "Fallbacks:\n"
                "If the page check fails, run Health Probe before changing profiles. If Playwright is missing, use Install Page Check Tools in Repair."
            ),
            "optional_setup_tools": (
                "Optional Setup Tools\n\n"
                "What it is:\n"
                "Installers and runtime helpers that are useful only when a check asks for them.\n\n"
                "Use it when:\n"
                "Page Check cannot find Playwright, Fingerprint Check cannot find CloakBrowser, bundled Xray Core is missing, or you need to build the Windows executable.\n\n"
                "Fallbacks:\n"
                "If Python is missing, install Python 3 first or run the equivalent commands manually from a configured environment."
            ),
            "when_something_fails": (
                "When Something Fails\n\n"
                "Start with:\n"
                "Read the last Needs attention line in the log. It usually names the missing dependency, file, port, route, or certificate issue.\n\n"
                "Useful buttons:\n"
                "Explain Output prints the status meanings. Copy Issue Summary copies a redacted machine summary. Troubleshooting Docs opens the detailed local guide.\n\n"
                "Fallbacks:\n"
                "If the GUI is blocked by missing optional tools, use Settings. If a browser check fails, run Health Probe next."
            ),
            "advanced_profile": (
                "Advanced Profile\n\n"
                "Leave this closed for normal use.\n\n"
                "Use it when:\n"
                "A guide tells you to test strict, balanced, compatibility, debug, or an alternate-port profile.\n\n"
                "What changes:\n"
                "Only the config file used when this GUI starts Xray changes. Existing external clients are not modified."
            ),
            "advanced_browser_settings": (
                "Advanced Browser Settings\n\n"
                "Leave this closed for normal use.\n\n"
                "Use it when:\n"
                "You need a custom proxy endpoint, a specific Chrome or Edge executable, or to reset browser fields.\n\n"
                "Fallbacks:\n"
                "Blank browser path means Playwright will use its managed browser when available."
            ),
            "operating_profiles": (
                "Operating Profiles\n\n"
                "Regenerate Standard Profiles refreshes the ready-made operating modes. Generate Alternate Profiles creates local-only variants with shifted ports for machines where default ports are occupied."
            ),
            "dns_diagnostics": (
                "DNS Check\n\n"
                "Domain is the name to query. Resolvers is a comma-separated list such as 1.1.1.1, 8.8.8.8. DNS Sweep checks common record types for resolver drift."
            ),
            "dns_check": (
                "DNS Check\n\n"
                "Domain is the name to query. Resolvers is a comma-separated list such as 1.1.1.1, 8.8.8.8. DNS Sweep checks common record types for resolver drift."
            ),
            "certificate_lifecycle": (
                "Certificate Lifecycle\n\n"
                "Use this screen to inspect, match, generate, and manually trust the local CA. The private key is local and ignored by git."
            ),
            "shared_settings": (
                "Shared Browser Settings\n\n"
                "Target URL and Proxy are reused by both browser test modes. The default proxy should point at the local mixed inbound."
            ),
            "advanced_page_check_settings": (
                "Advanced Page-Check Settings\n\n"
                "Use this only when the default Playwright browser is not enough.\n\n"
                "Chrome path selects a specific local Chrome or Edge executable. Headless hides the browser window and is less useful for first-time MITM debugging."
            ),
            "path_1_diagnostics_stock_chromium": (
                "Page Check Browser Path\n\n"
                "Use this first. It checks whether a stock browser can load the target page through the local proxy and local CA setup."
            ),
            "path_1_page_check_stock_chromium": (
                "Page Check Browser Path\n\n"
                "Use this first. It checks whether a stock browser can load the target page through the local proxy and local CA setup."
            ),
            "path_2_fingerprint_check_cloakbrowser": (
                "Fingerprint Browser Path\n\n"
                "Use this after the basic page check works. Fingerprint seed makes runs reproducible. GeoIP aligns browser timezone/locale to the proxy. Humanize enables realistic interaction timing."
            ),
            "advanced_support_reports": (
                "Advanced Support Reports\n\n"
                "Use these after Health Probe when you need deeper evidence.\n\n"
                "Lab Evidence runs DNS and FakeDNS scenarios. Decision Report creates a compact redacted summary. Copy Phase Summary copies the most recent decision summary if it exists.\n\n"
                "Fallbacks:\n"
                "If the decision report is missing, run Decision Report first."
            ),
            "browser_smoke_summary": (
                "Browser Smoke Summary\n\n"
                "This optional wrapper runs browser checks against the same URL and proxy and summarizes pass/attention state.\n\n"
                "Use it after the main setup is ready. For first failures, Page Check and Health Probe give clearer individual output."
            ),
            "local_health_probe": (
                "Local Health Probe\n\n"
                "Runs the redacted health probe and related one-click environment checks.\n\n"
                "What each button checks:\n"
                "Health Probe checks ports, certificates, trust alignment, DNS, provider freshness, and runtime hints. Platform Capability reports local browser/platform limitations. Trust Store Check looks for the local CA in available trust stores.\n\n"
                "Fallbacks:\n"
                "If trust is missing, use Certificates -> Trust Instructions. If platform capability warns about browser behavior, verify with the platform guide."
            ),
            "advanced_repair_and_install_tools": (
                "Advanced Repair And Install Tools\n\n"
                "Use these only when a setup check or guide asks for them.\n\n"
                "Profile generation refreshes generated profile files. Optional dependency installers add Playwright, CloakBrowser, and packaging tools. Download Xray Core writes a local runtime under xray/, which is ignored by git."
            ),
            "alternate_port_profiles": (
                "Alternate-Port Profiles\n\n"
                "Use this when default local ports are already occupied.\n\n"
                "The offset shifts the mixed inbound and internal decrypt listeners together. The suffix is appended to generated filenames. Generated alternate-port files stay local and ignored by git."
            ),
            "safe_repair_sequence": (
                "Safe Repair Sequence\n\n"
                "Repair Setup regenerates derived profile files, validates metadata, validates routes and protocols, runs static preflight, and offers certificate generation only after confirmation.\n\n"
                "Safety boundary:\n"
                "It does not install certificate trust, change system proxy settings, delete browser profiles, or upload diagnostics."
            ),
        }

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", font=self.fonts["body"], background=COLORS["bg"], foreground=COLORS["ink"])
        style.configure("TNotebook", background=COLORS["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", padding=(self._scaled(12), self._scaled(7)), background="#e7edf6", foreground=COLORS["ink"])
        style.map("TNotebook.Tab", background=[("selected", COLORS["panel"])], foreground=[("selected", COLORS["blue_dark"])])
        try:
            style.layout("Sidebar.TNotebook.Tab", [])
        except tk.TclError:
            pass
        btn_pad = (self._scaled(13), self._scaled(8))
        style.configure(
            "Accent.TButton",
            background=COLORS["blue"],
            foreground="#ffffff",
            padding=btn_pad,
            borderwidth=0,
            focuscolor=COLORS["blue"],
            font=self.fonts["body_bold"],
        )
        style.map(
            "Accent.TButton",
            background=[("pressed", COLORS["blue_dark"]), ("active", COLORS["blue_dark"]), ("disabled", "#c7d2e6")],
            foreground=[("disabled", "#eef2f8")],
        )
        style.configure(
            "Soft.TButton",
            background=COLORS["blue_soft"],
            foreground=COLORS["blue_dark"],
            padding=btn_pad,
            borderwidth=0,
            focuscolor=COLORS["blue_soft"],
            font=self.fonts["body_bold"],
        )
        style.map("Soft.TButton", background=[("pressed", "#d8e6ff"), ("active", "#dbe9ff")])
        style.configure(
            "Ghost.TButton",
            background=COLORS["panel"],
            foreground=COLORS["ink_soft"],
            padding=btn_pad,
            borderwidth=1,
            bordercolor=COLORS["line_strong"],
            relief="solid",
            focuscolor=COLORS["panel"],
            font=self.fonts["body_bold"],
        )
        style.map(
            "Ghost.TButton",
            background=[("active", COLORS["panel_alt"]), ("pressed", COLORS["panel_soft"])],
            bordercolor=[("active", COLORS["blue_ring"])],
        )
        style.configure(
            "Danger.TButton",
            background=COLORS["red_soft"],
            foreground=COLORS["red"],
            padding=btn_pad,
            borderwidth=0,
            focuscolor=COLORS["red_soft"],
            font=self.fonts["body_bold"],
        )
        style.map("Danger.TButton", background=[("pressed", "#fbd5d2"), ("active", "#fbdedb")])
        style.configure(
            "Warning.TButton",
            background=COLORS["amber_soft"],
            foreground=COLORS["amber"],
            padding=btn_pad,
            borderwidth=0,
            focuscolor=COLORS["amber_soft"],
            font=self.fonts["body_bold"],
        )
        style.map("Warning.TButton", background=[("pressed", "#fbe8c6"), ("active", "#fcecd0")])
        style.configure(
            "TEntry",
            fieldbackground="#ffffff",
            bordercolor=COLORS["line_strong"],
            lightcolor=COLORS["line_strong"],
            darkcolor=COLORS["line_strong"],
            insertcolor=COLORS["ink"],
            padding=self._scaled(7),
        )
        style.map("TEntry", bordercolor=[("focus", COLORS["blue"])], lightcolor=[("focus", COLORS["blue"])])
        style.configure(
            "TCombobox",
            fieldbackground="#ffffff",
            background="#ffffff",
            bordercolor=COLORS["line_strong"],
            arrowcolor=COLORS["muted"],
            padding=self._scaled(5),
        )
        style.map("TCombobox", bordercolor=[("focus", COLORS["blue"])], fieldbackground=[("readonly", "#ffffff")])
        style.configure("TCheckbutton", background=COLORS["panel"], foreground=COLORS["ink_soft"], focuscolor=COLORS["panel"])
        style.map("TCheckbutton", background=[("active", COLORS["panel"])])
        style.configure(
            "TProgressbar",
            background=COLORS["blue"],
            troughcolor=COLORS["panel_soft"],
            bordercolor=COLORS["panel_soft"],
            lightcolor=COLORS["blue"],
            darkcolor=COLORS["blue"],
            thickness=self._scaled(6),
        )
        style.configure(
            "Vertical.TScrollbar",
            background=COLORS["line_strong"],
            troughcolor=COLORS["panel"],
            bordercolor=COLORS["panel"],
            arrowcolor=COLORS["muted"],
            width=self._scaled(11),
        )
        style.map("Vertical.TScrollbar", background=[("active", COLORS["muted_soft"])])
        style.configure("TLabelframe", background=COLORS["panel"], bordercolor=COLORS["line"], relief="solid")
        style.configure("TLabelframe.Label", background=COLORS["panel"], foreground=COLORS["ink"], font=self.fonts["body_bold"])

    def _build_layout(self) -> None:
        root = tk.Frame(self, bg=COLORS["bg"])
        self.root_container = root
        root.pack(fill="both", expand=True)
        root.columnconfigure(0, minsize=self._scaled(220), weight=0)
        root.columnconfigure(1, weight=1)
        root.columnconfigure(2, minsize=self._scaled(285), weight=0)
        root.rowconfigure(0, weight=1)
        root.rowconfigure(1, weight=0)

        sidebar = tk.Frame(root, bg=COLORS["sidebar"])
        self.sidebar = sidebar
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)

        brand = tk.Frame(sidebar, bg=COLORS["sidebar"])
        brand.pack(fill="x", padx=self._scaled(16), pady=(self._scaled(20), self._scaled(8)))
        mark = tk.Frame(brand, bg=COLORS["blue"], width=self._scaled(40), height=self._scaled(40))
        mark.pack(side="left", padx=(0, self._scaled(11)))
        mark.pack_propagate(False)
        self._icon_canvas(mark, "shield_globe", "#ffffff", 32, COLORS["blue"]).pack(expand=True)
        brand_text = tk.Frame(brand, bg=COLORS["sidebar"])
        brand_text.pack(side="left", fill="x", expand=True)
        tk.Label(brand_text, text="MITM", bg=COLORS["sidebar"], fg=COLORS["ink"], font=self.fonts["h1"], anchor="w").pack(fill="x")
        tk.Label(brand_text, text="DomainFronting", bg=COLORS["sidebar"], fg=COLORS["blue"], font=self.fonts["caption_bold"], anchor="w").pack(fill="x")
        tk.Label(
            sidebar,
            text="Local proxy control center",
            bg=COLORS["sidebar"],
            fg=COLORS["muted"],
            font=self.fonts["caption"],
            wraplength=self._scaled(186),
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=self._scaled(18), pady=(self._scaled(6), self._scaled(14)))
        tk.Frame(sidebar, bg=COLORS["sidebar_line"], height=1).pack(fill="x", padx=self._scaled(16), pady=(0, self._scaled(8)))
        nav_holder = tk.Frame(sidebar, bg=COLORS["sidebar"])
        nav_holder.pack(fill="both", expand=True, padx=self._scaled(6), pady=(0, self._scaled(10)))

        footer_block = tk.Frame(sidebar, bg=COLORS["sidebar"])
        footer_block.pack(side="bottom", fill="x", padx=self._scaled(16), pady=(self._scaled(8), self._scaled(16)))
        tk.Frame(footer_block, bg=COLORS["sidebar_line"], height=1).pack(fill="x", pady=(0, self._scaled(10)))
        ready_row = tk.Frame(footer_block, bg=COLORS["sidebar"])
        ready_row.pack(fill="x")
        dot = tk.Canvas(ready_row, width=self._scaled(10), height=self._scaled(10), bg=COLORS["sidebar"], highlightthickness=0)
        dot.create_oval(self._scaled(1), self._scaled(1), self._scaled(9), self._scaled(9), fill=COLORS["green"], outline=COLORS["green"])
        dot.pack(side="left", padx=(0, self._scaled(7)))
        tk.Label(
            ready_row,
            textvariable=self.current_process_label,
            bg=COLORS["sidebar"],
            fg=COLORS["ink_soft"],
            font=self.fonts["caption_bold"],
            anchor="w",
        ).pack(side="left", fill="x", expand=True)
        tk.Label(
            ready_row,
            text=APP_VERSION,
            bg=COLORS["sidebar"],
            fg=COLORS["muted"],
            font=self.fonts["caption_bold"],
            anchor="e",
        ).pack(side="right")
        tk.Label(
            footer_block,
            text="F5 refresh  ·  Ctrl+K find  ·  Ctrl+L logs  ·  Ctrl+B focus",
            bg=COLORS["sidebar"],
            fg=COLORS["muted_soft"],
            font=self.fonts["caption"],
            wraplength=self._scaled(180),
            justify="left",
            anchor="w",
        ).pack(fill="x", pady=(self._scaled(8), 0))

        content = tk.Frame(root, bg=COLORS["bg"])
        content.grid(row=0, column=1, sticky="nsew")
        content.columnconfigure(0, weight=1)
        self._build_telemetry_rail(root)

        header = tk.Frame(content, bg=COLORS["bg"])
        header.pack(fill="x", padx=self._scaled(20), pady=(self._scaled(14), self._scaled(8)))
        tk.Label(header, textvariable=self.screen_title, bg=COLORS["bg"], fg=COLORS["ink"], font=self.fonts["h1"], anchor="w").pack(side="left", fill="x", expand=True)
        self.header_status_label = tk.Label(
            header,
            textvariable=self.overall_status,
            bg=COLORS["blue_soft"],
            fg=COLORS["blue"],
            font=self.fonts["micro"],
            padx=self._scaled(11),
            pady=self._scaled(4),
        )
        self.header_status_label.pack(side="left", padx=(0, self._scaled(10)))
        self.task_progress = ttk.Progressbar(header, mode="indeterminate", length=self._scaled(82), style="TProgressbar")
        self.task_progress.pack(side="left")

        self.banner_slot = tk.Frame(content, bg=COLORS["bg"])
        self.banner_slot.pack(fill="x", padx=self._scaled(16), pady=(0, self._scaled(8)))

        self.tabs = ttk.Notebook(content, style="Sidebar.TNotebook")
        self.tabs.pack(fill="both", expand=True, padx=self._scaled(16), pady=(0, self._scaled(8)))

        self.start_tab = self._tab()
        self.dashboard_tab = self._tab()
        self.validation_tab = self._tab()
        self.health_tab = self._tab()
        self.fixes_tab = self._tab()
        self.profiles_tab = self._tab()
        self.certs_tab = self._tab()
        self.browser_tab = self._tab()
        self.docs_tab = self._tab()
        self.tabs.add(self._tab_page(self.dashboard_tab), text="Dashboard")
        self.tabs.add(self._tab_page(self.browser_tab), text="Proxy")
        self.tabs.add(self._tab_page(self.profiles_tab), text="Profiles & DNS")
        self.tabs.add(self._tab_page(self.validation_tab), text="Routing Checks")
        self.tabs.add(self._tab_page(self.health_tab), text="Logs & Health")
        self.tabs.add(self._tab_page(self.fixes_tab), text="Settings")
        self.tabs.add(self._tab_page(self.start_tab), text="Getting Started")
        self.tabs.add(self._tab_page(self.certs_tab), text="Certificates")
        self.tabs.add(self._tab_page(self.docs_tab), text="About")
        self.tabs.bind("<<NotebookTabChanged>>", lambda _event: self._highlight_active_nav())
        self.bind_all("<MouseWheel>", self._route_mousewheel, add="+")
        self.bind_all("<Button-4>", self._route_mousewheel, add="+")
        self.bind_all("<Button-5>", self._route_mousewheel, add="+")
        self.bind_all("<F5>", lambda _event: self.refresh_status(), add="+")
        self.bind_all("<Control-r>", lambda _event: self.run_primary_action(), add="+")
        self.bind_all("<Control-l>", lambda _event: self.toggle_output_drawer(), add="+")
        self.bind_all("<Control-k>", lambda _event: self.show_command_palette(), add="+")
        self.bind_all("<Control-f>", lambda _event: self.focus_command_search(), add="+")
        self.bind_all("<Control-b>", lambda _event: self.toggle_focus_mode(), add="+")
        self.bind_all("<Control-t>", lambda _event: self.toggle_telemetry_rail(), add="+")
        self.bind_all("<Escape>", lambda _event: self.hide_output_drawer(), add="+")

        nav_groups: list[tuple[str, list[tuple[str, tk.Frame]]]] = [
            ("", [
                ("Dashboard", self.dashboard_tab),
                ("Proxy", self.browser_tab),
                ("Profiles & DNS", self.profiles_tab),
                ("Routing", self.validation_tab),
                ("Logs & Health", self.health_tab),
                ("Settings", self.fixes_tab),
                ("Getting Started", self.start_tab),
                ("Certificates", self.certs_tab),
                ("About", self.docs_tab),
            ]),
        ]
        for group_name, items in nav_groups:
            if group_name:
                tk.Label(
                    nav_holder,
                    text=group_name.upper(),
                    bg=COLORS["sidebar"],
                    fg=COLORS["muted"],
                    font=self.fonts["caption_bold"],
                    anchor="w",
                ).pack(fill="x", padx=self._scaled(8), pady=(self._scaled(12), self._scaled(4)))
            for text, target in items:
                self._make_nav_button(nav_holder, text, target)

        self._build_start_here()
        self._build_dashboard()
        self._build_validation()
        self._build_health()
        self._build_fixes_help()
        self._build_profiles_dns()
        self._build_certs()
        self._build_browser()
        self._build_docs()
        self._build_output_pane(content)
        self._build_status_footer(root)
        self.busy_controls = [widget for widget in self._walk_widgets(root) if self._is_busy_managed_control(widget)]
        self._append_output("Ready. All actions run locally in this repository.\n")
        self.tabs.select(self._tab_page(self.dashboard_tab))
        self._highlight_active_nav()

    def _build_status_footer(self, root: tk.Widget) -> None:
        footer = tk.Frame(root, bg=COLORS["panel"], highlightbackground=COLORS["line"], highlightthickness=1)
        footer.grid(row=1, column=1, columnspan=2, sticky="ew")
        tk.Label(
            footer,
            textvariable=self.footer_system_text,
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=self.fonts["caption"],
            anchor="e",
        ).pack(side="left", fill="x", expand=True, padx=(self._scaled(14), self._scaled(8)), pady=self._scaled(5))
        tk.Label(
            footer,
            text="OK",
            bg=COLORS["panel"],
            fg=COLORS["green"],
            font=self.fonts["caption_bold"],
        ).pack(side="left", padx=(0, self._scaled(5)))
        tk.Label(
            footer,
            textvariable=self.footer_update_text,
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=self.fonts["caption"],
            anchor="w",
        ).pack(side="left", padx=(0, self._scaled(14)), pady=self._scaled(5))

    def _build_telemetry_rail(self, root: tk.Widget) -> None:
        rail = tk.Frame(root, bg=COLORS["rail"], highlightbackground=COLORS["line"], highlightthickness=1)
        self.telemetry_rail = rail
        rail.grid(row=0, column=2, sticky="nsew")
        rail.grid_propagate(False)

        runtime = self._rail_panel(rail, "Running Time", "clock")
        runtime_value = tk.Label(
            runtime,
            textvariable=self.network_duration,
            bg=COLORS["panel"],
            fg=COLORS["green"],
            font=self.fonts["metric"],
            anchor="w",
        )
        runtime_value.pack(fill="x", pady=(0, self._scaled(2)))
        tk.Label(
            runtime,
            textvariable=self.network_runtime_hint,
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            font=self.fonts["caption"],
            anchor="w",
            wraplength=self._scaled(220),
            justify="left",
        ).pack(fill="x")

        network = self._rail_panel(rail, "Live Telemetry", "network")
        live_row = tk.Frame(network, bg=COLORS["panel"])
        live_row.pack(fill="x", pady=(0, self._scaled(8)))
        tk.Label(live_row, textvariable=self.auto_refresh_state, bg=COLORS["panel"], fg=COLORS["muted"], font=self.fonts["caption"], anchor="w").pack(side="left", fill="x", expand=True)
        live_dot = tk.Canvas(live_row, width=self._scaled(8), height=self._scaled(8), bg=COLORS["panel"], highlightthickness=0)
        live_dot.create_oval(self._scaled(1), self._scaled(1), self._scaled(7), self._scaled(7), fill=COLORS["green"], outline=COLORS["green"])
        live_dot.pack(side="right", padx=(self._scaled(5), 0))
        tk.Label(live_row, text="Live", bg=COLORS["panel"], fg=COLORS["green"], font=self.fonts["caption_bold"]).pack(side="right")
        self._telemetry_metric(network, "down", "Downlink", self.network_down_rate, COLORS["blue"])
        self._telemetry_metric(network, "up", "Uplink", self.network_up_rate, COLORS["blue"])
        self._telemetry_metric(network, "connections", "Connections", self.telemetry_connections, COLORS["green"])
        self._telemetry_metric(network, "requests", "Requests", self.telemetry_requests, COLORS["violet"])
        self._telemetry_metric(network, "blocked", "Blocked", self.telemetry_blocked, COLORS["red"])
        tk.Label(network, textvariable=self.network_source, bg=COLORS["panel"], fg=COLORS["muted"], font=self.fonts["caption"], anchor="w", wraplength=self._scaled(220), justify="left").pack(fill="x", pady=(4, 0))

        privacy = self._rail_panel(rail, "Local & Private", "shield")
        tk.Label(
            privacy,
            text="MITM DomainFronting runs locally on your machine. Your traffic, logs, and settings never leave your device.",
            bg=COLORS["panel"],
            fg=COLORS["ink"],
            font=self.fonts["caption"],
            wraplength=self._scaled(225),
            justify="left",
            anchor="w",
        ).pack(fill="x", pady=(0, self._scaled(9)))
        for line in ("No data collection", "No telemetry export", "All processing is local"):
            item = tk.Frame(privacy, bg=COLORS["panel"])
            item.pack(fill="x", pady=(0, self._scaled(6)))
            check = tk.Canvas(item, width=self._scaled(16), height=self._scaled(16), bg=COLORS["panel"], highlightthickness=0)
            check.create_oval(self._scaled(1), self._scaled(1), self._scaled(15), self._scaled(15), fill=COLORS["green_soft"], outline=COLORS["green_soft"])
            check.create_line(
                self._scaled(5), self._scaled(8), self._scaled(7), self._scaled(10), self._scaled(11), self._scaled(5),
                fill=COLORS["green"], width=max(1, self._scaled(2)), capstyle="round", joinstyle="round",
            )
            check.pack(side="left", padx=(0, self._scaled(8)))
            tk.Label(item, text=line, bg=COLORS["panel"], fg=COLORS["ink_soft"], font=self.fonts["caption"], anchor="w").pack(side="left", fill="x", expand=True)

        opsec_row = tk.Frame(privacy, bg=COLORS["panel"])
        opsec_row.pack(fill="x", pady=(0, self._scaled(6)))
        ttk.Checkbutton(
            opsec_row,
            text="OPSEC mode (RAM-only activity history)",
            variable=self.opsec_telemetry_mode,
            command=self.toggle_opsec_telemetry_mode,
        ).pack(anchor="w")

        gate_row = tk.Frame(privacy, bg=COLORS["panel"])
        gate_row.pack(fill="x", pady=(0, self._scaled(6)))
        ttk.Checkbutton(
            gate_row,
            text="Block Start Core when preflight gate fails",
            variable=self.block_connect_on_preflight_fail,
            command=self.toggle_connect_preflight_gate,
        ).pack(anchor="w")

        strategy_row = tk.Frame(privacy, bg=COLORS["panel"])
        strategy_row.pack(fill="x", pady=(0, self._scaled(6)))
        ttk.Checkbutton(
            strategy_row,
            text="Auto-apply strategy profile after non-healthy decision report",
            variable=self.auto_apply_strategy_on_probe,
            command=self.toggle_auto_apply_strategy,
        ).pack(anchor="w")

        view = self._rail_panel(rail, "Quick Actions", "bolt")
        for index, (label, command) in enumerate(
            (
                ("Open Logs", self.toggle_output_drawer),
                ("Find Action", self.show_command_palette),
                ("Reset Statistics", self.clear_telemetry),
                ("Refresh", self.refresh_status),
            )
        ):
            if index:
                tk.Frame(view, bg=COLORS["line"], height=1).pack(fill="x", pady=(0, self._scaled(2)))
            row = tk.Frame(view, bg=COLORS["panel"], cursor="hand2")
            row.pack(fill="x", pady=(0, self._scaled(2)))
            name = tk.Label(
                row, text=label, bg=COLORS["panel"], fg=COLORS["ink_soft"], font=self.fonts["caption_bold"],
                anchor="w", cursor="hand2", padx=self._scaled(4), pady=self._scaled(5),
            )
            name.pack(side="left", fill="x", expand=True)
            chevron = tk.Label(row, text="\u203a", bg=COLORS["panel"], fg=COLORS["muted_soft"], font=self.fonts["h3"], cursor="hand2", padx=self._scaled(4))
            chevron.pack(side="right")
            kids = (name, chevron)

            def make_hover(widgets: tuple[tk.Label, ...], bg: str) -> Callable[[tk.Event | None], None]:
                def handler(_event: tk.Event | None = None) -> None:
                    row.configure(bg=bg)
                    for child in widgets:
                        child.configure(bg=bg)
                return handler

            row.bind("<Enter>", make_hover(kids, COLORS["panel_alt"]))
            row.bind("<Leave>", make_hover(kids, COLORS["panel"]))
            row.bind("<Button-1>", lambda _event, action=command: action())
            for child in row.winfo_children():
                child.bind("<Button-1>", lambda _event, action=command: action())

    def _rail_panel(self, parent: tk.Widget, title: str, icon: str = "info") -> tk.Frame:
        outer = tk.Frame(parent, bg=COLORS["panel"], highlightbackground=COLORS["line"], highlightthickness=1)
        outer.pack(fill="x", padx=self._scaled(12), pady=(0, self._scaled(10)))
        head = tk.Frame(outer, bg=COLORS["panel"])
        head.pack(fill="x", padx=self._scaled(10), pady=(self._scaled(9), self._scaled(4)))
        self._icon_canvas(head, icon, COLORS["blue"], 20, COLORS["panel"]).pack(side="left", padx=(0, self._scaled(7)))
        tk.Label(head, text=title, bg=COLORS["panel"], fg=COLORS["ink"], font=self.fonts["body_bold"], anchor="w").pack(side="left", fill="x", expand=True)
        body = tk.Frame(outer, bg=COLORS["panel"])
        body.pack(fill="x", padx=self._scaled(10), pady=(0, self._scaled(10)))
        return body

    def _stacked_buttons(self, parent: tk.Widget, specs: Iterable[tuple[str, str, Callable[[], None]]]) -> None:
        for text, style, command in specs:
            ttk.Button(parent, text=text, style=style, command=command).pack(fill="x", pady=(0, self._scaled(6)))

    def _telemetry_metric(self, parent: tk.Widget, key: str, label: str, variable: tk.StringVar, color: str) -> None:
        row = tk.Frame(parent, bg=COLORS["panel"])
        row.pack(fill="x", pady=(0, self._scaled(7)))
        self._icon_canvas(row, self._icon_for_title(label), color, 17, COLORS["panel"]).pack(side="left", padx=(0, self._scaled(7)))
        tk.Label(row, text=label, bg=COLORS["panel"], fg=COLORS["ink"], font=self.fonts["caption"], anchor="w").pack(side="left", fill="x", expand=True)
        inline = tk.Frame(row, bg=COLORS["panel"])
        inline.pack(side="right")
        canvas = tk.Canvas(
            inline,
            width=self._scaled(52),
            height=self._scaled(18),
            bg=COLORS["panel"],
            highlightthickness=0,
            borderwidth=0,
        )
        canvas.pack(side="left", padx=(0, self._scaled(6)))
        setattr(canvas, "_spark_color", color)
        self.sparkline_canvases[key] = canvas
        tk.Label(
            inline,
            textvariable=variable,
            bg=COLORS["panel"],
            fg=color,
            font=self.fonts["caption_bold"],
            width=10,
            anchor="e",
        ).pack(side="left")

    def _sparkline_push(self, key: str, value: float) -> None:
        history = self.sparkline_history.setdefault(key, deque(maxlen=20))
        history.append(max(0.0, float(value)))

    def _refresh_sparkline_samples(self) -> None:
        down_rate, up_rate = self._network_last_rates
        self._sparkline_push("down", down_rate)
        self._sparkline_push("up", up_rate)
        self._sparkline_push("connections", float(self.stream_count))
        events = self._telemetry_events()
        fail_count = sum(1 for item in events if str(item.get("status", "")).lower() in {"fail", "blocked", "error"})
        self._sparkline_push("requests", float(len(events)))
        self._sparkline_push("blocked", float(fail_count))

    def _draw_sparklines(self) -> None:
        self._refresh_sparkline_samples()
        for key, canvas in self.sparkline_canvases.items():
            canvas.delete("all")
            width = max(1, int(canvas.winfo_width() or self._scaled(52)))
            height = max(1, int(canvas.winfo_height() or self._scaled(18)))
            color = str(getattr(canvas, "_spark_color", COLORS["blue"]))
            values = list(self.sparkline_history.get(key, ()))
            if len(values) < 2:
                baseline = height - 2
                canvas.create_line(0, baseline, width, baseline, fill=COLORS["line"], width=1)
                continue
            lo = min(values)
            hi = max(values)
            span = hi - lo or 1.0
            pad = max(2, self._scaled(2))
            step = width / max(1, len(values) - 1)
            points: list[float] = []
            for index, value in enumerate(values):
                norm = (value - lo) / span
                y = height - pad - norm * max(1.0, height - (2 * pad))
                points.extend([index * step, y])
            fill_points = list(points)
            fill_points.extend([width, height, 0, height])
            canvas.create_polygon(*fill_points, fill=color, stipple="gray25", outline="")
            if len(points) >= 4:
                canvas.create_line(*points, fill=color, width=max(1, self._scaled(2)), smooth=True)
            baseline = height - 1
            canvas.create_line(0, baseline, width, baseline, fill=COLORS["line"], width=1)

    def _build_menu(self) -> None:
        menu = tk.Menu(self)
        navigate = tk.Menu(menu, tearoff=False)
        screens = [
            ("Dashboard", self.dashboard_tab),
            ("Proxy", self.browser_tab),
            ("Profiles & DNS", self.profiles_tab),
            ("Routing", self.validation_tab),
            ("Logs & Health", self.health_tab),
            ("Settings", self.fixes_tab),
            ("Getting Started", self.start_tab),
            ("Certificates", self.certs_tab),
            ("About", self.docs_tab),
        ]
        for label, frame in screens:
            navigate.add_command(label=label, command=lambda target=frame: self._select_workspace(target))
        menu.add_cascade(label="Navigate", menu=navigate)

        actions = tk.Menu(menu, tearoff=False)
        for label, command in (
            ("Best Next Action", self.run_primary_action),
            ("Check Setup", self.run_beginner_setup_check),
            ("Start Core", self.connect_xray),
            ("Run Page Check", self.run_browser_diagnostics),
            ("Run Health Probe", self.run_health_probe),
            ("Repair Setup", self.safe_auto_fix),
            ("Generate Local CA", self.generate_ca),
            ("Copy Issue Summary", self.copy_issue_summary),
        ):
            actions.add_command(label=label, command=command)
        menu.add_cascade(label="Actions", menu=actions)

        view = tk.Menu(menu, tearoff=False)
        view.add_command(label="Find Action", command=self.show_command_palette, accelerator="Ctrl+K")
        view.add_command(label="Checks Search", command=self.focus_command_search, accelerator="Ctrl+F")
        view.add_command(label="Toggle Focus Mode", command=self.toggle_focus_mode, accelerator="Ctrl+B")
        view.add_command(label="Toggle Telemetry Rail", command=self.toggle_telemetry_rail, accelerator="Ctrl+T")
        view.add_command(label="Toggle Log Drawer", command=self.toggle_output_drawer, accelerator="Ctrl+L")
        view.add_command(label="Refresh Status", command=self.refresh_status, accelerator="F5")
        menu.add_cascade(label="View", menu=view)

        help_menu = tk.Menu(menu, tearoff=False)
        help_menu.add_command(label="Current Screen Help", command=self.show_current_help)
        help_menu.add_command(label="Command Palette Help", command=lambda: self.show_help_topic("command_palette"))
        help_menu.add_command(label="Keyboard Shortcuts", command=lambda: self.show_help_topic("keyboard_shortcuts"))
        help_menu.add_separator()
        help_menu.add_command(label="Open GUI Guide", command=lambda: self.open_path(ROOT / "docs" / "gui.md"))
        menu.add_cascade(label="Help", menu=help_menu)
        self.configure(menu=menu)

    def _walk_widgets(self, parent: tk.Widget) -> Iterable[tk.Widget]:
        for child in parent.winfo_children():
            yield child
            yield from self._walk_widgets(child)

    def _is_busy_managed_control(self, widget: tk.Widget) -> bool:
        if not isinstance(widget, (tk.Button, ttk.Button)):
            return False
        if hasattr(self, "output_toggle_button") and widget is self.output_toggle_button:
            return False
        try:
            text = str(widget.cget("text"))
        except tk.TclError:
            return True
        always_available = {
            "Help", "Refresh Status", "Clear", "Copy All", "Copy Output", "Close", "Copy",
            "Find Action", "Shortcuts", "Focus", "Nav", "Hide Telemetry", "Show Telemetry",
            "Toggle Logs", "Refresh", "Hide Logs", "Show Logs", "Show Logs *",
            "Dashboard", "Proxy", "Profiles & DNS", "Routing", "Logs & Health", "Settings",
            "Getting Started", "Certificates", "About",
        }
        return text not in always_available and not text.startswith("Open ")

    def _make_nav_button(self, parent: tk.Widget, text: str, target: tk.Frame) -> None:
        icon_map = {
            "Dashboard": "grid",
            "Proxy": "network",
            "Profiles & DNS": "globe",
            "Routing": "route",
            "Logs & Health": "list",
            "Settings": "gear",
            "Getting Started": "wrench",
            "Certificates": "doc",
            "About": "info",
        }
        row = tk.Frame(parent, bg=COLORS["sidebar"], cursor="hand2")
        row.pack(fill="x", padx=self._scaled(6), pady=self._scaled(1))
        rail = tk.Frame(row, bg=COLORS["sidebar"], width=self._scaled(3))
        rail.pack(side="left", fill="y", padx=(0, self._scaled(6)))
        icon = self._icon_canvas(row, icon_map.get(text, "info"), COLORS["muted"], 22, COLORS["sidebar"])
        icon.pack(side="left", padx=(self._scaled(8), self._scaled(9)), pady=self._scaled(8))
        label = tk.Label(row, text=text, bg=COLORS["sidebar"], fg=COLORS["ink_soft"], font=self.fonts["body_bold"], anchor="w", cursor="hand2")
        label.pack(side="left", fill="x", expand=True, pady=self._scaled(8))

        def select(_event: tk.Event | None = None) -> str:
            self._select_workspace(target)
            return "break"

        def on_enter(_event: tk.Event | None = None) -> None:
            if getattr(row, "_nav_active", False):
                return
            for widget in (row, label, icon):
                widget.configure(bg=COLORS["sidebar_hover"])

        def on_leave(_event: tk.Event | None = None) -> None:
            if getattr(row, "_nav_active", False):
                return
            for widget in (row, label, icon):
                widget.configure(bg=COLORS["sidebar"])

        for widget in (row, rail, icon, label):
            widget.bind("<Button-1>", select)
            widget.bind("<Enter>", on_enter)
            widget.bind("<Leave>", on_leave)
        self.nav_button_widgets[text] = (row, label, icon, rail)

    def _select_workspace(self, frame: tk.Frame) -> None:
        self.tabs.select(self._tab_page(frame))
        self._highlight_active_nav()

    def toggle_focus_mode(self) -> None:
        if not hasattr(self, "sidebar"):
            return
        self.sidebar_visible = not self.sidebar_visible
        if self.sidebar_visible:
            self.sidebar.grid()
            self.root_container.columnconfigure(0, minsize=self._scaled(220), weight=0)
            self.focus_mode_text.set("Focus")
        else:
            self.sidebar.grid_remove()
            self.root_container.columnconfigure(0, minsize=0, weight=0)
            self.focus_mode_text.set("Nav")

    def toggle_telemetry_rail(self) -> None:
        if not hasattr(self, "telemetry_rail"):
            return
        self.telemetry_rail_visible = not self.telemetry_rail_visible
        if self.telemetry_rail_visible:
            self.telemetry_rail.grid()
            self.root_container.columnconfigure(2, minsize=self._scaled(285), weight=0)
            self.telemetry_rail_text.set("Hide Telemetry")
        else:
            self.telemetry_rail.grid_remove()
            self.root_container.columnconfigure(2, minsize=0, weight=0)
            self.telemetry_rail_text.set("Show Telemetry")

    def focus_command_search(self) -> None:
        if hasattr(self, "validation_tab"):
            self._select_workspace(self.validation_tab)
        if hasattr(self, "command_search_entry"):
            self.command_search_entry.focus_set()
            self.command_search_entry.selection_range(0, "end")

    def _command_palette_items(self) -> list[PaletteItem]:
        return [
            PaletteItem("Dashboard", "Navigate", "Main status and control center", lambda: self._select_workspace(self.dashboard_tab)),
            PaletteItem("Proxy", "Navigate", "Page and fingerprint browser verification", lambda: self._select_workspace(self.browser_tab)),
            PaletteItem("Profiles & DNS", "Navigate", "Profile generation and DNS diagnostics", lambda: self._select_workspace(self.profiles_tab)),
            PaletteItem("Routing", "Navigate", "Local validation and routing checks", lambda: self._select_workspace(self.validation_tab)),
            PaletteItem("Logs & Health", "Navigate", "Redacted support and environment reports", lambda: self._select_workspace(self.health_tab)),
            PaletteItem("Settings", "Navigate", "Local repair and optional installers", lambda: self._select_workspace(self.fixes_tab)),
            PaletteItem("Getting Started", "Navigate", "Guided setup and recovery checklist", lambda: self._select_workspace(self.start_tab)),
            PaletteItem("Smart Tips", "Action", "Local advisor: profiles, lab, next commands", self.run_show_smart_tips),
            PaletteItem("Certificates", "Navigate", "Local CA status, generation, and trust docs", lambda: self._select_workspace(self.certs_tab)),
            PaletteItem("About", "Navigate", "Open local repository guides", lambda: self._select_workspace(self.docs_tab)),
            PaletteItem("Best Next Action", "Action", "Run the app-selected safest next command", self.run_primary_action),
            PaletteItem("Check Setup", "Action", "Run the beginner-safe validation sequence", self.run_beginner_setup_check),
            PaletteItem("Start Core", "Action", "Launch bundled Xray when no external core is listening", self.connect_xray),
            PaletteItem("Stop App Core", "Action", "Stop only the Xray process launched by this app", self.disconnect_xray),
            PaletteItem("Run Page Check", "Action", "Verify browser loading through the local proxy", self.run_browser_diagnostics),
            PaletteItem("Run Health Probe", "Action", "Create redacted local health output", self.run_health_probe),
            PaletteItem("Repair Setup", "Repair", "Regenerate and validate derived local files", self.safe_auto_fix),
            PaletteItem("Download Xray Core", "Repair", "Download bundled Xray Core runtime files", self.download_xray),
            PaletteItem("Install Page Check Tools", "Repair", "Install browser diagnostics dependencies", self.install_diagnostics_dependencies),
            PaletteItem("Generate Local CA", "Certificates", "Create local certificate and key files", self.generate_ca),
            PaletteItem("Certificate Status", "Certificates", "Inspect local CA files", self.cert_status),
            PaletteItem("Run Full Status", "Telemetry", "Record and print a local status snapshot", self.run_status_snapshot),
            PaletteItem("Show Activity", "Telemetry", "Print recent local GUI activity", self.show_telemetry_summary),
            PaletteItem("Copy Issue Summary", "Support", "Copy a redacted local issue summary", self.copy_issue_summary),
            PaletteItem("Show Logs", "View", "Open or close the log drawer", self.toggle_output_drawer),
            PaletteItem("Focus Mode", "View", "Hide or show the left navigation rail", self.toggle_focus_mode),
            PaletteItem("Telemetry Rail", "View", "Hide or show the right telemetry rail", self.toggle_telemetry_rail),
            PaletteItem("Checks Search", "View", "Jump to validation command filtering", self.focus_command_search),
            PaletteItem("Keyboard Shortcuts", "Help", "Open shortcut reference", lambda: self.show_help_topic("keyboard_shortcuts")),
            PaletteItem("Open GUI Guide", "Docs", "Open docs/gui.md", lambda: self.open_path(ROOT / "docs" / "gui.md")),
            PaletteItem("Open Troubleshooting Docs", "Docs", "Open preflight and diagnostics guide", lambda: self.open_path(ROOT / "docs" / "preflight-and-diagnostics.md")),
            PaletteItem("Open Browser Guide", "Docs", "Open Chromium integration guide", lambda: self.open_path(ROOT / "docs" / "chromium-integration.md")),
        ]

    def show_command_palette(self) -> None:
        existing = getattr(self, "palette_window", None)
        if existing is not None and existing.winfo_exists():
            existing.lift()
            existing.focus_force()
            if hasattr(self, "palette_entry"):
                self.palette_entry.focus_set()
                self.palette_entry.selection_range(0, "end")
            return

        window = tk.Toplevel(self)
        self.palette_window = window
        window.title("Find Action")
        window.configure(bg=COLORS["bg"])
        window.geometry(f"{self._scaled(620)}x{self._scaled(520)}")
        window.minsize(self._scaled(500), self._scaled(380))
        window.transient(self)
        window.grab_set()

        trace_id: str | None = None

        def close_palette() -> None:
            nonlocal trace_id
            if trace_id is not None:
                try:
                    self.palette_query.trace_remove("write", trace_id)
                except tk.TclError:
                    pass
                trace_id = None
            if window.winfo_exists():
                window.destroy()

        header = tk.Frame(window, bg=COLORS["bg"])
        header.pack(fill="x", padx=self._scaled(18), pady=(self._scaled(16), self._scaled(8)))
        tk.Label(header, text="Find Action", bg=COLORS["bg"], fg=COLORS["ink"], font=self.fonts["h1"], anchor="w").pack(side="left", fill="x", expand=True)
        ttk.Button(header, text="Help", style="Soft.TButton", command=lambda: self.show_help_topic("command_palette")).pack(side="right", padx=(self._scaled(8), 0))
        ttk.Button(header, text="Close", style="Soft.TButton", command=close_palette).pack(side="right")

        body = tk.Frame(window, bg=COLORS["panel"], highlightbackground=COLORS["line"], highlightthickness=1)
        body.pack(fill="both", expand=True, padx=self._scaled(18), pady=(0, self._scaled(18)))
        tk.Label(body, text="Search screens, checks, repairs, docs, and view controls", bg=COLORS["panel"], fg=COLORS["muted"], font=self.fonts["caption_bold"], anchor="w").pack(fill="x", padx=14, pady=(12, 4))
        self.palette_query.set("")
        entry = ttk.Entry(body, textvariable=self.palette_query)
        self.palette_entry = entry
        entry.pack(fill="x", padx=14, pady=(0, 10))

        list_frame = tk.Frame(body, bg=COLORS["panel"])
        list_frame.pack(fill="both", expand=True, padx=14, pady=(0, 8))
        results = tk.Listbox(
            list_frame,
            activestyle="dotbox",
            bg="#ffffff",
            fg=COLORS["ink"],
            selectbackground=COLORS["blue"],
            selectforeground="#ffffff",
            highlightthickness=1,
            highlightbackground=COLORS["line"],
            relief="flat",
            font=self.fonts["body"],
            height=12,
        )
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=results.yview)
        results.configure(yscrollcommand=scrollbar.set)
        results.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        tk.Label(body, text="Enter runs the selected action. Esc closes this window.", bg=COLORS["panel"], fg=COLORS["muted"], font=self.fonts["caption"], anchor="w").pack(fill="x", padx=14, pady=(0, 12))

        filtered: list[PaletteItem] = []

        def render(*_args: object) -> None:
            nonlocal filtered
            if not results.winfo_exists():
                return
            query = self.palette_query.get().strip().lower()
            items = self._command_palette_items()
            if query:
                items = [
                    item
                    for item in items
                    if query in item.label.lower() or query in item.group.lower() or query in item.detail.lower()
                ]
            filtered = items[:80]
            results.delete(0, "end")
            if not filtered:
                results.insert("end", "No matching actions")
                results.configure(state="disabled")
                return
            results.configure(state="normal")
            for item in filtered:
                results.insert("end", f"{item.label}    [{item.group}]  {item.detail}")
            results.selection_set(0)
            results.activate(0)

        def run_selected(_event: tk.Event | None = None) -> str:
            if not filtered:
                return "break"
            selection = results.curselection()
            index = selection[0] if selection else 0
            item = filtered[index]
            close_palette()
            item.action()
            return "break"

        def move(delta: int) -> str:
            if not filtered:
                return "break"
            current = results.curselection()
            index = current[0] if current else 0
            index = max(0, min(len(filtered) - 1, index + delta))
            results.selection_clear(0, "end")
            results.selection_set(index)
            results.activate(index)
            results.see(index)
            return "break"

        trace_id = self.palette_query.trace_add("write", render)
        results.bind("<Double-Button-1>", run_selected)
        window.bind("<Return>", run_selected)
        window.bind("<Escape>", lambda _event: (close_palette(), "break")[-1])
        window.bind("<Down>", lambda _event: move(1))
        window.bind("<Up>", lambda _event: move(-1))
        window.protocol("WM_DELETE_WINDOW", close_palette)
        render()
        entry.focus_set()

    def _current_help_key(self) -> str:
        selected = self.tabs.select() if hasattr(self, "tabs") else ""
        tab_to_key = {
            str(self._tab_page(self.dashboard_tab)): "dashboard",
            str(self._tab_page(self.start_tab)): "getting_started",
            str(self._tab_page(self.validation_tab)): "checks",
            str(self._tab_page(self.health_tab)): "health_report",
            str(self._tab_page(self.fixes_tab)): "fix_tools",
            str(self._tab_page(self.profiles_tab)): "profiles_dns",
            str(self._tab_page(self.certs_tab)): "certificates",
            str(self._tab_page(self.browser_tab)): "browser_tests",
            str(self._tab_page(self.docs_tab)): "docs",
        }
        return tab_to_key.get(selected, "dashboard")

    def show_current_help(self) -> None:
        self.show_help_topic(self._current_help_key())

    def show_help_topic(self, key: str) -> None:
        text = self.help_topics.get(key, "No help topic is registered for this item yet.")
        window = tk.Toplevel(self)
        window.title("Help")
        window.configure(bg=COLORS["bg"])
        window.geometry(f"{self._scaled(720)}x{self._scaled(560)}")
        window.minsize(self._scaled(560), self._scaled(390))
        window.transient(self)
        header = tk.Frame(window, bg=COLORS["bg"])
        header.pack(fill="x", padx=self._scaled(18), pady=(self._scaled(16), self._scaled(8)))
        title = text.splitlines()[0] if text else "Help"
        tk.Label(header, text=title, bg=COLORS["bg"], fg=COLORS["ink"], font=self.fonts["h1"], anchor="w").pack(side="left", fill="x", expand=True)
        ttk.Button(header, text="Copy", style="Soft.TButton", command=lambda: self._copy_help_text(text)).pack(side="right", padx=(self._scaled(8), 0))
        ttk.Button(header, text="Close", style="Soft.TButton", command=window.destroy).pack(side="right")
        body = tk.Text(
            window,
            bg=COLORS["panel"],
            fg=COLORS["ink"],
            relief="flat",
            wrap="word",
            font=self.fonts["body"],
            padx=self._scaled(18),
            pady=self._scaled(14),
            spacing1=self._scaled(2),
            spacing3=self._scaled(5),
        )
        body.pack(fill="both", expand=True, padx=self._scaled(18), pady=(0, self._scaled(18)))
        body.tag_configure("title", font=self.fonts["h1"], foreground=COLORS["ink"], spacing3=self._scaled(8))
        body.tag_configure("section", font=self.fonts["body_bold"], foreground=COLORS["blue_dark"], spacing1=self._scaled(8), spacing3=self._scaled(2))
        body.tag_configure("normal", font=self.fonts["body"], foreground=COLORS["ink"], lmargin1=self._scaled(4), lmargin2=self._scaled(4))
        body.tag_configure("list", font=self.fonts["body"], foreground=COLORS["ink"], lmargin1=self._scaled(18), lmargin2=self._scaled(24))
        for index, line in enumerate(text.splitlines()[1:]):
            tag = "normal"
            stripped = line.strip()
            if stripped.endswith(":"):
                tag = "section"
            elif re.match(r"^\d+\.\s+", stripped):
                tag = "list"
            body.insert("end", line + "\n", tag)
        body.configure(state="disabled")

    def _copy_help_text(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)
        self.current_process_label.set("Help copied")

    def _highlight_active_nav(self) -> None:
        if not hasattr(self, "tabs"):
            return
        selected = self.tabs.select()
        tab_to_name = {
            str(self._tab_page(self.dashboard_tab)): "Dashboard",
            str(self._tab_page(self.browser_tab)): "Proxy",
            str(self._tab_page(self.profiles_tab)): "Profiles & DNS",
            str(self._tab_page(self.validation_tab)): "Routing",
            str(self._tab_page(self.health_tab)): "Logs & Health",
            str(self._tab_page(self.fixes_tab)): "Settings",
            str(self._tab_page(self.start_tab)): "Getting Started",
            str(self._tab_page(self.certs_tab)): "Certificates",
            str(self._tab_page(self.docs_tab)): "About",
        }
        active_name = tab_to_name.get(selected)
        if active_name:
            self.screen_title.set(active_name)
        for name, button in self.nav_button_widgets.items():
            is_active = name == active_name
            row, label, icon, rail = button
            row._nav_active = is_active  # type: ignore[attr-defined]
            bg = COLORS["sidebar_active"] if is_active else COLORS["sidebar"]
            fg = COLORS["blue_dark"] if is_active else COLORS["ink_soft"]
            row.configure(bg=bg)
            label.configure(bg=bg, fg=fg)
            icon.configure(bg=bg)
            self._set_icon_color(icon, COLORS["blue"] if is_active else COLORS["muted"])
            rail.configure(bg=COLORS["blue"] if is_active else COLORS["sidebar"])

    def _start_status_loop(self) -> None:
        if self._status_loop_running:
            return
        self._status_loop_running = True
        self.after(STATUS_REFRESH_MS, self._periodic_status_refresh)

    def _periodic_status_refresh(self) -> None:
        if not self._status_loop_running:
            return
        try:
            if not self.is_busy:
                self.refresh_status()
        finally:
            if self._status_loop_running:
                self.after(STATUS_REFRESH_MS, self._periodic_status_refresh)

    def _build_primary_action_bar(self, parent: tk.Widget) -> None:
        bar = tk.Frame(parent, bg=COLORS["panel"], highlightbackground=COLORS["line"], highlightthickness=1)
        bar.pack(fill="x", padx=self._scaled(16), pady=(0, self._scaled(8)))
        accent = tk.Frame(bar, bg=COLORS["blue"], width=self._scaled(4))
        accent.pack(side="left", fill="y")
        text = tk.Frame(bar, bg=COLORS["panel"])
        text.pack(side="left", fill="x", expand=True, padx=self._scaled(12), pady=self._scaled(8))
        tk.Label(text, text="NEXT STEP", bg=COLORS["panel"], fg=COLORS["muted"], font=self.fonts["caption_bold"], anchor="w").pack(fill="x")
        tk.Label(text, textvariable=self.primary_action_detail, bg=COLORS["panel"], fg=COLORS["ink"], font=self.fonts["body_bold"], anchor="w", wraplength=self._scaled(760), justify="left").pack(fill="x", pady=(2, 0))
        self.primary_action_button = tk.Button(
            bar,
            textvariable=self.primary_action_text,
            command=self.run_primary_action,
            bg=COLORS["blue"],
            fg="#ffffff",
            activebackground=COLORS["blue_dark"],
            activeforeground="#ffffff",
            relief="flat",
            padx=self._scaled(12),
            pady=self._scaled(6),
            font=self.fonts["body_bold"],
        )
        self.primary_action_button.pack(side="right", padx=self._scaled(12), pady=self._scaled(8))

    def run_primary_action(self) -> None:
        self._primary_action()

    def _set_primary_action(self, text: str, detail: str, command: Callable[[], None], tone: str = "blue") -> None:
        self.primary_action_text.set(text)
        self.primary_action_detail.set(detail)
        self._primary_action = command
        palette = {
            "blue": (COLORS["blue"], COLORS["blue_dark"]),
            "green": (COLORS["green"], "#15803d"),
            "amber": (COLORS["amber"], "#b45309"),
            "red": (COLORS["red"], "#b91c1c"),
        }.get(tone, (COLORS["blue"], COLORS["blue_dark"]))
        if hasattr(self, "primary_action_button"):
            bg, active = palette
            self.primary_action_button.configure(bg=bg, activebackground=active)

    def _set_readiness_primary_action(self, snapshot: dict[str, object]) -> None:
        action = str(snapshot.get("readiness_next_action") or "Run Check Setup")
        detail = str(snapshot.get("readiness_next_action_detail") or "Run the shared readiness probe.")
        spec = primary_action_spec(action)
        command_map: dict[str, Callable[[], None]] = {
            "browser_tab": lambda: self._select_workspace(self.browser_tab),
            "certificates_tab": lambda: self._select_workspace(self.certs_tab),
            "check_setup": self.run_beginner_setup_check,
            "config_folder": lambda: self.open_path(ROOT / "Xray-config"),
            "download_xray": self.download_xray,
            "generate_ca": self.generate_ca,
            "generate_profiles": self.generate_standard_profiles,
            "health_tab": lambda: self._select_workspace(self.health_tab),
            "install_page_tools": self.install_diagnostics_dependencies,
            "page_check": self.run_browser_diagnostics,
            "start_core": self.connect_xray,
            "smart_tips": self.run_show_smart_tips,
            "getting_started_tab": lambda: self._select_workspace(self.start_tab),
        }
        self._set_primary_action(spec.button, detail, command_map.get(spec.target, self.run_beginner_setup_check), spec.tone)

    def _build_metrics_bar(self, parent: tk.Widget) -> None:
        bar = tk.Frame(parent, bg=COLORS["bg"])
        bar.pack(fill="x", padx=self._scaled(16), pady=(0, self._scaled(8)))
        self.metric_tunnel_label = self._metric_card(bar, "Core", "Checking", COLORS["amber"], compact=True)
        self.metric_down_label = self._metric_card(bar, "Download", "Measuring", COLORS["blue"], compact=True)
        self.metric_up_label = self._metric_card(bar, "Upload", "Measuring", COLORS["green"], compact=True)
        self.metric_stream_label = self._metric_card(bar, "Streams", "0 seen", COLORS["ink"], compact=True)
        self.metric_refresh_label = self._metric_card(bar, "Refresh", "Starting", COLORS["blue"], compact=True)
        self.metric_next_label = self._metric_card(bar, "Next", "Check setup", COLORS["blue"], compact=True)

    def _metric_card(self, parent: tk.Widget, title: str, value: str, color: str, compact: bool = False) -> tk.Label:
        card = tk.Frame(parent, bg=COLORS["panel"], highlightbackground=COLORS["line"], highlightthickness=1)
        card.pack(side="left", fill="x", expand=True, padx=(0, self._scaled(6)))
        accent = tk.Frame(card, bg=color, height=self._scaled(3))
        accent.pack(fill="x")
        tk.Label(card, text=title.upper(), bg=COLORS["panel"], fg=COLORS["muted"], font=self.fonts["caption_bold"], anchor="w").pack(fill="x", padx=self._scaled(9), pady=(self._scaled(5), 0))
        label = tk.Label(card, text=value, bg=COLORS["panel"], fg=color, font=self.fonts["h2"], anchor="w")
        label.pack(fill="x", padx=self._scaled(9), pady=(self._scaled(1), self._scaled(6 if compact else 9)))
        return label

    def _tab(self) -> tk.Frame:
        page = tk.Frame(self.tabs, bg=COLORS["panel"])
        canvas = tk.Canvas(page, bg=COLORS["panel"], highlightthickness=0, borderwidth=0)
        scrollbar = ttk.Scrollbar(page, orient="vertical", command=canvas.yview, style="Vertical.TScrollbar")
        inner = tk.Frame(canvas, bg=COLORS["panel"], padx=self._scaled(18), pady=self._scaled(16))
        window_id = canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        def sync_scroll_region(_event: tk.Event | None = None) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))

        def sync_width(event: tk.Event) -> None:
            canvas.itemconfigure(window_id, width=event.width)

        inner.bind("<Configure>", sync_scroll_region)
        canvas.bind("<Configure>", sync_width)
        self.tab_pages[str(inner)] = page
        self.tab_canvases[str(page)] = canvas
        return inner

    def _tab_page(self, frame: tk.Frame) -> tk.Frame:
        return self.tab_pages.get(str(frame), frame)

    def _route_mousewheel(self, event: tk.Event) -> None:
        if not hasattr(self, "tabs"):
            return
        if isinstance(getattr(event, "widget", None), tk.Text):
            widget = event.widget
            if event.num == 4:
                widget.yview_scroll(-3, "units")
            elif event.num == 5:
                widget.yview_scroll(3, "units")
            else:
                delta = int(-1 * (event.delta / 120)) if event.delta else 0
                if delta:
                    widget.yview_scroll(delta, "units")
            return "break"
        selected = self.tabs.select()
        canvas = self.tab_canvases.get(selected)
        if canvas is None:
            return
        if event.num == 4:
            canvas.yview_scroll(-3, "units")
        elif event.num == 5:
            canvas.yview_scroll(3, "units")
        else:
            delta = int(-1 * (event.delta / 120)) if event.delta else 0
            if delta:
                canvas.yview_scroll(delta, "units")
        return "break"

    def _responsive_grid(self, parent: tk.Widget, widgets: Iterable[tk.Widget], preferred_columns: int, min_cell_width: int = 280, gap: int = 8) -> None:
        items = list(widgets)
        scaled_gap = self._scaled(gap)
        scaled_min = self._scaled(min_cell_width)

        def layout(event: tk.Event | None = None) -> None:
            width = getattr(event, "width", 0) or parent.winfo_width() or (scaled_min * preferred_columns)
            columns = max(1, min(preferred_columns, width // max(1, scaled_min)))
            if getattr(parent, "_responsive_columns", None) == columns:
                return
            setattr(parent, "_responsive_columns", columns)
            for child in items:
                child.grid_forget()
            for column in range(preferred_columns):
                parent.columnconfigure(column, weight=1 if column < columns else 0)
            for index, child in enumerate(items):
                column = index % columns
                child.grid(
                    row=index // columns,
                    column=column,
                    sticky="nsew",
                    padx=(0 if column == 0 else scaled_gap, 0),
                    pady=(0, scaled_gap),
                )

        parent.bind("<Configure>", layout, add="+")
        self.after_idle(layout)

    def _button_grid(
        self,
        parent: tk.Widget,
        specs: Iterable[tuple[str, str, Callable[[], None]]],
        preferred_columns: int = 4,
        min_cell_width: int = 150,
    ) -> list[ttk.Button]:
        buttons: list[ttk.Button] = []
        for text, style, command in specs:
            button = ttk.Button(parent, text=text, style=style, command=command)
            buttons.append(button)
        self._responsive_grid(parent, buttons, preferred_columns=preferred_columns, min_cell_width=min_cell_width)
        return buttons

    def _icon_for_title(self, title: str) -> str:
        key = self._help_key(title)
        if any(word in key for word in ("xray", "core", "runtime", "dependency")):
            return "server"
        if any(word in key for word in ("proxy", "network", "mode")):
            return "network"
        if any(word in key for word in ("dns", "browser", "page", "fingerprint")):
            return "globe"
        if any(word in key for word in ("cert", "trust", "privacy", "private", "health")):
            return "shield"
        if any(word in key for word in ("repair", "install", "tool", "fix")):
            return "wrench"
        if any(word in key for word in ("profile", "route", "alternate")):
            return "route"
        if any(word in key for word in ("log", "activity", "command", "check", "status", "summary")):
            return "list"
        if any(word in key for word in ("doc", "guide", "readme")):
            return "doc"
        if any(word in key for word in ("quick", "action", "next")):
            return "bolt"
        return "info"

    @staticmethod
    def _delegate_geometry(inner: tk.Widget, shell: tk.Widget) -> None:
        for method in (
            "pack", "grid", "place", "pack_forget", "grid_forget",
            "place_forget", "pack_info", "grid_info", "place_info",
        ):
            target = getattr(shell, method, None)
            if target is not None:
                setattr(inner, method, target)

    def _card(self, parent: tk.Widget, title: str) -> tk.Frame:
        shell = tk.Frame(parent, bg=COLORS["shadow"])
        frame = tk.Frame(shell, bg=COLORS["panel"], highlightbackground=COLORS["line"], highlightthickness=1)
        frame.pack(fill="both", expand=True, pady=(0, self._scaled(1)))
        self._delegate_geometry(frame, shell)
        header = tk.Frame(frame, bg=COLORS["panel"])
        header.pack(fill="x", padx=self._scaled(14), pady=(self._scaled(12), self._scaled(6)))
        self._icon_canvas(header, self._icon_for_title(title), COLORS["blue"], 22, COLORS["panel"]).pack(side="left", padx=(0, self._scaled(9)))
        tk.Label(header, text=title, bg=COLORS["panel"], fg=COLORS["ink"], font=self.fonts["h2"], anchor="w").pack(side="left", fill="x", expand=True)
        if self._help_key(title) in self.help_topics:
            ttk.Button(header, text="Help", style="Soft.TButton", command=lambda key=self._help_key(title): self.show_help_topic(key)).pack(side="right")
        tk.Frame(frame, bg=COLORS["line"], height=1).pack(fill="x", padx=self._scaled(14), pady=(0, self._scaled(4)))
        return frame

    def _help_key(self, raw: str) -> str:
        return re.sub(r"_+", "_", "".join(ch.lower() if ch.isalnum() else "_" for ch in raw)).strip("_")

    def _info_strip(self, parent: tk.Widget, title: str, text: str, tone: str = "info") -> tk.Frame:
        palette = {
            "info": (COLORS["blue_soft"], COLORS["blue_ring"], COLORS["blue_dark"]),
            "success": (COLORS["green_soft"], "#bbe9d3", "#0c7a4f"),
            "warning": (COLORS["amber_soft"], "#f3d9a6", COLORS["amber"]),
        }.get(tone, (COLORS["blue_soft"], COLORS["blue_ring"], COLORS["blue_dark"]))
        bg, border, fg = palette
        strip = tk.Frame(parent, bg=bg, highlightbackground=border, highlightthickness=1)
        head = tk.Frame(strip, bg=bg)
        head.pack(fill="x", padx=12, pady=(9, 1))
        self._icon_canvas(head, self._icon_for_title(title), fg, 20, bg).pack(side="left", padx=(0, self._scaled(7)))
        tk.Label(head, text=title, bg=bg, fg=fg, font=self.fonts["body_bold"], anchor="w").pack(side="left", fill="x", expand=True)
        tk.Label(strip, text=text, bg=bg, fg=fg, font=self.fonts["caption"], wraplength=self._scaled(860), justify="left", anchor="w").pack(fill="x", padx=12, pady=(0, 9))
        return strip

    def _step_card(self, parent: tk.Widget, title: str, detail: str, command: Callable[[], None], button: str, style: str, accent: str) -> tk.Frame:
        card = tk.Frame(parent, bg=COLORS["panel"], highlightbackground=COLORS["line"], highlightthickness=1)
        stripe = tk.Frame(card, bg=accent, width=self._scaled(4))
        stripe.pack(side="left", fill="y")
        content = tk.Frame(card, bg=COLORS["panel"])
        content.pack(side="left", fill="both", expand=True)
        header = tk.Frame(content, bg=COLORS["panel"])
        header.pack(fill="x", padx=14, pady=(13, 4))
        self._icon_canvas(header, self._icon_for_title(title), accent, 22, COLORS["panel"]).pack(side="left", padx=(0, self._scaled(8)))
        tk.Label(header, text=title, bg=COLORS["panel"], fg=COLORS["ink"], font=self.fonts["h2"], anchor="w").pack(side="left", fill="x", expand=True)
        if self._help_key(title) in self.help_topics:
            ttk.Button(header, text="Help", style="Soft.TButton", command=lambda key=self._help_key(title): self.show_help_topic(key)).pack(side="right")
        tk.Label(content, text=detail, bg=COLORS["panel"], fg=COLORS["muted"], wraplength=390, justify="left", anchor="nw").pack(fill="x", padx=14, pady=(0, 12))
        ttk.Button(content, text=button, style=style, command=command).pack(anchor="w", padx=14, pady=(0, 16))
        return card

    def _collapsible_panel(
        self,
        parent: tk.Widget,
        title: str,
        summary: str,
        variable: tk.BooleanVar,
        hidden_text: str = "Show advanced options",
        shown_text: str = "Hide advanced options",
    ) -> tuple[tk.Frame, tk.Frame]:
        panel = self._card(parent, title)
        tk.Label(
            panel,
            text=summary,
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            wraplength=self._scaled(860),
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=16, pady=(2, 8))
        toggle_row = tk.Frame(panel, bg=COLORS["panel"])
        toggle_row.pack(fill="x", padx=16, pady=(0, 10))
        toggle = ttk.Checkbutton(toggle_row, text=hidden_text, variable=variable)
        toggle.pack(side="left")
        body = tk.Frame(panel, bg=COLORS["panel"])

        def sync() -> None:
            toggle.configure(text=shown_text if variable.get() else hidden_text)
            if variable.get():
                body.pack(fill="x", padx=16, pady=(0, 16))
            else:
                body.pack_forget()

        toggle.configure(command=sync)
        sync()
        return panel, body

    def _collapsible_section(
        self,
        parent: tk.Widget,
        title: str,
        summary: str,
        variable: tk.BooleanVar,
        hidden_text: str = "Show advanced options",
        shown_text: str = "Hide advanced options",
    ) -> tuple[tk.Frame, tk.Frame]:
        section = tk.Frame(parent, bg=COLORS["panel"])
        head = tk.Frame(section, bg=COLORS["panel"])
        head.pack(fill="x")
        self._icon_canvas(head, self._icon_for_title(title), COLORS["blue"], 18, COLORS["panel"]).pack(side="left", padx=(0, self._scaled(7)))
        tk.Label(head, text=title, bg=COLORS["panel"], fg=COLORS["ink"], font=self.fonts["body_bold"], anchor="w").pack(side="left", fill="x", expand=True)
        tk.Label(
            section,
            text=summary,
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            wraplength=self._scaled(760),
            justify="left",
            anchor="w",
        ).pack(fill="x", pady=(2, 8))
        toggle = ttk.Checkbutton(section, text=hidden_text, variable=variable)
        toggle.pack(anchor="w", pady=(0, 8))
        body = tk.Frame(section, bg=COLORS["panel"])

        def sync() -> None:
            toggle.configure(text=shown_text if variable.get() else hidden_text)
            if variable.get():
                body.pack(fill="x")
            else:
                body.pack_forget()

        toggle.configure(command=sync)
        sync()
        return section, body

    def _form_row(self, parent: tk.Widget, label: str, variable: tk.StringVar) -> None:
        row = tk.Frame(parent, bg=COLORS["panel"])
        row.pack(fill="x", padx=16, pady=(4, 6))
        tk.Label(row, text=label, bg=COLORS["panel"], fg=COLORS["muted"], width=12, anchor="w").pack(side="left")
        ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True)

    def _pill_palette(self, tone: str) -> tuple[str, str]:
        return {
            "pass": (COLORS["green_soft"], COLORS["green"]),
            "warn": (COLORS["amber_soft"], COLORS["amber"]),
            "fail": (COLORS["red_soft"], COLORS["red"]),
            "info": (COLORS["blue_soft"], COLORS["blue"]),
            "neutral": (COLORS["panel_soft"], COLORS["muted"]),
        }.get(tone, (COLORS["blue_soft"], COLORS["blue"]))

    def _pill_glyph(self, tone: str) -> str:
        return {"pass": "\u2714", "warn": "\u26a0", "fail": "\u2715", "info": "\u2022", "neutral": "\u2022"}.get(tone, "\u2022")

    def status_pill(self, parent: tk.Widget, text: str, tone: str = "neutral", glyph: bool = True) -> tk.Label:
        bg, fg = self._pill_palette(tone)
        label = tk.Label(
            parent,
            text=(f"{self._pill_glyph(tone)}  {text}" if glyph else text),
            bg=bg, fg=fg, font=self.fonts["micro"],
            padx=self._scaled(9), pady=self._scaled(3), anchor="center",
        )
        label._pill_glyph_on = glyph  # type: ignore[attr-defined]
        return label

    def set_pill(self, label: tk.Label, text: str, tone: str) -> None:
        bg, fg = self._pill_palette(tone)
        show_glyph = bool(getattr(label, "_pill_glyph_on", True))
        label.configure(
            text=(f"{self._pill_glyph(tone)}  {text}" if show_glyph else text),
            bg=bg, fg=fg,
        )

    def _status_chip(self, parent: tk.Widget, name: str) -> tk.Label:
        box = tk.Frame(parent, bg=COLORS["panel_alt"], highlightbackground=COLORS["line"], highlightthickness=1)
        box.pack(side="left", fill="x", expand=True, padx=(0, 8))
        tk.Label(box, text=name, bg=COLORS["panel_alt"], fg=COLORS["muted"], font=self.fonts["caption"], anchor="w").pack(fill="x", padx=10, pady=(8, 1))
        label = tk.Label(box, text="Checking", bg=COLORS["panel_alt"], fg=COLORS["amber"], font=self.fonts["body_bold"], anchor="w")
        label.pack(fill="x", padx=10, pady=(0, 8))
        self.status_chip_labels[name] = label
        return label

    def _traffic_summary_item(self, parent: tk.Widget, key: str, title: str, icon: str) -> tk.Frame:
        item = tk.Frame(parent, bg=COLORS["panel_alt"], highlightbackground=COLORS["line"], highlightthickness=1)
        head = tk.Frame(item, bg=COLORS["panel_alt"])
        head.pack(fill="x", padx=10, pady=(8, 0))
        self._icon_canvas(head, icon, COLORS["blue"], 18, COLORS["panel_alt"]).pack(side="left", padx=(0, self._scaled(7)))
        tk.Label(head, text=title, bg=COLORS["panel_alt"], fg=COLORS["muted"], font=self.fonts["caption_bold"], anchor="w").pack(side="left", fill="x", expand=True)
        value = tk.Label(item, text="Checking", bg=COLORS["panel_alt"], fg=COLORS["ink"], font=self.fonts["body_bold"], anchor="w", wraplength=self._scaled(210), justify="left")
        value.pack(fill="x", padx=10, pady=(3, 0))
        detail = tk.Label(item, text="", bg=COLORS["panel_alt"], fg=COLORS["muted"], font=self.fonts["caption"], anchor="w", wraplength=self._scaled(210), justify="left")
        detail.pack(fill="x", padx=10, pady=(2, 9))
        self.traffic_summary_labels[key] = (value, detail)
        return item

    def _set_traffic_summary(self, key: str, value: str, detail: str, level: str) -> None:
        labels = self.traffic_summary_labels.get(key)
        if not labels:
            return
        value_label, detail_label = labels
        color = {"pass": COLORS["green"], "warn": COLORS["amber"], "fail": COLORS["red"], "info": COLORS["blue"]}.get(level, COLORS["ink"])
        value_label.configure(text=value, fg=color)
        detail_label.configure(text=detail)

    def _icon_canvas(self, parent: tk.Widget, kind: str, color: str, size: int = 32, bg: str | None = None) -> tk.Canvas:
        scaled = self._scaled(size)
        canvas = tk.Canvas(parent, width=scaled, height=scaled, bg=bg or COLORS["panel"], highlightthickness=0, borderwidth=0)
        s = scaled
        c = color
        if kind == "shield_globe":
            canvas.create_polygon(s * 0.5, s * 0.05, s * 0.88, s * 0.20, s * 0.80, s * 0.70, s * 0.5, s * 0.94, s * 0.20, s * 0.70, s * 0.12, s * 0.20, fill=c, outline=c)
            canvas.create_oval(s * 0.27, s * 0.25, s * 0.73, s * 0.71, outline="#ffffff", width=max(1, self._scaled(2)))
            canvas.create_line(s * 0.29, s * 0.48, s * 0.71, s * 0.48, fill="#ffffff", width=max(1, self._scaled(1)))
            canvas.create_arc(s * 0.38, s * 0.25, s * 0.62, s * 0.71, start=90, extent=180, outline="#ffffff", width=max(1, self._scaled(1)))
            canvas.create_arc(s * 0.38, s * 0.25, s * 0.62, s * 0.71, start=270, extent=180, outline="#ffffff", width=max(1, self._scaled(1)))
        elif kind == "shield":
            canvas.create_polygon(s * 0.5, s * 0.08, s * 0.86, s * 0.22, s * 0.78, s * 0.70, s * 0.5, s * 0.92, s * 0.22, s * 0.70, s * 0.14, s * 0.22, fill="", outline=c, width=max(2, self._scaled(2)))
            canvas.create_line(s * 0.32, s * 0.50, s * 0.45, s * 0.63, s * 0.68, s * 0.35, fill=c, width=max(2, self._scaled(2)), capstyle="round", joinstyle="round")
        elif kind == "grid":
            for x in (0.18, 0.52):
                for y in (0.18, 0.52):
                    canvas.create_rectangle(s * x, s * y, s * (x + 0.24), s * (y + 0.24), outline=c, width=max(2, self._scaled(2)))
        elif kind == "globe":
            canvas.create_oval(s * 0.12, s * 0.12, s * 0.88, s * 0.88, outline=c, width=max(2, self._scaled(2)))
            canvas.create_line(s * 0.12, s * 0.5, s * 0.88, s * 0.5, fill=c, width=max(1, self._scaled(1)))
            canvas.create_arc(s * 0.30, s * 0.12, s * 0.70, s * 0.88, start=90, extent=180, outline=c, width=max(1, self._scaled(1)))
            canvas.create_arc(s * 0.30, s * 0.12, s * 0.70, s * 0.88, start=270, extent=180, outline=c, width=max(1, self._scaled(1)))
        elif kind == "doc":
            canvas.create_polygon(s * 0.24, s * 0.12, s * 0.62, s * 0.12, s * 0.78, s * 0.28, s * 0.78, s * 0.88, s * 0.24, s * 0.88, fill="", outline=c, width=max(2, self._scaled(2)))
            canvas.create_line(s * 0.62, s * 0.12, s * 0.62, s * 0.30, s * 0.78, s * 0.30, fill=c, width=max(2, self._scaled(2)))
            for y in (0.44, 0.58, 0.72):
                canvas.create_line(s * 0.34, s * y, s * 0.68, s * y, fill=c, width=max(1, self._scaled(1)))
        elif kind == "list":
            for y in (0.25, 0.50, 0.75):
                canvas.create_oval(s * 0.16, s * (y - 0.035), s * 0.23, s * (y + 0.035), fill=c, outline=c)
                canvas.create_line(s * 0.34, s * y, s * 0.84, s * y, fill=c, width=max(2, self._scaled(2)))
        elif kind == "route":
            canvas.create_line(s * 0.20, s * 0.30, s * 0.72, s * 0.30, s * 0.58, s * 0.18, fill=c, width=max(2, self._scaled(2)), capstyle="round", joinstyle="round")
            canvas.create_line(s * 0.72, s * 0.30, s * 0.58, s * 0.42, fill=c, width=max(2, self._scaled(2)), capstyle="round")
            canvas.create_line(s * 0.80, s * 0.70, s * 0.28, s * 0.70, s * 0.42, s * 0.58, fill=c, width=max(2, self._scaled(2)), capstyle="round", joinstyle="round")
            canvas.create_line(s * 0.28, s * 0.70, s * 0.42, s * 0.82, fill=c, width=max(2, self._scaled(2)), capstyle="round")
        elif kind == "server":
            for y in (0.18, 0.42, 0.66):
                canvas.create_rectangle(s * 0.18, s * y, s * 0.82, s * (y + 0.16), outline=c, width=max(2, self._scaled(2)))
                canvas.create_oval(s * 0.68, s * (y + 0.055), s * 0.73, s * (y + 0.105), fill=c, outline=c)
        elif kind == "network":
            nodes = ((0.5, 0.18), (0.22, 0.72), (0.78, 0.72))
            canvas.create_line(s * 0.5, s * 0.32, s * 0.22, s * 0.58, fill=c, width=max(2, self._scaled(2)))
            canvas.create_line(s * 0.5, s * 0.32, s * 0.78, s * 0.58, fill=c, width=max(2, self._scaled(2)))
            canvas.create_line(s * 0.22, s * 0.72, s * 0.78, s * 0.72, fill=c, width=max(2, self._scaled(2)))
            for x, y in nodes:
                canvas.create_rectangle(s * (x - 0.09), s * (y - 0.09), s * (x + 0.09), s * (y + 0.09), outline=c, width=max(2, self._scaled(2)))
        elif kind == "bolt":
            canvas.create_polygon(s * 0.56, s * 0.08, s * 0.24, s * 0.56, s * 0.48, s * 0.56, s * 0.38, s * 0.92, s * 0.76, s * 0.42, s * 0.52, s * 0.42, fill=c, outline=c)
        elif kind == "gear":
            canvas.create_oval(s * 0.26, s * 0.26, s * 0.74, s * 0.74, outline=c, width=max(2, self._scaled(2)))
            canvas.create_oval(s * 0.43, s * 0.43, s * 0.57, s * 0.57, outline=c, width=max(2, self._scaled(2)))
            for x1, y1, x2, y2 in ((0.50, 0.08, 0.50, 0.22), (0.50, 0.78, 0.50, 0.92), (0.08, 0.50, 0.22, 0.50), (0.78, 0.50, 0.92, 0.50), (0.20, 0.20, 0.30, 0.30), (0.80, 0.20, 0.70, 0.30), (0.20, 0.80, 0.30, 0.70), (0.80, 0.80, 0.70, 0.70)):
                canvas.create_line(s * x1, s * y1, s * x2, s * y2, fill=c, width=max(2, self._scaled(2)), capstyle="round")
        elif kind == "wrench":
            canvas.create_line(s * 0.25, s * 0.76, s * 0.66, s * 0.35, fill=c, width=max(3, self._scaled(3)), capstyle="round")
            canvas.create_arc(s * 0.52, s * 0.10, s * 0.88, s * 0.46, start=35, extent=250, outline=c, width=max(2, self._scaled(2)))
            canvas.create_oval(s * 0.18, s * 0.70, s * 0.32, s * 0.84, outline=c, width=max(2, self._scaled(2)))
        elif kind == "info":
            canvas.create_oval(s * 0.16, s * 0.16, s * 0.84, s * 0.84, outline=c, width=max(2, self._scaled(2)))
            canvas.create_line(s * 0.50, s * 0.44, s * 0.50, s * 0.68, fill=c, width=max(2, self._scaled(2)), capstyle="round")
            canvas.create_oval(s * 0.47, s * 0.30, s * 0.53, s * 0.36, fill=c, outline=c)
        elif kind == "xray":
            canvas.create_polygon(s * 0.18, s * 0.24, s * 0.36, s * 0.24, s * 0.50, s * 0.42, s * 0.64, s * 0.24, s * 0.82, s * 0.24, s * 0.58, s * 0.54, s * 0.82, s * 0.84, s * 0.64, s * 0.84, s * 0.50, s * 0.66, s * 0.36, s * 0.84, s * 0.18, s * 0.84, s * 0.42, s * 0.54, fill=c, outline=c)
        else:
            canvas.create_oval(s * 0.18, s * 0.18, s * 0.82, s * 0.82, outline=c, width=max(2, self._scaled(2)))
            canvas.create_line(s * 0.5, s * 0.3, s * 0.5, s * 0.54, fill=c, width=max(2, self._scaled(2)))
            canvas.create_line(s * 0.5, s * 0.54, s * 0.66, s * 0.66, fill=c, width=max(2, self._scaled(2)))
        for item in canvas.find_all():
            try:
                fill = canvas.itemcget(item, "fill")
            except tk.TclError:
                fill = ""
            try:
                outline = canvas.itemcget(item, "outline")
            except tk.TclError:
                outline = ""
            if fill == c:
                canvas.addtag_withtag("icon_fill", item)
            if outline == c:
                canvas.addtag_withtag("icon_outline", item)
        return canvas

    def _set_icon_color(self, canvas: tk.Canvas, color: str) -> None:
        try:
            canvas.itemconfigure("icon_fill", fill=color)
            canvas.itemconfigure("icon_outline", outline=color)
        except tk.TclError:
            pass

    def _dashboard_stat_card(self, parent: tk.Widget, key: str, title: str, value: str, tone: str = "blue", icon: str = "shield") -> tk.Frame:
        card = tk.Frame(parent, bg=COLORS["panel"])
        body = tk.Frame(card, bg=COLORS["panel"])
        body.pack(side="left", fill="both", expand=True, padx=self._scaled(12), pady=self._scaled(11))
        icon_widget = self._icon_canvas(body, icon, COLORS[tone] if tone in COLORS else COLORS["blue"], 30, COLORS["panel"])
        icon_widget.pack(side="left", padx=(0, self._scaled(9)), anchor="n", pady=(self._scaled(1), 0))
        text = tk.Frame(body, bg=COLORS["panel"])
        text.pack(side="left", fill="both", expand=True)
        title_label = tk.Label(text, text=title.upper(), bg=COLORS["panel"], fg=COLORS["muted"], font=self.fonts["micro"], anchor="w")
        title_label.pack(fill="x")
        value_label = tk.Label(text, text=value, bg=COLORS["panel"], fg=COLORS[tone] if tone in COLORS else COLORS["blue"], font=self.fonts["h3"], anchor="w", wraplength=self._scaled(150), justify="left")
        value_label.pack(fill="x", pady=(self._scaled(2), 0))
        value_label.bind(
            "<Configure>",
            lambda event, lbl=value_label: lbl.configure(wraplength=max(self._scaled(72), event.width - self._scaled(2))),
            add="+",
        )
        tk.Frame(card, bg=COLORS["line"], width=1).pack(side="right", fill="y", pady=self._scaled(11))
        self.dashboard_stat_labels[key] = (title_label, value_label, icon_widget)
        return card

    def _set_dashboard_stat(self, key: str, title: str, value: str, level: str) -> None:
        labels = self.dashboard_stat_labels.get(key)
        if not labels:
            return
        title_label, value_label, icon_widget = labels
        color = {"pass": COLORS["green"], "warn": COLORS["amber"], "fail": COLORS["red"], "info": COLORS["blue"]}.get(level, COLORS["muted"])
        title_label.configure(text=title.upper())
        value_label.configure(text=value, fg=color)
        self._set_icon_color(icon_widget, color)

    def _mode_item(self, parent: tk.Widget, key: str, title: str, detail: str) -> tk.Frame:
        item = tk.Frame(parent, bg=COLORS["panel_alt"], highlightbackground=COLORS["line"], highlightthickness=1)
        top = tk.Frame(item, bg=COLORS["panel_alt"])
        top.pack(fill="x", padx=10, pady=(8, 2))
        self._icon_canvas(top, self._icon_for_title(title), COLORS["blue"], 18, COLORS["panel_alt"]).pack(side="left", padx=(0, self._scaled(7)))
        tk.Label(top, text=title, bg=COLORS["panel_alt"], fg=COLORS["ink"], font=self.fonts["body_bold"], anchor="w").pack(side="left", fill="x", expand=True)
        status = tk.Label(top, text="Checking", bg=COLORS["amber_soft"], fg=COLORS["amber"], font=self.fonts["caption_bold"], padx=8, pady=3)
        status.pack(side="right")
        detail_label = tk.Label(item, text=detail, bg=COLORS["panel_alt"], fg=COLORS["muted"], font=self.fonts["caption"], wraplength=self._scaled(290), justify="left", anchor="nw")
        detail_label.pack(fill="x", padx=10, pady=(0, 8))
        self.network_mode_labels[key] = (status, detail_label)
        return item

    def _set_mode_item(self, key: str, status: str, detail: str, level: str) -> None:
        labels = self.network_mode_labels.get(key)
        if not labels:
            return
        status_label, detail_label = labels
        bg = {"pass": COLORS["green_soft"], "warn": COLORS["amber_soft"], "fail": COLORS["red_soft"], "info": COLORS["blue_soft"]}.get(level, COLORS["panel_soft"])
        fg = {"pass": COLORS["green"], "warn": COLORS["amber"], "fail": COLORS["red"], "info": COLORS["blue"]}.get(level, COLORS["muted"])
        status_label.configure(text=status, bg=bg, fg=fg)
        detail_label.configure(text=detail)

    def _readiness_item(self, parent: tk.Widget, key: str, title: str, detail: str) -> tk.Frame:
        item = tk.Frame(parent, bg=COLORS["panel"])
        self._icon_canvas(item, self._icon_for_title(title), COLORS["muted"], 18, COLORS["panel"]).pack(side="left", padx=(self._scaled(4), self._scaled(7)), pady=self._scaled(6))
        text = tk.Frame(item, bg=COLORS["panel"])
        text.pack(side="left", fill="both", expand=True, pady=self._scaled(5))
        row = tk.Frame(text, bg=COLORS["panel"])
        row.pack(fill="x")
        tk.Label(row, text=title, bg=COLORS["panel"], fg=COLORS["ink"], font=self.fonts["caption_bold"], anchor="w").pack(side="left")
        status = tk.Label(row, text="Checking", bg=COLORS["panel"], fg=COLORS["amber"], font=self.fonts["caption_bold"], padx=4)
        status.pack(side="left", padx=(self._scaled(6), 0))
        detail_label = tk.Label(text, text=detail, bg=COLORS["panel"], fg=COLORS["muted"], font=self.fonts["caption"], wraplength=self._scaled(210), justify="left", anchor="nw")
        detail_label.pack(fill="x")
        self.readiness_labels[key] = (status, detail_label)
        return item

    def _preflight_item(self, parent: tk.Widget, key: str, title: str, detail: str) -> tk.Frame:
        item = tk.Frame(parent, bg=COLORS["panel"])
        self._icon_canvas(item, self._icon_for_title(title), COLORS["muted"], 18, COLORS["panel"]).pack(side="left", padx=(self._scaled(4), self._scaled(7)), pady=self._scaled(6))
        text = tk.Frame(item, bg=COLORS["panel"])
        text.pack(side="left", fill="both", expand=True, pady=self._scaled(5))
        row = tk.Frame(text, bg=COLORS["panel"])
        row.pack(fill="x")
        tk.Label(row, text=title, bg=COLORS["panel"], fg=COLORS["ink"], font=self.fonts["caption_bold"], anchor="w").pack(side="left")
        status = tk.Label(row, text="Checking", bg=COLORS["panel"], fg=COLORS["amber"], font=self.fonts["caption_bold"], padx=4)
        status.pack(side="left", padx=(self._scaled(6), 0))
        detail_label = tk.Label(text, text=detail, bg=COLORS["panel"], fg=COLORS["muted"], font=self.fonts["caption"], wraplength=self._scaled(210), justify="left", anchor="nw")
        detail_label.pack(fill="x")
        self.preflight_labels[key] = (status, detail_label)
        return item

    def _set_preflight_item(self, key: str, status: str, detail: str, level: str) -> None:
        labels = self.preflight_labels.get(key)
        if not labels:
            return
        status_label, detail_label = labels
        fg = {"pass": COLORS["green"], "warn": COLORS["amber"], "fail": COLORS["red"], "info": COLORS["blue"]}.get(level, COLORS["muted"])
        status_label.configure(text=status, bg=COLORS["panel"], fg=fg)
        detail_label.configure(text=detail)

    def _runtime_item(self, parent: tk.Widget, key: str, title: str, detail: str) -> tk.Frame:
        item = tk.Frame(parent, bg=COLORS["panel_alt"], highlightbackground=COLORS["line"], highlightthickness=1)
        top = tk.Frame(item, bg=COLORS["panel_alt"])
        top.pack(fill="x", padx=10, pady=(7, 2))
        self._icon_canvas(top, self._icon_for_title(title), COLORS["blue"], 18, COLORS["panel_alt"]).pack(side="left", padx=(0, self._scaled(7)))
        tk.Label(top, text=title, bg=COLORS["panel_alt"], fg=COLORS["ink"], font=self.fonts["body_bold"], anchor="w").pack(side="left", fill="x", expand=True)
        status = tk.Label(top, text="Checking", bg=COLORS["amber_soft"], fg=COLORS["amber"], font=self.fonts["caption_bold"], padx=8, pady=3)
        status.pack(side="right")
        detail_label = tk.Label(item, text=detail, bg=COLORS["panel_alt"], fg=COLORS["muted"], font=self.fonts["caption"], wraplength=self._scaled(270), justify="left", anchor="nw")
        detail_label.pack(fill="x", padx=10, pady=(0, 7))
        self.runtime_labels.setdefault(key, []).append((status, detail_label))
        return item

    def _set_runtime_item(self, key: str, status: str, detail: str, level: str) -> None:
        label_sets = self.runtime_labels.get(key)
        if not label_sets:
            return
        bg = {"pass": COLORS["green_soft"], "warn": COLORS["amber_soft"], "fail": COLORS["red_soft"], "info": COLORS["blue_soft"]}.get(level, COLORS["panel_soft"])
        fg = {"pass": COLORS["green"], "warn": COLORS["amber"], "fail": COLORS["red"], "info": COLORS["blue"]}.get(level, COLORS["muted"])
        for status_label, detail_label in label_sets:
            status_label.configure(text=status, bg=bg, fg=fg)
            detail_label.configure(text=detail)

    def _set_readiness_item(self, key: str, status: str, detail: str, level: str) -> None:
        labels = self.readiness_labels.get(key)
        if not labels:
            return
        status_label, detail_label = labels
        fg = {"pass": COLORS["green"], "warn": COLORS["amber"], "fail": COLORS["red"], "info": COLORS["blue"]}.get(level, COLORS["muted"])
        status_label.configure(text=status, bg=COLORS["panel"], fg=fg)
        detail_label.configure(text=detail)

    def _action_tile(self, parent: tk.Widget, title: str, detail: str, button: str, command: Callable[[], None], tone: str = "blue") -> tk.Frame:
        palette = {
            "blue": (COLORS["blue"], COLORS["blue_soft"], COLORS["blue_dark"]),
            "green": (COLORS["green"], COLORS["green_soft"], COLORS["green"]),
            "amber": (COLORS["amber"], COLORS["amber_soft"], COLORS["amber"]),
            "red": (COLORS["red"], COLORS["red_soft"], COLORS["red"]),
        }.get(tone, (COLORS["blue"], COLORS["blue_soft"], COLORS["blue_dark"]))
        accent, soft, fg = palette
        tile = tk.Frame(parent, bg=soft, highlightbackground=COLORS["line"], highlightthickness=1)
        stripe = tk.Frame(tile, bg=accent, width=self._scaled(4))
        stripe.pack(side="left", fill="y")
        body = tk.Frame(tile, bg=soft)
        body.pack(side="left", fill="both", expand=True, padx=12, pady=10)
        top = tk.Frame(body, bg=soft)
        top.pack(fill="x")
        self._icon_canvas(top, self._icon_for_title(title), accent, 20, soft).pack(side="left", padx=(0, self._scaled(7)))
        tk.Label(top, text=title, bg=soft, fg=COLORS["ink"], font=self.fonts["body_bold"], anchor="w").pack(side="left", fill="x", expand=True)
        tk.Label(body, text=detail, bg=soft, fg=COLORS["muted"], font=self.fonts["caption"], wraplength=self._scaled(290), justify="left", anchor="w").pack(fill="x", pady=(2, 8))
        tk.Button(
            body,
            text=button,
            command=command,
            bg=accent,
            fg="#ffffff",
            activebackground=fg,
            activeforeground="#ffffff",
            relief="flat",
            padx=self._scaled(10),
            pady=self._scaled(6),
            font=self.fonts["caption_bold"],
        ).pack(anchor="w")
        return tile

    def _step_circle(self, parent: tk.Widget, number: str, done: bool, active: bool) -> tk.Canvas:
        d = self._scaled(26)
        canvas = tk.Canvas(parent, width=d, height=d, bg=COLORS["panel"], highlightthickness=0, borderwidth=0)
        pad = self._scaled(2)
        if done or active:
            canvas.create_oval(pad, pad, d - pad, d - pad, fill=COLORS["blue"], outline=COLORS["blue"])
            if done:
                canvas.create_line(
                    d * 0.30, d * 0.52, d * 0.44, d * 0.66, d * 0.72, d * 0.34,
                    fill="#ffffff", width=max(2, self._scaled(2)), capstyle="round", joinstyle="round",
                )
            else:
                canvas.create_text(d / 2, d / 2 + self._scaled(1), text=number, fill="#ffffff", font=self.fonts["micro"])
        else:
            canvas.create_oval(pad, pad, d - pad, d - pad, fill=COLORS["panel_soft"], outline=COLORS["line_strong"])
            canvas.create_text(d / 2, d / 2 + self._scaled(1), text=number, fill=COLORS["muted"], font=self.fonts["micro"])
        return canvas

    def _workflow_rail(self, parent: tk.Widget, steps: list[tuple[str, str, str]]) -> tk.Frame:
        rail = tk.Frame(parent, bg=COLORS["panel"])
        for index, (number, title, detail) in enumerate(steps):
            done = index < 2
            active = index == 2
            reached = index <= 2
            if index:
                connector = COLORS["blue_ring"] if index <= 2 else COLORS["line_strong"]
                tk.Frame(rail, bg=connector, height=self._scaled(2), width=self._scaled(42)).pack(
                    side="left", fill="x", expand=True, padx=self._scaled(4), pady=(self._scaled(18), 0)
                )
            item = tk.Frame(rail, bg=COLORS["panel"])
            item.pack(side="left", fill="both", expand=True, padx=self._scaled(2))
            top = tk.Frame(item, bg=COLORS["panel"])
            top.pack(fill="x", pady=(self._scaled(5), self._scaled(4)))
            self._step_circle(top, number, done, active).pack(side="left", padx=(0, self._scaled(9)))
            tk.Label(
                top, text=title, bg=COLORS["panel"],
                fg=COLORS["blue_dark"] if reached else COLORS["muted"],
                font=self.fonts["body_bold"], anchor="w",
            ).pack(side="left", fill="x", expand=True)
            tk.Label(
                item, text=detail, bg=COLORS["panel"], fg=COLORS["muted"],
                font=self.fonts["caption"], wraplength=self._scaled(180),
                justify="left", anchor="nw",
            ).pack(fill="x", padx=(self._scaled(35), 0), pady=(0, self._scaled(4)))
        return rail

    def _build_start_here(self) -> None:
        intro = tk.Label(
            self.start_tab,
            text="Follow the four-step path below. The app can use its bundled Xray Core or an already-open local client such as v2rayN.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            wraplength=900,
            justify="left",
            anchor="w",
        )
        intro.pack(fill="x", pady=(0, 12))
        self._info_strip(
            self.start_tab,
            "Clean first run",
            "Start with setup, create your local CA when needed, connect a core, then test one page. Advanced tools stay out of the way until a check asks for them.",
            "info",
        ).pack(fill="x", pady=(0, 12))

        chooser = self._card(self.start_tab, "Choose your path")
        chooser.pack(fill="x", pady=(0, 14))
        chooser_grid = tk.Frame(chooser, bg=COLORS["panel"])
        chooser_grid.pack(fill="x", padx=16, pady=(6, 16))
        quick_paths = [
            ("New setup", "Start with the smallest safe check set.", "Check Setup", self.run_beginner_setup_check, "blue"),
            ("Core already open", "Use v2rayN/Xray if it already owns the local port.", "Run Page Check", self.run_browser_diagnostics, "green"),
            ("Something failed", "Collect a redacted local health snapshot.", "Run Health Probe", self.run_health_probe, "amber"),
        ]
        path_tiles: list[tk.Frame] = []
        for index, (title, detail, button, command, tone) in enumerate(quick_paths):
            tile = self._action_tile(chooser_grid, title, detail, button, command, tone)
            path_tiles.append(tile)
        self._responsive_grid(chooser_grid, path_tiles, preferred_columns=3, min_cell_width=230)

        runtime = self._card(self.start_tab, "Bundled Xray Core")
        runtime.pack(fill="x", pady=(0, 14))
        tk.Label(
            runtime,
            text="The app looks for a local Xray Core first. If v2rayN or another core is already listening on 127.0.0.1:10808, the app treats it as an external core and will not stop it.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            wraplength=self._scaled(900),
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=16, pady=(4, 10))
        runtime_grid = tk.Frame(runtime, bg=COLORS["panel"])
        runtime_grid.pack(fill="x", padx=12, pady=(0, 14))
        runtime_items = [
            self._runtime_item(runtime_grid, "xray_exe", "Xray executable", "xray/xray.exe or xray/xray"),
            self._runtime_item(runtime_grid, "geoip", "GeoIP data", "xray/geoip.dat"),
            self._runtime_item(runtime_grid, "geosite", "Geosite data", "xray/geosite.dat"),
        ]
        self._responsive_grid(runtime_grid, runtime_items, preferred_columns=3, min_cell_width=220)

        map_card = self._card(self.start_tab, "Setup map")
        map_card.pack(fill="x", pady=(0, 14))
        self._workflow_rail(
            map_card,
            [
                ("1", "Check", "Find missing files, tools, or outdated generated data."),
                ("2", "Create CA", "Generate local cert/key; trust install stays manual."),
                ("3", "Connect", "Start bundled Xray or use your open v2rayN/Xray."),
                ("4", "Verify", "Run a page check, then Health if needed."),
            ],
        ).pack(fill="x", padx=16, pady=(6, 16))

        flow = tk.Frame(self.start_tab, bg=COLORS["panel"])
        flow.pack(fill="x", pady=(0, 14))
        steps = [
            ("1. Check setup", "Runs a small local check set and points out missing files or tools.", self.run_beginner_setup_check, "Check Setup", "Accent.TButton", COLORS["blue"]),
            ("2. Create local CA", "Creates your personal certificate files. Trust installation stays manual.", self.generate_ca, "Generate Local CA", "Warning.TButton", COLORS["amber"]),
            ("3. Start core", "Starts the bundled Xray Core. If v2rayN is already open, the app uses that listener instead.", self.connect_xray, "Start Core", "Accent.TButton", COLORS["green"]),
            ("4. Test a page", "Loads one page through 127.0.0.1:10808 after a core is listening.", self.run_browser_diagnostics, "Run Page Check", "Accent.TButton", COLORS["blue_dark"]),
        ]
        step_cards: list[tk.Frame] = []
        for index, (title, detail, command, button, style, accent) in enumerate(steps):
            card = self._step_card(flow, title, detail, command, button, style, accent)
            step_cards.append(card)
        self._responsive_grid(flow, step_cards, preferred_columns=2, min_cell_width=360, gap=10)

        optional, optional_body = self._collapsible_panel(
            self.start_tab,
            "Optional setup tools",
            "Open this only if a check asks for a missing browser tool, bundled Xray Core, or packaging dependency.",
            self.show_start_advanced,
        )
        optional.pack(fill="x", pady=(0, 14))
        self._button_grid(
            optional_body,
            [
                ("Install Page Check Tools", "Soft.TButton", self.install_diagnostics_dependencies),
                ("Install Fingerprint Tools", "Soft.TButton", self.install_stealth_dependencies),
                ("Download Xray Core", "Soft.TButton", self.download_xray),
                ("Install PyInstaller", "Soft.TButton", self.install_pyinstaller),
            ],
            preferred_columns=4,
            min_cell_width=180,
        )

        help_card = self._card(self.start_tab, "When something fails")
        help_card.pack(fill="x", pady=(0, 14))
        help_text = (
            "Needs Attention usually means the local machine is not fully set up yet: missing CA files, no core listening, a port already active, "
            "or optional browser tools not installed. Blocked means a config or script check needs attention before continuing."
        )
        tk.Label(help_card, text=help_text, bg=COLORS["panel"], fg=COLORS["muted"], wraplength=900, justify="left", anchor="w").pack(fill="x", padx=16, pady=(4, 10))
        row = tk.Frame(help_card, bg=COLORS["panel"])
        row.pack(fill="x", padx=16, pady=(0, 16))
        self._button_grid(
            row,
            [
                ("Smart Tips", "Soft.TButton", self.run_show_smart_tips),
                ("Explain Output", "Soft.TButton", self.explain_output),
                ("Copy Issue Summary", "Soft.TButton", self.copy_issue_summary),
                ("Read Getting Started Guide", "Soft.TButton", lambda: self.open_path(ROOT / "docs" / "getting-started.md")),
                ("Open Troubleshooting Docs", "Soft.TButton", lambda: self.open_path(ROOT / "docs" / "preflight-and-diagnostics.md")),
            ],
            preferred_columns=3,
            min_cell_width=170,
        )

    def _build_dashboard(self) -> None:
        status_row = tk.Frame(self.dashboard_tab, bg=COLORS["panel"], highlightbackground=COLORS["line"], highlightthickness=1)
        status_row.pack(fill="x", pady=(0, 12))
        status_cards = [
            self._dashboard_stat_card(status_row, "system", "System status", "Checking", "amber", "shield"),
            self._dashboard_stat_card(status_row, "core", "Xray Core", "Checking", "blue", "server"),
            self._dashboard_stat_card(status_row, "proxy", "Local proxy", "127.0.0.1:10808", "blue", "network"),
            self._dashboard_stat_card(status_row, "dns", "DNS", "1.1.1.1", "blue", "globe"),
            self._dashboard_stat_card(status_row, "uptime", "Uptime", "0s", "green", "clock"),
        ]
        self._responsive_grid(status_row, status_cards, preferred_columns=5, min_cell_width=155, gap=8)

        newcomer = self._card(self.dashboard_tab, "New here?")
        newcomer.pack(fill="x", pady=(0, 12))
        newcomer_body = tk.Frame(newcomer, bg=COLORS["panel"])
        newcomer_body.pack(fill="x", padx=16, pady=(0, 14))
        tk.Label(
            newcomer_body,
            text="First time? Use Check Setup, create your local CA, start a core, then run one Page Check. "
            "Trust installation stays manual; nothing is uploaded.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            wraplength=self._scaled(880),
            justify="left",
            anchor="w",
        ).pack(fill="x", pady=(0, 10))
        newcomer_actions = tk.Frame(newcomer_body, bg=COLORS["panel"])
        newcomer_actions.pack(fill="x")
        self._button_grid(
            newcomer_actions,
            [
                ("Open Getting Started", "Accent.TButton", lambda: self._select_workspace(self.start_tab)),
                ("Check Setup", "Soft.TButton", self.run_beginner_setup_check),
                ("Smart Tips", "Soft.TButton", self.run_show_smart_tips),
                ("Read Guide", "Soft.TButton", lambda: self.open_path(ROOT / "docs" / "getting-started.md")),
            ],
            preferred_columns=4,
            min_cell_width=160,
        )

        workflow = self._card(self.dashboard_tab, "Setup Workflow")
        workflow.pack(fill="x", pady=(0, 12))
        tk.Label(
            workflow,
            text="Follow the steps below to get MITM DomainFronting running.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            wraplength=self._scaled(880),
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=16, pady=(0, 10))
        self.dashboard_hint_frame = tk.Frame(workflow, bg=COLORS["blue_soft"], highlightbackground=COLORS["line"], highlightthickness=1)
        tk.Label(
            self.dashboard_hint_frame,
            textvariable=self.intelligent_hint_text,
            bg=COLORS["blue_soft"],
            fg=COLORS["blue_dark"],
            font=self.fonts["caption"],
            wraplength=self._scaled(860),
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=12, pady=8)
        self._workflow_rail(
            workflow,
            [
                ("1", "Core", "Install and verify Xray Core."),
                ("2", "Proxy", "Confirm local proxy settings."),
                ("3", "Browser", "Check browser proxy and connectivity."),
                ("4", "Ready", "Start monitoring status."),
            ],
        ).pack(fill="x", padx=16, pady=(2, 14))
        readiness_grid = tk.Frame(workflow, bg=COLORS["panel"])
        readiness_grid.pack(fill="x", padx=12, pady=(0, 14))
        readiness_items = (
            ("config", "Xray Core", "Runtime configuration is present."),
            ("runtime", "Bundled files", "Xray executable and geodata are local."),
            ("cert", "Certificate", "Local CA files exist; trust stays manual."),
            ("listener", "Proxy state", "Selected local listener is checked live."),
            ("fingerprint", "TLS fingerprint", "Configured vs measured (oracle only)."),
        )
        readiness_widgets: list[tk.Frame] = []
        for key, title, item_detail in readiness_items:
            readiness_widgets.append(self._readiness_item(readiness_grid, key, title, item_detail))
        self._responsive_grid(readiness_grid, readiness_widgets, preferred_columns=4, min_cell_width=190, gap=8)

        main = tk.Frame(self.dashboard_tab, bg=COLORS["panel"])
        main.pack(fill="x", pady=(0, 12))

        connection = self._card(main, "Xray Core (bundled)")
        core_visual = tk.Frame(connection, bg=COLORS["panel"])
        core_visual.pack(fill="x", padx=16, pady=(2, 8))
        self._icon_canvas(core_visual, "xray", "#111827", 44, COLORS["panel"]).pack(side="left", padx=(0, 12))
        core_copy = tk.Frame(core_visual, bg=COLORS["panel"])
        core_copy.pack(side="left", fill="x", expand=True)
        tk.Label(core_copy, textvariable=self.core_version_text, bg=COLORS["panel"], fg=COLORS["ink"], font=self.fonts["body_bold"], anchor="w").pack(fill="x")
        tk.Label(core_copy, textvariable=self.local_proxy_text, bg=COLORS["panel"], fg=COLORS["muted"], font=self.fonts["caption"], anchor="w").pack(fill="x", pady=(2, 0))
        runtime_grid = tk.Frame(connection, bg=COLORS["panel"])
        runtime_grid.pack(fill="x", padx=12, pady=(4, 12))
        runtime_items = [
            self._runtime_item(runtime_grid, "xray_exe", "Executable", "xray/xray.exe"),
            self._runtime_item(runtime_grid, "geoip", "GeoIP", "xray/geoip.dat"),
            self._runtime_item(runtime_grid, "geosite", "Geosite", "xray/geosite.dat"),
        ]
        self._responsive_grid(runtime_grid, runtime_items, preferred_columns=3, min_cell_width=135, gap=8)
        conn_row = tk.Frame(connection, bg=COLORS["panel"])
        conn_row.pack(fill="x", padx=16, pady=(0, 16))
        self._button_grid(
            conn_row,
            [
                ("Start Core", "Accent.TButton", self.connect_xray),
                ("Stop App Core", "Danger.TButton", self.disconnect_xray),
                ("Open Config", "Soft.TButton", lambda: self.open_path(ROOT / "Xray-config")),
            ],
            preferred_columns=3,
            min_cell_width=135,
        )
        profile_panel, profile_body = self._collapsible_section(
            connection,
            "Advanced profile",
            "Leave this closed for normal use. Open for strict/balanced/compatibility/debug, alternate ports, or lab evasion profiles.",
            self.show_dashboard_profile,
            hidden_text="Choose a different profile",
            shown_text="Hide profile options",
        )
        profile_panel.pack(fill="x", padx=16, pady=(0, 16))
        profile_row = tk.Frame(profile_body, bg=COLORS["panel"])
        profile_row.pack(fill="x")
        tk.Label(profile_row, text="Profile", bg=COLORS["panel"], fg=COLORS["muted"], width=12, anchor="w").pack(side="left")
        self.profile_box = ttk.Combobox(profile_row, textvariable=self.profile_selection, values=self._profile_choices(), state="readonly")
        self.profile_box.pack(side="left", fill="x", expand=True)
        self.profile_box.bind("<<ComboboxSelected>>", self._select_profile)
        ttk.Button(profile_row, text="Apply Recommended", style="Soft.TButton", command=self.apply_recommended_profile).pack(side="left", padx=(8, 0))

        network_mode = self._card(main, "Proxy Control")
        proxy_head = tk.Frame(network_mode, bg=COLORS["panel"])
        proxy_head.pack(fill="x", padx=16, pady=(2, 10))
        self.proxy_control_status_label = tk.Label(proxy_head, text="Checking", bg=COLORS["amber_soft"], fg=COLORS["amber"], font=self.fonts["caption_bold"], padx=9, pady=4)
        self.proxy_control_status_label.pack(side="right")
        self.connection_label = tk.Label(proxy_head, textvariable=self.connection_state, bg=COLORS["panel"], fg=COLORS["ink"], font=self.fonts["body_bold"], anchor="w")
        self.connection_label.pack(side="left", fill="x", expand=True)
        proxy_buttons = tk.Frame(network_mode, bg=COLORS["panel"])
        proxy_buttons.pack(fill="x", padx=16, pady=(0, 12))
        self._button_grid(
            proxy_buttons,
            [
                ("Start Core", "Accent.TButton", self.connect_xray),
                ("Stop App Core", "Danger.TButton", self.disconnect_xray),
            ],
            preferred_columns=1,
            min_cell_width=240,
        )
        traffic_row = tk.Frame(network_mode, bg=COLORS["panel"])
        traffic_row.pack(fill="x", padx=12, pady=(0, 12))
        traffic_items = [
            self._traffic_summary_item(traffic_row, "browser_path", "Browser proxy", "globe"),
            self._traffic_summary_item(traffic_row, "core_owner", "Owner", "server"),
            self._traffic_summary_item(traffic_row, "system_route", "System proxy", "network"),
            self._traffic_summary_item(traffic_row, "tun_route", "TUN", "route"),
        ]
        self._responsive_grid(traffic_row, traffic_items, preferred_columns=2, min_cell_width=170, gap=8)
        mode_grid = tk.Frame(network_mode, bg=COLORS["panel"])
        mode_grid.pack(fill="x", padx=12, pady=(0, 12))
        mode_items = [
            self._mode_item(mode_grid, "local_proxy", "Local proxy endpoint", "Browser checks use the configured local mixed inbound."),
            self._mode_item(mode_grid, "external_core", "External core ownership", "v2rayN/Xray on the same port is detected and left untouched."),
            self._mode_item(mode_grid, "system_proxy", "System proxy", "Detected for loop warnings; not changed automatically."),
            self._mode_item(mode_grid, "tun", "TUN mode", "Not enabled by the standard config unless a TUN inbound exists."),
        ]
        self._responsive_grid(mode_grid, mode_items, preferred_columns=2, min_cell_width=250)
        mode_actions = tk.Frame(network_mode, bg=COLORS["panel"])
        mode_actions.pack(fill="x", padx=16, pady=(0, 16))
        self._button_grid(
            mode_actions,
            [
                ("Run Page Check", "Accent.TButton", self.run_browser_diagnostics),
                ("Health Probe", "Soft.TButton", self.run_health_probe),
                ("Generate Alt Ports", "Soft.TButton", self.generate_alt_profiles),
                ("Network Help", "Soft.TButton", lambda: self.show_help_topic("network_mode")),
            ],
            preferred_columns=4,
            min_cell_width=150,
        )
        self._responsive_grid(main, [connection, network_mode], preferred_columns=2, min_cell_width=380, gap=10)

        browser = self._card(self.dashboard_tab, "Browser Proxy Check")
        browser.pack(fill="x", pady=(0, 12))
        check_top = tk.Frame(browser, bg=COLORS["panel"])
        check_top.pack(fill="x", padx=16, pady=(0, 8))
        tk.Label(check_top, text="Verifies that your browser is using the proxy and can reach test endpoints.", bg=COLORS["panel"], fg=COLORS["muted"], anchor="w", justify="left", wraplength=self._scaled(680)).pack(side="left", fill="x", expand=True)
        ttk.Button(check_top, text="Run Check", style="Soft.TButton", command=self.run_browser_diagnostics).pack(side="right", padx=(12, 0))
        self._form_row(browser, "Target URL", self.browser_url)
        brow_row = tk.Frame(browser, bg=COLORS["panel"])
        brow_row.pack(fill="x", padx=16, pady=(0, 10))
        self._button_grid(
            brow_row,
            [
                ("Run Page Check", "Accent.TButton", self.run_browser_diagnostics),
                ("Open Browser Guide", "Soft.TButton", lambda: self.open_path(ROOT / "docs" / "chromium-integration.md")),
            ],
            preferred_columns=2,
            min_cell_width=180,
        )
        check_grid = tk.Frame(browser, bg=COLORS["panel"])
        check_grid.pack(fill="x", padx=12, pady=(0, 12))
        for key, title, detail in (
            ("browser_proxy", "Proxy reachable", self.browser_proxy.get().strip() or "127.0.0.1:10808"),
            ("browser_dns", "DNS resolution", self.dns_resolvers.get().strip() or "Default resolvers"),
            ("browser_https", "HTTPS handshake", "TLS handshake through local proxy"),
            ("browser_result", "Browser verified", "Run Check to verify."),
        ):
            self._mode_item(check_grid, key, title, detail)
        self._responsive_grid(check_grid, [child for child in check_grid.winfo_children()], preferred_columns=4, min_cell_width=180, gap=8)
        browser_settings, browser_settings_body = self._collapsible_section(
            browser,
            "Advanced browser settings",
            "The defaults work for most users. Open this for a custom proxy endpoint, a specific Chrome/Edge executable, or reset controls.",
            self.show_dashboard_browser_advanced,
            hidden_text="Show proxy and browser path",
            shown_text="Hide proxy and browser path",
        )
        browser_settings.pack(fill="x", padx=16, pady=(0, 16))
        self._form_row(browser_settings_body, "Proxy", self.browser_proxy)
        path_row = tk.Frame(browser_settings_body, bg=COLORS["panel"])
        path_row.pack(fill="x", pady=(4, 10))
        tk.Label(path_row, text="Browser path", bg=COLORS["panel"], fg=COLORS["muted"], width=12, anchor="w").pack(side="left")
        ttk.Entry(path_row, textvariable=self.browser_executable).pack(side="left", fill="x", expand=True)
        ttk.Button(path_row, text="Browse", style="Soft.TButton", command=self.choose_browser_path).pack(side="left", padx=(8, 0))
        ttk.Button(browser_settings_body, text="Reset Browser Fields", style="Soft.TButton", command=self.reset_gui_defaults).pack(anchor="w")

        fixes = self._card(self.dashboard_tab, "Quick actions")
        fixes.pack(fill="x", pady=(0, 12))
        fix_row = tk.Frame(fixes, bg=COLORS["panel"])
        fix_row.pack(fill="x", padx=16, pady=(8, 16))
        self._button_grid(
            fix_row,
            [
                ("Check Setup", "Accent.TButton", self.run_beginner_setup_check),
                ("Getting Started", "Soft.TButton", lambda: self._select_workspace(self.start_tab)),
                ("Smart Tips", "Soft.TButton", self.run_show_smart_tips),
                ("Repair Setup", "Accent.TButton", self.safe_auto_fix),
                ("Generate Local CA", "Warning.TButton", self.generate_ca),
                ("Copy Issue Summary", "Soft.TButton", self.copy_issue_summary),
            ],
            preferred_columns=3,
            min_cell_width=150,
        )

        summary = self._card(self.dashboard_tab, "Status summary")
        summary.pack(fill="x")
        grid = tk.Frame(summary, bg=COLORS["panel"])
        grid.pack(fill="x", padx=16, pady=(8, 16))
        self.status_labels: dict[str, tk.Label] = {}
        status_boxes: list[tk.Frame] = []
        for index, title in enumerate(("Config", "Certificate", "Profiles", "Health", "Dependencies", "Browser", "Privacy")):
            box = tk.Frame(grid, bg="#f8fafc", highlightbackground=COLORS["line"], highlightthickness=1)
            status_boxes.append(box)
            head = tk.Frame(box, bg="#f8fafc")
            head.pack(fill="x", padx=10, pady=(8, 2))
            self._icon_canvas(head, self._icon_for_title(title), COLORS["blue"], 18, "#f8fafc").pack(side="left", padx=(0, self._scaled(6)))
            tk.Label(head, text=title, bg="#f8fafc", fg=COLORS["ink"], font=("Segoe UI", 10, "bold"), anchor="w").pack(side="left", fill="x", expand=True)
            label = tk.Label(box, text="Checking...", bg="#f8fafc", fg=COLORS["muted"], font=("Segoe UI", 9), justify="left", anchor="nw", wraplength=210)
            label.pack(fill="both", expand=True, padx=10, pady=(0, 8))
            self.status_labels[title] = label
        self._responsive_grid(grid, status_boxes, preferred_columns=4, min_cell_width=210)

    @property
    def validation_commands(self) -> list[CommandSpec]:
        return [
            CommandSpec("Validate Config", "Static validation for primary config.", tuple(py_script("validate_config.py", str(CONFIG)))),
            CommandSpec("Readiness State", "Shared ProjectState probe used by Dashboard and CLI.", tuple(py_script("core/readiness.py", "--config", str(CONFIG), "--cert", str(CERT), "--key", str(KEY), "--json"))),
            CommandSpec("Static Preflight", "Local preflight without cert/runtime/DNS requirements.", tuple(py_script("preflight.py", "--config", str(CONFIG), "--no-dns", "--skip-cert", "--skip-runtime"))),
            CommandSpec("Metadata", "Provider/profile/health metadata checks.", tuple(py_script("validate_metadata.py"))),
            CommandSpec("Route Tests", "Route order, references, and policy tests.", tuple(py_test("route_policy_tests.py"))),
            CommandSpec("Route Rule Linter", "First-match shadow and decrypted-inbound isolation lint.", tuple(py_script("route_rule_linter.py", str(CONFIG)))),
            CommandSpec("Protocol Tests", "Protocol metadata and docs coverage tests.", tuple(py_test("protocol_policy_tests.py"))),
            CommandSpec("Browser Probe Semantics", "Regression tests for browser probe success/failure classification.", tuple(py_test("browser_probe_semantics_test.py"))),
            CommandSpec("Health Policy Tests", "Regression tests for health recommendation behavior.", tuple(py_test("health_policy_tests.py"))),
            CommandSpec("Repository Structure", "Required files and gitignore hygiene checks.", tuple(py_test("repository_structure_tests.py"))),
            CommandSpec("Provider Dossiers", "Provider metadata, route-tag linkage, and rollback/evidence checks.", tuple(py_script("provider_dossier_validate.py"))),
            CommandSpec("Provider Policy", "Typed provider policy schema and freshness validation.", tuple(py_script("provider_policy_validator.py"))),
            CommandSpec("Geodata Pin Verify", "Verifies geodata lock file when present; info-only if absent.", tuple(py_script("geodata_pin.py", "--verify"))),
            CommandSpec("Health Probe", "Redacted health report for ports/cert/trust/dns/providers.", tuple(py_script("health_probe.py", "--config", str(CONFIG), "--cert", str(CERT), "--key", str(KEY), "--providers-dir", str(ROOT / "providers")))),
            CommandSpec("Route Intent Sync", "Compare config ruleTags against configs/route-intent.json.", tuple(py_script("route_intent_sync.py", str(CONFIG)))),
            CommandSpec("Config-src Validate", "Validate config-src manifest and run build-time checks.", tuple(py_script("config_src_validate.py", "--run-steps"))),
            CommandSpec("Config-src Build", "Validate and compile config-src output to build/config/.", tuple(py_script("config_src_build.py"))),
            CommandSpec("Config-src Merge Tests", "Regression tests for structured config merge behavior.", tuple(py_test("config_src_merge_test.py"))),
            CommandSpec("Transport Governance", "Validate transport experiment manifest guardrails.", tuple(py_script("transport_experiment_validate.py"))),
            CommandSpec("DNS Harness Tests", "Regression tests for DNS packet parsing and harness safety.", tuple(py_test("dns_lab_harness_tests.py"))),
            CommandSpec("Lab Evidence Bundle", "Run DNS/fakeDNS/captive and protocol structure probes locally.", tuple(py_script("lab_evidence_run.py", "--allow-warn"))),
            CommandSpec("Secret Scan", "Tracked-file private key scan.", tuple(py_script("secret_scan.py"))),
            CommandSpec(
                "Decision Report",
                "Redacted local decision summary with phase diagnostics.",
                tuple(
                    py_script(
                        "decision_report.py",
                        "--config",
                        str(CONFIG),
                        "--cert",
                        str(CERT),
                        "--key",
                        str(KEY),
                        "--profile",
                        "balanced",
                        "--target",
                        self.dns_domain.get().strip() or "www.google.com",
                        "--provider-family",
                        "unknown",
                        "--json-out",
                        str(LOCAL_STATE / "decision-report.latest.json"),
                    )
                ),
            ),
        ]

    def _build_validation(self) -> None:
        intro = tk.Label(self.validation_tab, text="Run the recommended local checks first. Deeper checks stay hidden until you open advanced options.", bg=COLORS["panel"], fg=COLORS["muted"], anchor="w")
        intro.pack(fill="x", pady=(0, 12))

        search = self._card(self.validation_tab, "Command Search")
        search.pack(fill="x", pady=(0, 10))
        search_body = tk.Frame(search, bg=COLORS["panel"])
        search_body.pack(fill="x", padx=12, pady=(4, 10))
        tk.Label(search_body, text="Filter checks", bg=COLORS["panel"], fg=COLORS["muted"], font=self.fonts["caption_bold"], anchor="w").pack(side="left", padx=(0, 8))
        self.command_search_entry = ttk.Entry(search_body, textvariable=self.command_search)
        self.command_search_entry.pack(side="left", fill="x", expand=True)
        ttk.Button(search_body, text="Clear", style="Soft.TButton", command=lambda: self.command_search.set("")).pack(side="left", padx=(8, 0))
        self.command_search.trace_add("write", lambda *_args: self._render_validation_commands())

        starter_labels = {"Validate Config", "Readiness State", "Static Preflight", "Health Probe", "Secret Scan"}
        self.validation_starter_labels = starter_labels
        self.validation_starter_container = tk.Frame(self.validation_tab, bg=COLORS["panel"])
        self.validation_starter_container.pack(fill="x")

        advanced_panel, advanced_body = self._collapsible_panel(
            self.validation_tab,
            "Extra local checks",
            "These checks are useful when a guide asks for deeper detail. They are local-only, but noisier than the recommended first-pass checks.",
            self.show_validation_advanced,
            hidden_text="Show extra checks",
            shown_text="Hide extra checks",
        )
        advanced_panel.pack(fill="x", pady=(0, 12))
        self.validation_advanced_container = advanced_body
        self._render_validation_commands()

        controls = tk.Frame(self.validation_tab, bg=COLORS["panel"])
        controls.pack(fill="x", pady=(0, 8))
        ttk.Button(controls, text="Clear Output", style="Soft.TButton", command=self.clear_output).pack(side="left")
        ttk.Button(controls, text="Copy Output", style="Soft.TButton", command=self.copy_output).pack(side="left", padx=8)
        tk.Label(controls, text="Output is always visible in the bottom log streams.", bg=COLORS["panel"], fg=COLORS["muted"]).pack(side="left", padx=8)

    def _render_validation_commands(self) -> None:
        if not hasattr(self, "validation_starter_container"):
            return
        for container in (self.validation_starter_container, self.validation_advanced_container):
            for child in container.winfo_children():
                child.destroy()
        query = self.command_search.get().strip().lower()
        specs = self.validation_commands
        if query:
            specs = [spec for spec in specs if query in spec.label.lower() or query in spec.description.lower() or query in " ".join(spec.args).lower()]
        starter_specs = [spec for spec in specs if spec.label in self.validation_starter_labels]
        advanced_specs = [spec for spec in specs if spec.label not in self.validation_starter_labels]
        if starter_specs:
            self._add_command_cards(self.validation_starter_container, starter_specs, columns=2)
        elif query:
            self._empty_state(self.validation_starter_container, "No recommended checks match this search.")
        if advanced_specs:
            self._add_compact_commands(self.validation_advanced_container, advanced_specs)
        elif query:
            self._empty_state(self.validation_advanced_container, "No extra checks match this search.")

    def _add_command_cards(self, parent: tk.Widget, specs: list[CommandSpec], columns: int = 3) -> None:
        button_grid = tk.Frame(parent, bg=COLORS["panel"])
        button_grid.pack(fill="x", pady=(0, 12))
        cards: list[tk.Frame] = []
        for index, spec in enumerate(specs):
            card = self._card(button_grid, spec.label)
            cards.append(card)
            tk.Label(card, text=spec.description, bg=COLORS["panel"], fg=COLORS["muted"], wraplength=self._scaled(260), justify="left").pack(fill="x", padx=12, pady=(2, 10))
            ttk.Button(card, text="Run", style="Accent.TButton", command=lambda s=spec: self.run_spec(s)).pack(anchor="w", padx=12, pady=(0, 12))
        self._responsive_grid(button_grid, cards, preferred_columns=columns, min_cell_width=260)

    def _add_compact_commands(self, parent: tk.Widget, specs: list[CommandSpec]) -> None:
        for spec in specs:
            row = tk.Frame(parent, bg=COLORS["panel_alt"], highlightbackground=COLORS["line"], highlightthickness=1)
            row.pack(fill="x", pady=(0, 6))
            self._icon_canvas(row, self._icon_for_title(spec.label), COLORS["blue"], 22, COLORS["panel_alt"]).pack(side="left", padx=(10, 0), pady=8)
            text = tk.Frame(row, bg=COLORS["panel_alt"])
            text.pack(side="left", fill="x", expand=True, padx=10, pady=7)
            tk.Label(text, text=spec.label, bg=COLORS["panel_alt"], fg=COLORS["ink"], font=self.fonts["body_bold"], anchor="w").pack(fill="x")
            tk.Label(text, text=spec.description, bg=COLORS["panel_alt"], fg=COLORS["muted"], anchor="w", wraplength=self._scaled(680), justify="left").pack(fill="x")
            ttk.Button(row, text="Run", style="Soft.TButton", command=lambda s=spec: self.run_spec(s)).pack(side="right", padx=(8, 10))

    def _empty_state(self, parent: tk.Widget, text: str) -> None:
        row = tk.Frame(parent, bg=COLORS["panel_alt"], highlightbackground=COLORS["line"], highlightthickness=1)
        row.pack(fill="x", pady=(0, 8))
        self._icon_canvas(row, "info", COLORS["muted"], 20, COLORS["panel_alt"]).pack(side="left", padx=(12, 8), pady=9)
        tk.Label(row, text=text, bg=COLORS["panel_alt"], fg=COLORS["muted"], font=self.fonts["caption_bold"], anchor="w", pady=10).pack(side="left", fill="x", expand=True)

    def _build_health(self) -> None:
        intro = tk.Label(
            self.health_tab,
            text=(
                "Health checks are local-only and redacted. Start with Run Health Probe. Advanced support reports are hidden below."
            ),
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            wraplength=900,
            justify="left",
            anchor="w",
        )
        intro.pack(fill="x", pady=(0, 12))

        preflight = self._card(self.health_tab, "Startup preflight")
        preflight.pack(fill="x", pady=(0, 12))
        tk.Label(
            preflight,
            text="Surface Xray pin, platform capability, and private-key ACL before connect. When blocking is enabled in Settings, Start Core is refused on gate failure.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            wraplength=860,
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=16, pady=(4, 10))
        preflight_grid = tk.Frame(preflight, bg=COLORS["panel"])
        preflight_grid.pack(fill="x", padx=12, pady=(0, 8))
        preflight_widgets: list[tk.Frame] = []
        for key, title, detail in (
            ("xray_pin", "Xray version pin", "Bundled runtime vs config minimum."),
            ("platform", "Platform capabilities", "OS, browser, and VPN conflict hints."),
            ("key_acl", "Private key ACL", "Local CA key permissions."),
        ):
            preflight_widgets.append(self._preflight_item(preflight_grid, key, title, detail))
        self._responsive_grid(preflight_grid, preflight_widgets, preferred_columns=3, min_cell_width=220, gap=8)
        preflight_row = tk.Frame(preflight, bg=COLORS["panel"])
        preflight_row.pack(fill="x", padx=16, pady=(0, 16))
        self._button_grid(
            preflight_row,
            [
                ("Run Full Preflight", "Accent.TButton", self.run_full_preflight),
                ("Apply Strategy Profile", "Soft.TButton", self.apply_recommended_profile),
                ("Restrict Key ACL", "Soft.TButton", self.restrict_private_key_acl),
                ("Wrap Key (DPAPI)", "Soft.TButton", self.wrap_private_key_dpapi),
                ("Unwrap Key (DPAPI)", "Soft.TButton", self.unwrap_private_key_dpapi),
            ],
            preferred_columns=3,
            min_cell_width=190,
        )

        ja3_card = self._card(self.health_tab, "TLS fingerprint oracle (opt-in)")
        ja3_card.pack(fill="x", pady=(0, 12))
        tk.Label(
            ja3_card,
            text="Measures wire JA3 through a trusted echo oracle (ADR-0004). Configured vs measured stay separate until this run completes.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            wraplength=860,
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=16, pady=(4, 8))
        self._form_row(ja3_card, "Oracle URL", self.browser_ja3_oracle_url)
        ja3_row = tk.Frame(ja3_card, bg=COLORS["panel"])
        ja3_row.pack(fill="x", padx=16, pady=(0, 16))
        self._button_grid(
            ja3_row,
            [
                ("Run JA3 Oracle", "Accent.TButton", self.run_ja3_oracle),
                ("Open Chromium Guide", "Soft.TButton", lambda: self.open_path(ROOT / "docs" / "chromium-integration.md")),
            ],
            preferred_columns=2,
            min_cell_width=180,
        )

        health = self._card(self.health_tab, "Local health probe")
        health.pack(fill="x", pady=(0, 12))
        tk.Label(
            health,
            text="Runs scripts/health_probe.py and prints redacted JSON. No payload logs, URLs with tokens, or private key material.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            wraplength=860,
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=16, pady=(4, 10))
        row = tk.Frame(health, bg=COLORS["panel"])
        row.pack(fill="x", padx=16, pady=(0, 16))
        self._button_grid(
            row,
            [
                ("Run Health Probe", "Accent.TButton", self.run_health_probe),
                ("Platform Capability", "Soft.TButton", self.run_platform_capability_check),
                ("Trust Store Check", "Soft.TButton", self.run_trust_store_check),
                ("Open Health Guide", "Soft.TButton", lambda: self.open_path(ROOT / "docs" / "preflight-and-diagnostics.md")),
            ],
            preferred_columns=4,
            min_cell_width=170,
        )

        advanced, advanced_body = self._collapsible_panel(
            self.health_tab,
            "Advanced support reports",
            "Use these when sharing a redacted report with someone helping you, or when investigating DNS, captive portal, or provider drift.",
            self.show_health_advanced,
            hidden_text="Show support reports",
            shown_text="Hide support reports",
        )
        advanced.pack(fill="x", pady=(0, 12))
        self._button_grid(
            advanced_body,
            [
                ("Run Lab Evidence", "Soft.TButton", self.run_lab_evidence),
                ("Run Decision Report", "Soft.TButton", self.run_decision_report),
                ("Score Decision Report", "Soft.TButton", self.run_path_scorer),
                ("Copy Phase Summary", "Soft.TButton", self.copy_phase_summary),
                ("Open Health Policy", "Soft.TButton", lambda: self.open_path(ROOT / "configs" / "health-checks.yml")),
                ("Open Decision Engine Doc", "Soft.TButton", lambda: self.open_path(ROOT / "docs" / "decision-engine.md")),
            ],
            preferred_columns=3,
            min_cell_width=210,
        )

        smoke = self._card(self.health_tab, "Browser smoke summary")
        smoke.pack(fill="x", pady=(0, 12))
        tk.Label(
            smoke,
            text="Optional wrapper that runs browser checks against the same URL/proxy and summarizes ready/attention state.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            wraplength=860,
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=16, pady=(4, 10))
        row2 = tk.Frame(smoke, bg=COLORS["panel"])
        row2.pack(fill="x", padx=16, pady=(0, 16))
        self._button_grid(
            row2,
            [
                ("Run Browser Smoke", "Accent.TButton", self.run_browser_smoke),
                ("Open Browser Integration Guide", "Soft.TButton", lambda: self.open_path(ROOT / "docs" / "chromium-integration.md")),
            ],
            preferred_columns=2,
            min_cell_width=230,
        )

    def _build_fixes_help(self) -> None:
        intro = tk.Label(
            self.fixes_tab,
            text="Use these when checks need help. Repairs stay local and do not install certificate trust, change system proxy settings, or delete browser profiles.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            anchor="w",
        )
        intro.pack(fill="x", pady=(0, 12))
        self._info_strip(
            self.fixes_tab,
            "Repair stays local",
            "These tools can regenerate project files or install optional tools, but they do not install certificate trust or change system proxy settings.",
            "warn",
        ).pack(fill="x", pady=(0, 12))

        quick = self._card(self.fixes_tab, "Safe repair sequence")
        quick.pack(fill="x", pady=(0, 14))
        tk.Label(
            quick,
            text="Repairs generated local files, validates metadata, routes and protocols, then runs static preflight. Certificate generation is offered only after confirmation.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            wraplength=820,
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=16, pady=(4, 10))
        qrow = tk.Frame(quick, bg=COLORS["panel"])
        qrow.pack(fill="x", padx=16, pady=(0, 16))
        self._button_grid(
            qrow,
            [
                ("Repair Setup", "Accent.TButton", self.safe_auto_fix),
                ("Reset GUI Defaults", "Soft.TButton", self.reset_gui_defaults),
                ("Open Preflight Guide", "Soft.TButton", lambda: self.open_path(ROOT / "docs" / "preflight-and-diagnostics.md")),
            ],
            preferred_columns=3,
            min_cell_width=190,
        )

        common, common_body = self._collapsible_panel(
            self.fixes_tab,
            "Advanced repair and install tools",
            "Open this for profile regeneration, optional dependency installers, bundled Xray Core download, and packaging tools.",
            self.show_repair_advanced,
            hidden_text="Show advanced setup tools",
            shown_text="Hide advanced setup tools",
        )
        common.pack(fill="x", pady=(0, 14))
        row = tk.Frame(common_body, bg=COLORS["panel"])
        row.pack(fill="x", pady=(0, 8))
        self._button_grid(
            row,
            [
                ("Regenerate Profiles", "Accent.TButton", self.generate_standard_profiles),
                ("Create Alternate Ports", "Soft.TButton", self.generate_alt_profiles),
                ("Certificate Status", "Soft.TButton", self.cert_status),
                ("Run FakeDNS Check", "Soft.TButton", self.run_fakedns_recovery_check),
                ("FakeDNS Guide", "Soft.TButton", lambda: self.open_path(ROOT / "docs" / "fakedns-recovery.md")),
            ],
            preferred_columns=3,
            min_cell_width=180,
        )

        row2 = tk.Frame(common_body, bg=COLORS["panel"])
        row2.pack(fill="x", pady=(0, 8))
        self._button_grid(
            row2,
            [
                ("Install Optional Dependencies", "Accent.TButton", self.install_optional_dependencies),
                ("Install Page Check Tools", "Soft.TButton", self.install_diagnostics_dependencies),
                ("Install Fingerprint Tools", "Soft.TButton", self.install_stealth_dependencies),
                ("Browser Install Hints", "Soft.TButton", self.browser_install_hints),
                ("Open Xray Core Releases", "Soft.TButton", lambda: webbrowser.open(XRAY_RELEASES_URL)),
            ],
            preferred_columns=3,
            min_cell_width=210,
        )

        row3 = tk.Frame(common_body, bg=COLORS["panel"])
        row3.pack(fill="x")
        self._button_grid(
            row3,
            [
                ("Install PyInstaller", "Soft.TButton", self.install_pyinstaller),
                ("Download Xray Core", "Soft.TButton", self.download_xray),
                ("Open GUI Guide", "Soft.TButton", lambda: self.open_path(ROOT / "docs" / "gui.md")),
                ("Open Xray-config Folder", "Soft.TButton", lambda: self.open_path(ROOT / "Xray-config")),
            ],
            preferred_columns=4,
            min_cell_width=180,
        )

    def _build_output_pane(self, parent: tk.Widget) -> None:
        outer = tk.Frame(parent, bg=COLORS["bg"])
        outer.pack(fill="x", padx=self._scaled(24), pady=(0, self._scaled(24)))
        self.output_outer = outer
        frame = tk.Frame(outer, bg=COLORS["panel"], highlightbackground=COLORS["line"], highlightthickness=1)
        frame.pack(fill="x")
        header = tk.Frame(frame, bg=COLORS["panel"])
        header.pack(fill="x", padx=self._scaled(14), pady=(self._scaled(10), self._scaled(6)))
        self._icon_canvas(header, "list", COLORS["blue"], 22, COLORS["panel"]).pack(side="left", padx=(0, self._scaled(8)))
        tk.Label(header, text="Log Drawer", bg=COLORS["panel"], fg=COLORS["ink"], font=self.fonts["h2"]).pack(side="left")
        tk.Label(header, text="System, core, and check output are separated. Hide this drawer when you only need status.", bg=COLORS["panel"], fg=COLORS["muted"], font=self.fonts["caption"]).pack(side="left", padx=self._scaled(10))
        self.output_toggle_button = ttk.Button(header, textvariable=self.output_toggle_text, style="Soft.TButton", command=self.toggle_output_drawer)
        self.output_toggle_button.pack(side="right")
        ttk.Button(header, text="Clear", style="Soft.TButton", command=self.clear_output).pack(side="right", padx=self._scaled(8))
        ttk.Button(header, text="Copy All", style="Soft.TButton", command=self.copy_output).pack(side="right")
        self.output_body = tk.Frame(frame, bg=COLORS["panel"])
        self.output_body.pack(fill="x")
        self.output_notebook = ttk.Notebook(self.output_body)
        self.output_notebook.pack(fill="both", expand=True, padx=self._scaled(14), pady=(0, self._scaled(14)))
        self.output_buffers = {
            "sys": self._create_log_buffer("System"),
            "xray": self._create_log_buffer("Core"),
            "audit": self._create_log_buffer("Checks"),
        }
        self.output = self.output_buffers["sys"]
        self.log_multiplexer = LogMultiplexer(self.output_buffers)
        self.after(100, self._drain_log_buffers)
        if not self.output_visible.get():
            self.output_body.pack_forget()
            self.output_toggle_text.set("Show Logs")

    def toggle_output_drawer(self) -> None:
        self.output_visible.set(not self.output_visible.get())
        if self.output_visible.get():
            self.output_body.pack(fill="x")
            self.output_toggle_text.set("Hide Logs")
            self.logs_have_unread = False
        else:
            self.output_body.pack_forget()
            self.output_toggle_text.set("Show Logs")

    def hide_output_drawer(self) -> None:
        if hasattr(self, "output_body") and self.output_visible.get():
            self.output_visible.set(False)
            self.output_body.pack_forget()
            self.output_toggle_text.set("Show Logs")

    def _create_log_buffer(self, title: str) -> tk.Text:
        tab = tk.Frame(self.output_notebook, bg="#0f172a")
        self.output_notebook.add(tab, text=title)
        text = tk.Text(
            tab,
            height=8,
            bg="#0f172a",
            fg="#dbeafe",
            insertbackground="#ffffff",
            relief="flat",
            padx=self._scaled(12),
            pady=self._scaled(10),
            font=self.fonts["code"],
            wrap="word",
            state="disabled",
        )
        text.pack(fill="both", expand=True)
        text.tag_configure("normal", foreground="#dbeafe")
        text.tag_configure("success", foreground="#86efac")
        text.tag_configure("warning", foreground="#fbbf24")
        text.tag_configure("danger", foreground="#fca5a5")
        return text

    def _drain_log_buffers(self) -> None:
        if self.log_multiplexer:
            self.log_multiplexer.drain()
        self.after(100, self._drain_log_buffers)

    def clear_output(self) -> None:
        targets = self.output_buffers.values() if self.output_buffers else [self.output]
        for widget in targets:
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            widget.configure(state="disabled")

    def _build_profiles_dns(self) -> None:
        self._info_strip(
            self.profiles_tab,
            "Profiles are modes, not chores",
            "Use the standard profile for normal tests. Open alternate-port tools only when another local app already uses the default ports.",
            "info",
        ).pack(fill="x", pady=(0, 12))

        profiles = self._card(self.profiles_tab, "Operating profiles")
        profiles.pack(fill="x", pady=(0, 14))
        tk.Label(profiles, text="Regenerate the standard operating modes used by the GUI.", bg=COLORS["panel"], fg=COLORS["muted"], anchor="w").pack(fill="x", padx=16, pady=(4, 10))
        row = tk.Frame(profiles, bg=COLORS["panel"])
        row.pack(fill="x", padx=16, pady=(0, 16))
        ttk.Button(row, text="Regenerate Standard Profiles", style="Accent.TButton", command=self.generate_standard_profiles).pack(side="left", padx=(0, 10))

        alt_section, alt_body = self._collapsible_section(
            profiles,
            "Alternate-port profiles",
            "Use only when another app already owns the default local ports. The generated files stay local and ignored by git.",
            self.show_profiles_advanced,
            hidden_text="Show alternate-port generator",
            shown_text="Hide alternate-port generator",
        )
        alt_section.pack(fill="x", padx=16, pady=(0, 16))
        tk.Label(alt_body, text="Offset", bg=COLORS["panel"], fg=COLORS["muted"]).pack(side="left")
        ttk.Entry(alt_body, textvariable=self.profile_offset, width=8).pack(side="left", padx=6)
        tk.Label(alt_body, text="Suffix", bg=COLORS["panel"], fg=COLORS["muted"]).pack(side="left")
        ttk.Entry(alt_body, textvariable=self.profile_suffix, width=14).pack(side="left", padx=6)
        ttk.Button(alt_body, text="Generate Alternate Profiles", style="Soft.TButton", command=self.generate_alt_profiles).pack(side="left", padx=10)

        dns = self._card(self.profiles_tab, "DNS Check")
        dns.pack(fill="x", pady=(0, 14))
        tk.Label(dns, text="Query A, AAAA, HTTPS, and SVCB records for resolver drift checks.", bg=COLORS["panel"], fg=COLORS["muted"], anchor="w").pack(fill="x", padx=16, pady=(4, 10))
        row2 = tk.Frame(dns, bg=COLORS["panel"])
        row2.pack(fill="x", padx=16, pady=(0, 16))
        tk.Label(row2, text="Domain", bg=COLORS["panel"], fg=COLORS["muted"]).pack(side="left")
        ttk.Entry(row2, textvariable=self.dns_domain, width=24).pack(side="left", padx=6)
        tk.Label(row2, text="Resolvers", bg=COLORS["panel"], fg=COLORS["muted"]).pack(side="left")
        ttk.Entry(row2, textvariable=self.dns_resolvers, width=32).pack(side="left", padx=6)
        ttk.Button(row2, text="Run DNS Sweep", style="Accent.TButton", command=self.run_dns_sweep).pack(side="left", padx=10)

    def _build_certs(self) -> None:
        self._info_strip(
            self.certs_tab,
            "Private key stays local",
            "The GUI can create and inspect your local CA files, but trust installation remains a manual choice.",
            "warn",
        ).pack(fill="x", pady=(0, 12))

        certs = self._card(self.certs_tab, "Certificate lifecycle")
        certs.pack(fill="x", pady=(0, 14))
        text = (
            "Use personal local certificates only. The GUI can inspect or generate local CA files, "
            "but it never installs trust silently and never uploads keys."
        )
        tk.Label(certs, text=text, bg=COLORS["panel"], fg=COLORS["muted"], wraplength=740, justify="left", anchor="w").pack(fill="x", padx=16, pady=(4, 12))
        row = tk.Frame(certs, bg=COLORS["panel"])
        row.pack(fill="x", padx=16, pady=(0, 16))
        self._button_grid(
            row,
            [
                ("Certificate Status", "Accent.TButton", self.cert_status),
                ("Check Cert/Key Pair", "Soft.TButton", self.cert_pair),
                ("Generate Local CA", "Warning.TButton", self.generate_ca),
                ("Trust Store Check", "Soft.TButton", self.run_trust_store_check),
                ("Trust Instructions", "Soft.TButton", self.trust_instructions),
                ("Open Xray-config Folder", "Soft.TButton", lambda: self.open_path(ROOT / "Xray-config")),
            ],
            preferred_columns=3,
            min_cell_width=190,
        )

    def _build_browser(self) -> None:
        intro = (
            "Start with Page Check. It verifies proxy and CA wiring with stock Chromium. "
            "Fingerprint Check is advanced and uses CloakBrowser after the basic page check works. "
            "Both paths send traffic to the local mixed inbound only."
        )
        tk.Label(self.browser_tab, text=intro, bg=COLORS["panel"], fg=COLORS["muted"], wraplength=820, justify="left", anchor="w").pack(fill="x", pady=(0, 12))
        self._info_strip(
            self.browser_tab,
            "Page Check first",
            "Use the stock browser check before changing browser paths or fingerprint settings. Advanced controls stay tucked away below.",
            "info",
        ).pack(fill="x", pady=(0, 12))

        shared = self._card(self.browser_tab, "Shared settings")
        shared.pack(fill="x", pady=(0, 14))
        row = tk.Frame(shared, bg=COLORS["panel"])
        row.pack(fill="x", padx=16, pady=(4, 16))
        tk.Label(row, text="Target URL", bg=COLORS["panel"], fg=COLORS["muted"]).pack(side="left")
        ttk.Entry(row, textvariable=self.browser_url, width=42).pack(side="left", padx=6)
        tk.Label(row, text="Proxy", bg=COLORS["panel"], fg=COLORS["muted"]).pack(side="left")
        ttk.Entry(row, textvariable=self.browser_proxy, width=30).pack(side="left", padx=6)
        ttk.Button(row, text="Open integration doc", style="Soft.TButton", command=lambda: self.open_path(ROOT / "docs" / "chromium-integration.md")).pack(side="left", padx=10)

        diag = self._card(self.browser_tab, "Path 1 - Page Check (stock Chromium)")
        diag.pack(fill="x", pady=(0, 14))
        tk.Label(
            diag,
            text="Playwright + optional system Chrome/Edge. Use after setup checks are ready to confirm page load through the local proxy.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            wraplength=780,
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=16, pady=(2, 8))
        drow2 = tk.Frame(diag, bg=COLORS["panel"])
        drow2.pack(fill="x", padx=16, pady=(0, 10))
        page_actions: list[tuple[str, str, Callable[[], None]]] = [
            ("Run page check", "Accent.TButton", self.run_browser_diagnostics),
            (
                "Install hint (Playwright)",
                "Soft.TButton",
                lambda: self._append_output(
                    "\nPage check tools install:\n  pip install -r requirements-browser-diagnostics.txt\n"
                    "  playwright install chromium\n"
                    "  # Linux only, if dependencies are missing: playwright install-deps chromium\n"
                ),
            ),
        ]
        if os.name == "nt":
            page_actions.append(("Launch stock Chrome (PS)", "Soft.TButton", self.launch_diagnostics_chrome_ps))
        page_actions.append(("Launch isolated Chromium", "Soft.TButton", self.launch_isolated_chromium))
        self._button_grid(drow2, page_actions, preferred_columns=3, min_cell_width=200)

        page_advanced, page_advanced_body = self._collapsible_section(
            diag,
            "Advanced page-check settings",
            "Leave these empty/off unless you need a specific Chrome or Edge executable or a headless run.",
            self.show_browser_page_advanced,
            hidden_text="Show custom browser settings",
            shown_text="Hide custom browser settings",
        )
        page_advanced.pack(fill="x", padx=16, pady=(0, 16))
        drow = tk.Frame(page_advanced_body, bg=COLORS["panel"])
        drow.pack(fill="x", pady=(0, 8))
        tk.Label(drow, text="Chrome path (optional)", bg=COLORS["panel"], fg=COLORS["muted"]).pack(side="left")
        ttk.Entry(drow, textvariable=self.browser_executable, width=48).pack(side="left", padx=6)
        ttk.Button(drow, text="Browse", style="Soft.TButton", command=self.choose_browser_path).pack(side="left", padx=(0, 10))
        ttk.Checkbutton(page_advanced_body, text="Headless", variable=self.browser_headless).pack(anchor="w")

        stealth, stealth_body = self._collapsible_panel(
            self.browser_tab,
            "Path 2 - Fingerprint Check (CloakBrowser)",
            "Use this only after Page Check passes. It tests browser fingerprint behavior while Xray still owns routing and MITM behavior.",
            self.show_browser_fingerprint,
            hidden_text="Show fingerprint check",
            shown_text="Hide fingerprint check",
        )
        stealth.pack(fill="x", pady=(0, 14))
        stealth_url = read_browser_integration().get("stealth", {}).get("project_url", CLOAKBROWSER_URL)
        tk.Label(
            stealth_body,
            text=f"Default engine: CloakBrowser - {stealth_url}",
            bg=COLORS["panel"],
            fg=COLORS["ink"],
            wraplength=780,
            justify="left",
            anchor="w",
            font=("Segoe UI", 10, "bold"),
        ).pack(fill="x", pady=(2, 4))
        tk.Label(
            stealth_body,
            text="Browser fingerprint testing only. Xray still owns MITM, routing, and domain fronting.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            wraplength=780,
            justify="left",
            anchor="w",
        ).pack(fill="x", pady=(0, 8))
        srow = tk.Frame(stealth_body, bg=COLORS["panel"])
        srow.pack(fill="x", pady=(0, 8))
        tk.Label(srow, text="Fingerprint seed", bg=COLORS["panel"], fg=COLORS["muted"]).pack(side="left")
        ttk.Entry(srow, textvariable=self.browser_fingerprint_seed, width=16).pack(side="left", padx=6)
        ttk.Checkbutton(srow, text="geoip (timezone/locale from proxy)", variable=self.browser_geoip).pack(side="left", padx=12)
        ttk.Checkbutton(srow, text="humanize", variable=self.browser_humanize).pack(side="left", padx=12)
        srow2 = tk.Frame(stealth_body, bg=COLORS["panel"])
        srow2.pack(fill="x")
        self._button_grid(
            srow2,
            [
                ("Run fingerprint check", "Accent.TButton", self.run_browser_stealth),
                (
                    "Install hint (CloakBrowser)",
                    "Soft.TButton",
                    lambda: self._append_output(
                        f"\nFingerprint tools install:\n  pip install -r requirements-browser-stealth.txt\n"
                        f"  python -m cloakbrowser install\n  Project: {stealth_url}\n"
                    ),
                ),
                ("Open CloakBrowser on GitHub", "Soft.TButton", lambda: webbrowser.open(stealth_url)),
                ("Check CloakBrowser import", "Soft.TButton", self.check_cloakbrowser_installed),
            ],
            preferred_columns=2,
            min_cell_width=230,
        )

    def _build_docs(self) -> None:
        docs = [
            ("README", ROOT / "README.md"),
            ("Operating profiles", ROOT / "docs" / "operating-profiles.md"),
            ("Chromium integration", ROOT / "docs" / "chromium-integration.md"),
            ("Preflight guide", ROOT / "docs" / "preflight-and-diagnostics.md"),
            ("Certificate lifecycle", ROOT / "docs" / "certificate-lifecycle.md"),
            ("DNS resilience", ROOT / "docs" / "dns-resilience.md"),
            ("Platform compatibility", ROOT / "docs" / "platform-compatibility.md"),
            ("FakeDNS recovery", ROOT / "docs" / "fakedns-recovery.md"),
            ("Provider status", ROOT / "docs" / "provider-status.md"),
            ("Local activity history", ROOT / "docs" / "local-telemetry.md"),
        ]
        tk.Label(self.docs_tab, text="Open the focused guide you need. These files are local repository docs.", bg=COLORS["panel"], fg=COLORS["muted"], anchor="w").pack(fill="x", pady=(0, 12))
        grid = tk.Frame(self.docs_tab, bg=COLORS["panel"])
        grid.pack(fill="x")
        doc_cards: list[tk.Frame] = []
        for index, (label, path) in enumerate(docs):
            card = self._card(grid, label)
            doc_cards.append(card)
            tk.Label(card, text=short_path(path), bg=COLORS["panel"], fg=COLORS["muted"], anchor="w").pack(fill="x", padx=16, pady=(2, 12))
            ttk.Button(card, text="Open", style="Soft.TButton", command=lambda p=path: self.open_path(p)).pack(anchor="w", padx=16, pady=(0, 16))
        self._responsive_grid(grid, doc_cards, preferred_columns=2, min_cell_width=300, gap=10)

    def record_telemetry(self, event: str, status: str, detail: str = "", fields: dict[str, object] | None = None) -> None:
        payload: dict[str, object] = {
            "ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "event": event,
            "status": status,
            "detail": detail[:240],
            "fields": fields or {},
        }
        if self.opsec_telemetry_mode.get():
            self._ram_telemetry_events.append(payload)
            cap = self.gui_preferences.telemetry_max_events
            if len(self._ram_telemetry_events) > cap:
                self._ram_telemetry_events = self._ram_telemetry_events[-cap:]
            self._update_telemetry_labels(payload)
            return
        LOCAL_STATE.mkdir(exist_ok=True)
        try:
            with GUI_TELEMETRY.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, sort_keys=True) + "\n")
        except OSError:
            return
        self._update_telemetry_labels(payload)

    def toggle_connect_preflight_gate(self) -> None:
        self._save_gui_preferences_from_vars()
        enabled = self.block_connect_on_preflight_fail.get()
        summary = "enabled" if enabled else "disabled"
        self.record_telemetry("preflight_gate_toggle", "info", f"Connect blocking {summary}")
        self._append_output(f"\nPreflight connect gate: {summary}\n")

    def toggle_auto_apply_strategy(self) -> None:
        self._save_gui_preferences_from_vars()
        enabled = self.auto_apply_strategy_on_probe.get()
        summary = "enabled" if enabled else "disabled"
        self.record_telemetry("auto_strategy_toggle", "info", f"Auto strategy apply {summary}")
        self._append_output(f"\nAuto strategy apply: {summary}\n")

    def _save_gui_preferences_from_vars(self) -> None:
        mode = "ram_only" if self.opsec_telemetry_mode.get() else "local_disk"
        self.gui_preferences = GuiPreferences(
            telemetry_mode=mode,
            telemetry_max_events=self.gui_preferences.telemetry_max_events,
            block_connect_on_preflight_fail=self.block_connect_on_preflight_fail.get(),
            auto_apply_strategy_on_probe=self.auto_apply_strategy_on_probe.get(),
        )
        save_preferences(self.gui_preferences)

    def toggle_opsec_telemetry_mode(self) -> None:
        self._save_gui_preferences_from_vars()
        if self.opsec_telemetry_mode.get() and GUI_TELEMETRY.exists():
            try:
                GUI_TELEMETRY.unlink()
            except OSError:
                pass
        summary = "RAM-only (no jsonl append)" if self.opsec_telemetry_mode.get() else "Local disk history enabled"
        self.record_telemetry("telemetry_mode_changed", "info", summary, {"mode": self.gui_preferences.telemetry_mode})
        self._append_output(f"\nTelemetry mode: {summary}\n")

    def _telemetry_events(self, limit: int | None = None) -> list[dict[str, object]]:
        if self.opsec_telemetry_mode.get():
            events = list(self._ram_telemetry_events)
            return events[-limit:] if limit else events
        if not GUI_TELEMETRY.exists():
            return []
        try:
            lines = GUI_TELEMETRY.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        selected = lines[-limit:] if limit else lines
        events: list[dict[str, object]] = []
        for line in selected:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                events.append(item)
        return events

    def _update_telemetry_labels(self, latest: dict[str, object] | None = None) -> None:
        events = self._telemetry_events()
        if latest is None and events:
            latest = events[-1]
        fail_count = sum(1 for item in events if str(item.get("status", "")).lower() in {"fail", "blocked", "error"})
        self.telemetry_summary.set(f"Activity history: local only, {len(events)} event{'s' if len(events) != 1 else ''}")
        self.telemetry_connections.set(str(self.stream_count))
        self.telemetry_requests.set(f"{len(events):,}")
        self.telemetry_blocked.set(str(fail_count))
        if latest:
            self.telemetry_last.set(f"Last activity: {latest.get('event', 'unknown')} / {latest.get('status', 'info')} / {latest.get('detail', '')}")
        else:
            self.telemetry_last.set("Last activity: none")

    def _status_snapshot(self) -> dict[str, object]:
        selected_config = self.active_config_path()
        proxy_endpoint = config_proxy_endpoint(selected_config)
        proxy_port = int(proxy_endpoint.get("port") or 10808)
        profiles = sorted((ROOT / "Xray-config").glob("Xray-Cooperative-Overlay.*.json"))
        host_python = find_host_python()
        runtime = xray_runtime_status()
        local_xray = runtime["executable"]
        readiness = self.readiness_cache.get(selected_config)
        readiness_port = int(readiness.listener_port) if readiness else proxy_port
        loopback_open = bool(readiness and readiness.listener_status == "open") or port_accepts_loopback(proxy_port)
        listener_info = listener_process_info(proxy_port) if loopback_open else {"pid": "", "name": "", "endpoint": ""}
        gui_pid = str(self.xray_process.pid) if self._xray_running_from_gui() and self.xray_process is not None else ""
        listener_pid = str(readiness.listener_pid if readiness else listener_info.get("pid", ""))
        readiness_owner = readiness.xray_owner if readiness else ""
        core_owner = "app" if gui_pid and listener_pid == gui_pid else readiness_owner or ("external" if loopback_open else "none")
        listener_endpoint = (
            f"{readiness.listener_host}:{readiness.listener_port}"
            if readiness and readiness.listener_host
            else str(listener_info.get("endpoint", ""))
        )
        browser_cfg = read_browser_integration()
        proxy_state = system_proxy_status()
        tun_enabled = config_has_tun(selected_config)
        snapshot = {
            "config_exists": CONFIG.exists(),
            "selected_config_exists": bool(readiness.config_ok) if readiness else selected_config.exists(),
            "cert_exists": bool(readiness.cert_exists) if readiness else CERT.exists(),
            "key_exists": bool(readiness.key_exists) if readiness else KEY.exists(),
            "profile_count": len(profiles),
            "loopback_10808_open": loopback_open,
            "proxy_port": readiness_port,
            "proxy_listen": str(proxy_endpoint.get("listen") or "127.0.0.1"),
            "proxy_protocol": str(proxy_endpoint.get("protocol") or "mixed"),
            "proxy_tag": str(proxy_endpoint.get("tag") or "mixed-in"),
            "xray_started_by_gui": self._xray_running_from_gui(),
            "xray_local": bool(readiness.xray_path) if readiness else bool(local_xray),
            "xray_runtime_ready": bool(readiness.xray_available) if readiness else bool(runtime["ready"]),
            "xray_path": short_path(Path(readiness.xray_path)) if readiness and readiness.xray_path else short_path(local_xray) if local_xray else "",
            "xray_version": readiness.xray_version if readiness else xray_core_version(local_xray if isinstance(local_xray, Path) else None),
            "xray_geoip": bool(runtime["geoip_exists"]),
            "xray_geosite": bool(runtime["geosite_exists"]),
            "core_owner": core_owner,
            "listener_pid": listener_pid,
            "listener_name": readiness.listener_process_name if readiness else str(listener_info.get("name", "")),
            "listener_path": readiness.listener_process_path if readiness else "",
            "listener_endpoint": listener_endpoint,
            "listener_exposure": readiness.listener_exposure if readiness else "unknown",
            "listener_status": readiness.listener_status if readiness else "unknown",
            "system_proxy_status": proxy_state["status"],
            "system_proxy_detail": proxy_state["detail"],
            "system_proxy_level": proxy_state["level"],
            "tun_enabled": tun_enabled,
            "host_python": " ".join(host_python or []),
            "browser_proxy": self.browser_proxy.get().strip() or browser_cfg.get("default_proxy", "socks5://127.0.0.1:10808"),
            "browser_path_set": bool(self.browser_executable.get().strip()),
            "diagnostics_script": (SCRIPTS / "browser_diagnostics.py").exists(),
            "stealth_script": (SCRIPTS / "browser_stealth.py").exists(),
            "geodata_lock": (ROOT / "release-geodata-lock.json").exists(),
        }
        snapshot.update(readiness_snapshot_fields(readiness, self.readiness_cache.error))
        if readiness is None:
            snapshot["profiles_present"] = len(profiles) >= 4
        return snapshot

    def _status_level(self, snapshot: dict[str, object]) -> tuple[str, str]:
        proxy_endpoint = f"{snapshot.get('proxy_listen')}:{snapshot.get('proxy_port')}"
        if snapshot.get("readiness_error"):
            return "warn", f"Shared readiness state could not refresh: {snapshot.get('readiness_error')}"
        if snapshot.get("listener_exposure") == "exposed":
            return "fail", "Unsafe external listener is exposed on a non-loopback interface."
        if not snapshot["selected_config_exists"]:
            return "fail", "Primary config is missing."
        if not snapshot["cert_exists"] or not snapshot["key_exists"]:
            return "warn", "Generate local CA files before browser MITM testing."
        if snapshot.get("cert_key_match") == "mismatch":
            return "fail", "Certificate and private key do not match."
        if not snapshot["loopback_10808_open"]:
            return "warn", f"No local core is listening on {proxy_endpoint}. Start Core or open v2rayN."
        if snapshot.get("key_permission_status") == "broad":
            return "warn", "Local CA private key permissions appear broader than recommended."
        if snapshot.get("trust_status") not in {"pass", "not_supported", "skipped"}:
            return "warn", "Local CA trust is not matched in the target trust store."
        if not snapshot["diagnostics_script"] or not snapshot["stealth_script"]:
            return "warn", "Browser check scripts are missing."
        return "pass", f"Ready for browser testing through {proxy_endpoint}."

    def _update_readiness_items(self, snapshot: dict[str, object], selected_config: Path) -> None:
        self._set_readiness_item(
            "config",
            "Ready" if snapshot["selected_config_exists"] else "Missing",
            f"{short_path(selected_config)}; {snapshot.get('config_remarks') or 'remarks unknown'}" if snapshot["selected_config_exists"] else "Selected config was not found or did not validate.",
            "pass" if snapshot["selected_config_exists"] else "fail",
        )
        self._set_readiness_item(
            "runtime",
            "Ready" if snapshot["xray_runtime_ready"] else "Partial" if snapshot["xray_local"] else "Missing",
            str(snapshot.get("xray_path") or "Download Xray Core from Settings."),
            "pass" if snapshot["xray_runtime_ready"] else "warn",
        )
        cert_ready = bool(snapshot["cert_exists"] and snapshot["key_exists"])
        cert_issue = str(snapshot.get("cert_key_match") or "unknown")
        trust_status = str(snapshot.get("trust_status") or "unknown")
        if not cert_ready:
            cert_status = "Missing"
            cert_detail = "Generate Local CA; install trust manually."
            cert_level = "warn"
        elif cert_issue == "mismatch":
            cert_status = "Mismatch"
            cert_detail = "Certificate and private key do not match; regenerate the local CA."
            cert_level = "fail"
        elif trust_status not in {"pass", "not_supported", "skipped"}:
            cert_status = "Trust check"
            cert_detail = f"Files match, but trust is {trust_status}. The app never installs trust silently."
            cert_level = "warn"
        else:
            cert_status = "Ready"
            cert_detail = "Certificate/key pair and trust check are acceptable."
            cert_level = "pass"
        self._set_readiness_item(
            "cert",
            cert_status,
            cert_detail,
            cert_level,
        )
        listener_ready = bool(snapshot["loopback_10808_open"])
        exposure = str(snapshot.get("listener_exposure") or "unknown")
        if exposure == "exposed":
            process = str(snapshot.get("listener_name") or "external process")
            pid = str(snapshot.get("listener_pid") or "")
            listener_detail = f"{process}" + (f" PID {pid}" if pid else "") + f" is bound to {snapshot.get('listener_endpoint') or 'a non-loopback address'}."
            listener_status = "Exposed"
            listener_level = "fail"
        elif snapshot.get("core_owner") == "app":
            listener_detail = "Started by this app."
            listener_status = "Running"
            listener_level = "pass"
        elif snapshot.get("core_owner") == "external":
            process = str(snapshot.get("listener_name") or "external process")
            pid = str(snapshot.get("listener_pid") or "")
            listener_detail = f"External core active: {process}" + (f" (PID {pid})" if pid else "")
            listener_status = "Running"
            listener_level = "pass"
        else:
            listener_detail = f"No listener detected on {snapshot.get('proxy_listen')}:{snapshot.get('proxy_port')}."
            listener_status = "Stopped"
            listener_level = "warn"
        self._set_readiness_item(
            "listener",
            listener_status if listener_ready else "Stopped",
            listener_detail,
            listener_level if listener_ready else "warn",
        )
        configured = bool(snapshot.get("ja3_configured"))
        measured = bool(snapshot.get("ja3_measured"))
        validation = str(snapshot.get("ja3_validation_status") or "not_measured")
        if measured:
            observed = str(snapshot.get("ja3_observed") or "unknown")
            expected = str(snapshot.get("ja3_expected") or "")
            if validation == "match":
                fp_status, fp_level = "Measured", "pass"
                fp_detail = f"Oracle match. observed={observed}"
            elif validation == "mismatch":
                fp_status, fp_level = "Mismatch", "warn"
                fp_detail = f"Oracle mismatch. observed={observed} expected={expected or 'unset'}"
            else:
                fp_status, fp_level = "Measured", "info"
                fp_detail = f"Oracle recorded observed={observed}; no expected hash configured."
        elif configured:
            fp_status, fp_level = "Configured", "info"
            fp_detail = "Xray uTLS fingerprint configured; run an opt-in JA3 oracle to measure."
        else:
            fp_status, fp_level = "Not set", "warn"
            fp_detail = "No TLS fingerprint configured on repack outbounds."
        self._set_readiness_item("fingerprint", fp_status, fp_detail, fp_level)

    def _update_preflight_items(self, snapshot: dict[str, object]) -> None:
        min_version = str(snapshot.get("config_min_xray_version") or "").strip()
        runtime_version = str(snapshot.get("xray_version") or "").strip()
        if not min_version:
            pin_status, pin_level, pin_detail = "Unknown", "info", "Config does not declare a minimum Xray version."
        elif not runtime_version or runtime_version.lower() == "unknown":
            pin_status, pin_level, pin_detail = "Missing", "warn", f"Required >= {min_version}; download bundled Xray Core."
        elif version_at_least(runtime_version, min_version):
            pin_status, pin_level, pin_detail = "OK", "pass", f"Runtime {runtime_version} meets pin {min_version}."
        else:
            pin_status, pin_level, pin_detail = "Below pin", "fail", f"Runtime {runtime_version} is below required {min_version}."
        self._set_preflight_item("xray_pin", pin_status, pin_detail, pin_level)

        host_python = str(snapshot.get("host_python") or "").strip()
        if host_python:
            plat_status, plat_level, plat_detail = "Ready", "pass", f"Host Python: {host_python}"
        else:
            plat_status, plat_level, plat_detail = "Check", "warn", "Host Python not detected for optional browser tools."
        self._set_preflight_item("platform", plat_status, plat_detail, plat_level)

        key_perm = str(snapshot.get("key_permission_status") or "unknown")
        if key_perm == "restricted":
            acl_status, acl_level, acl_detail = "Restricted", "pass", "Private key ACL looks acceptable."
        elif key_perm == "broad":
            acl_status, acl_level, acl_detail = "Broad", "warn", "Restrict mycert.key to the current user only."
        else:
            acl_status, acl_level, acl_detail = "Unknown", "info", "Run Restrict Key ACL or certificate status for details."
        self._set_preflight_item("key_acl", acl_status, acl_detail, acl_level)

    def _update_runtime_items(self, snapshot: dict[str, object]) -> None:
        xray_path = str(snapshot.get("xray_path") or "")
        self._set_runtime_item(
            "xray_exe",
            "Ready" if snapshot["xray_local"] else "Missing",
            xray_path or "Click Download Xray Core to install the local runtime.",
            "pass" if snapshot["xray_local"] else "warn",
        )
        self._set_runtime_item(
            "geoip",
            "Ready" if snapshot["xray_geoip"] else "Missing",
            "xray/geoip.dat is present." if snapshot["xray_geoip"] else "Download Xray Core to restore geodata.",
            "pass" if snapshot["xray_geoip"] else "warn",
        )
        self._set_runtime_item(
            "geosite",
            "Ready" if snapshot["xray_geosite"] else "Missing",
            "xray/geosite.dat is present." if snapshot["xray_geosite"] else "Download Xray Core to restore geodata.",
            "pass" if snapshot["xray_geosite"] else "warn",
        )

    def _update_dashboard_stats(self, snapshot: dict[str, object], level: str, status_text: str) -> None:
        proxy_endpoint = f"{snapshot.get('proxy_listen')}:{snapshot.get('proxy_port')}"
        owner = str(snapshot.get("core_owner") or "none")
        exposure = str(snapshot.get("listener_exposure") or "unknown")
        core_state = (
            f"Running ({snapshot.get('xray_version')})"
            if owner == "app"
            else f"External exposed: {snapshot.get('listener_name') or 'detected'}"
            if owner == "external" and exposure == "exposed"
            else f"External: {snapshot.get('listener_name') or 'detected'}"
            if owner == "external"
            else f"Ready ({snapshot.get('xray_version')})"
            if snapshot.get("xray_runtime_ready")
            else "Missing files"
        )
        self._set_dashboard_stat("system", "System status", status_text, level)
        self._set_dashboard_stat("core", "Xray Core", core_state, "fail" if exposure == "exposed" else "pass" if owner in {"app", "external"} or snapshot.get("xray_runtime_ready") else "warn")
        self._set_dashboard_stat("proxy", "Local proxy", proxy_endpoint, "fail" if exposure == "exposed" else "pass" if snapshot.get("loopback_10808_open") else "warn")
        self._set_dashboard_stat("dns", "DNS", self.dns_resolvers.get().strip() or "Default resolvers", "info")
        self._set_dashboard_stat("uptime", "Uptime", self.network_duration.get(), "pass" if snapshot.get("loopback_10808_open") else "info")
        self.core_version_text.set(f"Xray Core: {core_state}")
        self.local_proxy_text.set(f"Local proxy: {proxy_endpoint}")
        self.dns_text.set(f"DNS: {self.dns_resolvers.get().strip() or 'default'}")
        self.system_proxy_text.set(f"System proxy: {snapshot.get('system_proxy_status')}")
        self.tun_text.set("TUN: configured" if snapshot.get("tun_enabled") else "TUN: off")

    def _update_network_mode_items(self, snapshot: dict[str, object]) -> None:
        proxy_endpoint = f"{snapshot.get('proxy_listen')}:{snapshot.get('proxy_port')}"
        proxy_url = self.browser_proxy.get().strip() or f"socks5://{browser_proxy_host(snapshot.get('proxy_listen'))}:{snapshot.get('proxy_port')}"
        exposure = str(snapshot.get("listener_exposure") or "unknown")
        self._set_mode_item(
            "local_proxy",
            "Exposed" if exposure == "exposed" else "Ready" if snapshot.get("loopback_10808_open") else "Waiting",
            f"Browser checks use {proxy_url}. Selected config expects {snapshot.get('proxy_protocol')} on {proxy_endpoint}.",
            "fail" if exposure == "exposed" else "pass" if snapshot.get("loopback_10808_open") else "warn",
        )
        owner = str(snapshot.get("core_owner") or "none")
        if owner == "app":
            external_status = "App owned"
            external_detail = "This app launched the core and can stop it safely."
            external_level = "pass"
        elif owner == "external":
            process = snapshot.get("listener_name") or "External process"
            pid = f" PID {snapshot.get('listener_pid')}" if snapshot.get("listener_pid") else ""
            path = f" Path: {snapshot.get('listener_path')}" if snapshot.get("listener_path") else ""
            external_status = "Exposed" if exposure == "exposed" else "External"
            external_detail = (
                f"{process}{pid} owns {snapshot.get('listener_endpoint') or proxy_endpoint}.{path} "
                + ("Change that client's inbound listen address to 127.0.0.1." if exposure == "exposed" else "Stop it in that app, not here.")
            )
            external_level = "fail" if exposure == "exposed" else "info"
        else:
            external_status = "None"
            external_detail = "No external v2rayN/Xray listener is detected on the selected local port."
            external_level = "pass"
        self._set_mode_item("external_core", external_status, external_detail, external_level)
        self._set_mode_item(
            "system_proxy",
            str(snapshot.get("system_proxy_status") or "Unknown"),
            str(snapshot.get("system_proxy_detail") or "System proxy state could not be checked."),
            str(snapshot.get("system_proxy_level") or "info"),
        )
        self._set_mode_item(
            "tun",
            "Configured" if snapshot.get("tun_enabled") else "Off",
            "The selected config includes a TUN inbound. Run as administrator and review OS routing before use." if snapshot.get("tun_enabled") else "Standard profile uses explicit browser proxy. TUN is not changed by the app.",
            "info" if snapshot.get("tun_enabled") else "pass",
        )
        owner_value = {
            "app": "App Core",
            "external": "External Core",
            "none": "No Core",
        }.get(owner, "Unknown")
        owner_detail = (
            "This app can stop the core."
            if owner == "app"
            else f"{snapshot.get('listener_name') or 'External process'} is left untouched."
            if owner == "external"
            else "Start Core or open v2rayN/Xray."
        )
        self._set_traffic_summary(
            "browser_path",
            "Explicit Proxy",
            f"{proxy_url}",
            "fail" if exposure == "exposed" else "pass" if snapshot.get("loopback_10808_open") else "warn",
        )
        self._set_traffic_summary(
            "core_owner",
            owner_value,
            owner_detail,
            "fail" if exposure == "exposed" else "pass" if owner == "app" else "info" if owner == "external" else "warn",
        )
        self._set_traffic_summary(
            "system_route",
            str(snapshot.get("system_proxy_status") or "Unknown"),
            "Detected only; the app does not change OS proxy settings.",
            str(snapshot.get("system_proxy_level") or "info"),
        )
        self._set_traffic_summary(
            "tun_route",
            "Configured" if snapshot.get("tun_enabled") else "Off",
            "Manual/admin routing path." if snapshot.get("tun_enabled") else "Browser proxy remains the default path.",
            "info" if snapshot.get("tun_enabled") else "pass",
        )
        self._set_mode_item(
            "browser_proxy",
            "Exposed" if exposure == "exposed" else "Ready" if snapshot.get("loopback_10808_open") else "Waiting",
            proxy_url,
            "fail" if exposure == "exposed" else "pass" if snapshot.get("loopback_10808_open") else "warn",
        )
        self._set_mode_item(
            "browser_dns",
            "Configured",
            self.dns_resolvers.get().strip() or "Default resolvers",
            "info",
        )
        self._set_mode_item(
            "browser_https",
            "Blocked" if exposure == "exposed" else "Ready" if snapshot.get("loopback_10808_open") else "Waiting",
            "Run Check to confirm TLS through the proxy.",
            "fail" if exposure == "exposed" else "pass" if snapshot.get("loopback_10808_open") else "warn",
        )
        self._set_mode_item(
            "browser_result",
            "Run Check",
            "Browser verification is explicit; no system proxy changes are made.",
            "info",
        )

    def _update_network_telemetry(self, proxy_active: bool) -> None:
        now = time.monotonic()
        if proxy_active:
            if self._proxy_active_since is None:
                self._proxy_active_since = now
            self.network_duration.set(format_duration(now - self._proxy_active_since))
            self.network_runtime_hint.set("Core session active on local proxy")
        else:
            self._proxy_active_since = None
            self.network_duration.set("0s")
            self.network_runtime_hint.set("Core not active")
        self._set_dashboard_stat("uptime", "Uptime", self.network_duration.get(), "pass" if proxy_active else "info")

        if now < self._network_next_poll:
            down_rate, up_rate = self._network_last_rates
            if hasattr(self, "metric_down_label"):
                self.metric_down_label.configure(text=format_rate(down_rate), fg=COLORS["blue"])
                self.metric_up_label.configure(text=format_rate(up_rate), fg=COLORS["green"])
            self._draw_sparklines()
            return
        self._network_next_poll = now + NETWORK_REFRESH_MS / 1000.0

        sample = system_network_totals()
        if sample is None:
            self.network_down_rate.set("Unavailable")
            self.network_up_rate.set("Unavailable")
            self.network_total.set("Unavailable")
            self.network_source.set("Counters: local OS network counters unavailable")
            if hasattr(self, "metric_down_label"):
                self.metric_down_label.configure(text="Unavailable", fg=COLORS["muted"])
                self.metric_up_label.configure(text="Unavailable", fg=COLORS["muted"])
            self._draw_sparklines()
            return

        rx, tx, source = sample
        if self._network_baseline is None or rx < self._network_baseline[1] or tx < self._network_baseline[2]:
            self._network_baseline = (now, rx, tx, source)
        last = self._network_last
        if last is None or rx < last[1] or tx < last[2] or now <= last[0]:
            down_rate = 0.0
            up_rate = 0.0
        else:
            elapsed = max(0.001, now - last[0])
            down_rate = (rx - last[1]) / elapsed
            up_rate = (tx - last[2]) / elapsed
        self._network_last_rates = (down_rate, up_rate)
        self._network_last = (now, rx, tx, source)
        assert self._network_baseline is not None
        total_rx = max(0, rx - self._network_baseline[1])
        total_tx = max(0, tx - self._network_baseline[2])

        self.network_down_rate.set(format_rate(down_rate))
        self.network_up_rate.set(format_rate(up_rate))
        self.network_total.set(f"{format_bytes(total_rx)} / {format_bytes(total_tx)}")
        self.network_source.set(f"Counters: {source}; local system traffic since this GUI opened, not payload inspection.")
        if hasattr(self, "metric_down_label"):
            self.metric_down_label.configure(text=format_rate(down_rate), fg=COLORS["blue"])
            self.metric_up_label.configure(text=format_rate(up_rate), fg=COLORS["green"])
        self._draw_sparklines()

    def _update_diagnostic_guidance(self, snapshot: dict[str, object], level: str, detail: str) -> None:
        proxy_endpoint = f"{snapshot.get('proxy_listen')}:{snapshot.get('proxy_port')}"
        if self.last_command_failure:
            label = str(self.last_command_failure.get("label", "Last command"))
            advice = str(self.last_command_failure.get("advice", "Read the last failed output, then run Health Probe."))
            self.diagnostic_title.set(f"Last issue: {label}")
            self.diagnostic_detail.set(str(self.last_command_failure.get("summary", detail)))
            self.diagnostic_action.set(f"Suggested fix: {advice}")
            return
        if snapshot.get("listener_exposure") == "exposed":
            process = str(snapshot.get("listener_name") or "external Xray/v2rayN")
            pid = f" PID {snapshot.get('listener_pid')}" if snapshot.get("listener_pid") else ""
            path = f" Path: {snapshot.get('listener_path')}" if snapshot.get("listener_path") else ""
            self.diagnostic_title.set("Unsafe listener exposed")
            self.diagnostic_detail.set(f"{process}{pid} is listening on {snapshot.get('listener_endpoint') or 'a non-loopback address'}.{path}")
            self.diagnostic_action.set("Configure that external client inbound listen address to 127.0.0.1, then refresh status.")
        elif not snapshot["selected_config_exists"]:
            self.diagnostic_title.set("Primary configuration is missing")
            self.diagnostic_detail.set("The selected Xray config could not be found, so core launch and checks cannot continue.")
            self.diagnostic_action.set("Open the Xray-config folder or run Repair Setup after restoring repository files.")
        elif not snapshot["xray_runtime_ready"] and not snapshot["loopback_10808_open"]:
            self.diagnostic_title.set("Bundled Xray Core is missing")
            self.diagnostic_detail.set("The app can run checks, but Start Core needs xray.exe plus geoip.dat and geosite.dat under the project xray folder.")
            self.diagnostic_action.set("Click Download Xray Core in Repair, or open v2rayN and then run Page Check.")
        elif not snapshot["cert_exists"] or not snapshot["key_exists"]:
            self.diagnostic_title.set("Local CA files are not ready")
            self.diagnostic_detail.set("Browser MITM checks need both mycert.crt and mycert.key. The app never installs trust silently.")
            self.diagnostic_action.set("Generate Local CA, then follow the manual trust-store guide for your browser or OS.")
        elif not snapshot["loopback_10808_open"]:
            self.diagnostic_title.set("No core is listening")
            self.diagnostic_detail.set(f"No local listener is accepting connections on {proxy_endpoint} yet.")
            self.diagnostic_action.set("Start Core from the app, or open v2rayN/Xray before browser tests.")
        elif level == "pass":
            self.diagnostic_title.set("Ready for browser testing")
            if snapshot.get("core_owner") == "external":
                process = str(snapshot.get("listener_name") or "external core")
                self.diagnostic_detail.set(f"{process} is already listening on {proxy_endpoint}. The app will use it and will not stop it.")
            else:
                self.diagnostic_detail.set("The app-launched core is listening, required scripts are present, and certificate files exist.")
            self.diagnostic_action.set("Run Page Check. If a site still fails, run Health Probe and Copy Issue Summary.")
        else:
            self.diagnostic_title.set("Setup needs attention")
            self.diagnostic_detail.set(str(snapshot.get("readiness_next_action_detail") or detail))
            hint = str(snapshot.get("intelligent_hint") or "").strip()
            if hint:
                self.diagnostic_action.set(f"Next: {snapshot.get('readiness_next_action') or 'Run Check Setup'}. Tip: {hint}")
            else:
                self.diagnostic_action.set(f"Next: {snapshot.get('readiness_next_action') or 'Run Check Setup'}.")

    def _update_dashboard_intelligent_hint(self, snapshot: dict[str, object]) -> None:
        if not hasattr(self, "dashboard_hint_frame"):
            return
        hint = str(snapshot.get("intelligent_hint") or "").strip()
        detail = str(snapshot.get("readiness_next_action_detail") or "").strip()
        if hint:
            self.intelligent_hint_text.set(f"Tip: {hint}")
            self.dashboard_hint_frame.pack(fill="x", padx=16, pady=(0, 10))
        elif snapshot.get("readiness_next_action") == "Review Advisor" and detail:
            self.intelligent_hint_text.set(detail)
            self.dashboard_hint_frame.pack(fill="x", padx=16, pady=(0, 10))
        else:
            self.intelligent_hint_text.set("")
            self.dashboard_hint_frame.pack_forget()

    def run_show_smart_tips(self) -> None:
        """Show local intelligent advisor output (same engine as main.py advise)."""
        try:
            from core.intelligent_advisor import build_advisor_plan

            readiness = self.readiness_cache.get(self.active_config_path(), force=True)
            plan = build_advisor_plan(root=ROOT, state=readiness)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Smart tips", f"Could not build advisor plan: {exc}")
            return
        lines = [
            "Smart tips (local only — nothing is uploaded)",
            "",
        ]
        persona = plan.get("persona")
        if persona:
            lines.append(f"Persona: {persona}")
            playbook = plan.get("playbook")
            if isinstance(playbook, dict):
                steps = playbook.get("steps") or []
                if steps:
                    lines.append("Playbook steps:")
                    for step in steps[:6]:
                        if isinstance(step, dict):
                            lines.append(f"  - {step.get('id', '?')}: {step.get('title', '')}")
                    lines.append("")
        suggested = plan.get("suggested_profile")
        if isinstance(suggested, dict) and suggested.get("profile_id"):
            lines.append(
                f"Suggested profile: {suggested.get('profile_id')} "
                f"({suggested.get('confidence', 'unknown')})"
            )
            lines.append(str(suggested.get("reason") or ""))
            lines.append("")
        for rec in plan.get("recommendations") or []:
            if not isinstance(rec, dict):
                continue
            lines.append(f"[{rec.get('priority', '?')}] {rec.get('title', 'Recommendation')}")
            if rec.get("detail"):
                lines.append(f"  {rec['detail']}")
            if rec.get("command"):
                lines.append(f"  Command: {rec['command']}")
            lines.append("")
        commands = plan.get("automation_commands") or []
        if commands:
            lines.append("Automation commands:")
            for cmd in commands[:5]:
                lines.append(f"  {cmd}")
        text = "\n".join(lines).strip() or "No recommendations right now. Run Check Setup first."
        window = tk.Toplevel(self)
        window.title("Smart tips")
        window.configure(bg=COLORS["bg"])
        window.geometry(f"{self._scaled(640)}x{self._scaled(480)}")
        window.transient(self)
        body = tk.Text(
            window,
            bg=COLORS["panel"],
            fg=COLORS["ink"],
            relief="flat",
            wrap="word",
            font=self.fonts["body"],
            padx=self._scaled(14),
            pady=self._scaled(12),
        )
        body.pack(fill="both", expand=True, padx=self._scaled(14), pady=self._scaled(14))
        body.insert("1.0", text)
        body.configure(state="disabled")
        ttk.Button(window, text="Close", style="Soft.TButton", command=window.destroy).pack(pady=(0, self._scaled(12)))
        self.record_telemetry("smart_tips_opened", "info", "Advisor plan shown", {})

    def _failure_advice(self, label: str, code: int, output: str) -> tuple[str, str]:
        lowered = output.lower()
        if code == 124 or "timed out" in lowered:
            return (
                "The command timed out before it could finish.",
                "Check proxy/DNS connectivity, then rerun Health Probe with the same target.",
            )
        if "no module named playwright" in lowered or "playwright" in lowered and "install" in lowered:
            return (
                "The browser diagnostic dependency is missing.",
                "Open Repair and run Install Page Check Tools.",
            )
        if "no module named cloakbrowser" in lowered or "cloakbrowser" in lowered:
            return (
                "Fingerprint tooling is missing or not initialized.",
                "Open Repair and run Install Fingerprint Tools, or use Page Check first.",
            )
        if "xray" in lowered and ("not found" in lowered or "missing" in lowered):
            return (
                "Bundled Xray Core could not be found.",
                "Open Repair and run Download Xray Core, or open v2rayN and rerun Page Check.",
            )
        if "certificate" in lowered or "cert" in lowered or "mycert" in lowered:
            return (
                "Certificate files or trust-store alignment need attention.",
                "Run Certificate Status, then Generate Local CA or open the trust guide.",
            )
        if "address already in use" in lowered or "bind" in lowered and "10808" in lowered:
            return (
                "The local core port is already occupied.",
                "If v2rayN/Xray is intentionally open, use it and run Page Check. Otherwise stop it there or create alternate-port profiles.",
            )
        if "connection refused" in lowered or "proxy-offline" in lowered:
            return (
                "The browser or probe could not reach a local core.",
                "Start Core or open v2rayN, then confirm the core status says Running.",
            )
        if "dns" in lowered or "getaddrinfo" in lowered or "name resolution" in lowered:
            return (
                "DNS resolution or resolver reachability failed.",
                "Run the DNS sweep in Profiles and DNS, then run Health Probe.",
            )
        if "permission denied" in lowered or "access is denied" in lowered:
            return (
                "Windows denied access to a file, process, or helper executable.",
                "Close apps using the files, check antivirus/quarantine, then rerun the same action.",
            )
        if "json" in lowered and ("decode" in lowered or "invalid" in lowered):
            return (
                "A generated or selected JSON file is malformed.",
                "Run Repair Setup to regenerate derived profiles and validate metadata.",
            )
        return (
            f"{label} exited with code {code}.",
            "Read the last failed lines, run Health Probe, then Copy Issue Summary for support.",
        )

    def _set_label_state(self, label: tk.Label, text: str, level: str) -> None:
        color = {"pass": COLORS["green"], "warn": COLORS["amber"], "fail": COLORS["red"], "info": COLORS["blue"]}.get(level, COLORS["muted"])
        label.configure(text=text, fg=color)

    def _show_remediation_banner(self, level: str, code: str, message: str, action_text: str, action: Callable[[], None]) -> None:
        self._clear_remediation_banner()
        palette = {
            "fail": (COLORS["red_soft"], "#f6c4bf", "#9a2018", COLORS["red"], "shield"),
            "warn": (COLORS["amber_soft"], "#f3d9a6", COLORS["amber"], COLORS["amber"], "info"),
            "info": (COLORS["blue_soft"], COLORS["blue_ring"], COLORS["blue_dark"], COLORS["blue"], "info"),
        }.get(level, (COLORS["blue_soft"], COLORS["blue_ring"], COLORS["blue_dark"], COLORS["blue"], "info"))
        bg, border, fg, button_bg, icon = palette
        banner = tk.Frame(self.banner_slot, bg=bg, highlightbackground=border, highlightthickness=1)
        banner.pack(fill="x")
        tk.Frame(banner, bg=button_bg, width=self._scaled(4)).pack(side="left", fill="y")
        self._icon_canvas(banner, icon, button_bg, 22, bg).pack(side="left", padx=(self._scaled(12), 0), pady=self._scaled(10))
        text_block = tk.Frame(banner, bg=bg)
        text_block.pack(side="left", fill="x", expand=True, padx=self._scaled(12), pady=self._scaled(10))
        tk.Label(text_block, text=f"{code}: {message}", bg=bg, fg=fg, font=self.fonts["body_bold"], anchor="w", justify="left", wraplength=self._scaled(680)).pack(fill="x")
        tk.Label(text_block, text="This is advisory; no system trust store or proxy setting is changed silently.", bg=bg, fg=fg, font=self.fonts["caption"], anchor="w", justify="left").pack(fill="x", pady=(self._scaled(2), 0))
        tk.Button(
            banner,
            text=action_text,
            command=action,
            bg=button_bg,
            fg="#ffffff",
            activebackground=COLORS["blue_dark"] if button_bg == COLORS["blue"] else button_bg,
            activeforeground="#ffffff",
            relief="flat",
            borderwidth=0,
            cursor="hand2",
            padx=self._scaled(14),
            pady=self._scaled(8),
            font=self.fonts["body_bold"],
        ).pack(side="right", padx=self._scaled(14), pady=self._scaled(10))
        self.active_banner = banner

    def _clear_remediation_banner(self) -> None:
        if self.active_banner is not None:
            self.active_banner.destroy()
            self.active_banner = None

    def _update_remediation_banner(self, snapshot: dict[str, object], level: str) -> None:
        if snapshot.get("listener_exposure") == "exposed":
            process = str(snapshot.get("listener_name") or "external Xray/v2rayN")
            endpoint = str(snapshot.get("listener_endpoint") or "0.0.0.0")
            self._show_remediation_banner(
                "fail",
                "LISTENER-EXPOSED",
                f"{process} is bound to {endpoint}; expected 127.0.0.1 only.",
                "Open Health",
                lambda: self._select_workspace(self.health_tab),
            )
        elif not snapshot["selected_config_exists"]:
            self._show_remediation_banner("fail", "CONFIG-MISSING", "Primary configuration is missing.", "Open Xray-config", lambda: self.open_path(ROOT / "Xray-config"))
        elif not snapshot["xray_runtime_ready"] and not snapshot["loopback_10808_open"]:
            self._show_remediation_banner("warn", "CORE-MISSING", "Bundled Xray Core files are missing or incomplete.", "Download Xray Core", self.download_xray)
        elif not snapshot["cert_exists"] or not snapshot["key_exists"]:
            self._show_remediation_banner("warn", "CA-MISSING", "Local CA files are missing; browser MITM tests will fail until they exist and are trusted manually.", "Generate Local CA", self.generate_ca)
        elif not snapshot["loopback_10808_open"]:
            self._show_remediation_banner("info", "CORE-OFFLINE", "No local core is listening yet. Start bundled Xray Core, or open v2rayN before testing.", "Start Core", self.connect_xray)
        elif level == "pass":
            self._clear_remediation_banner()
        else:
            self._show_remediation_banner("warn", "SETUP-ATTENTION", str(self.overall_detail.get()), "Run Check Setup", self.run_beginner_setup_check)

    def _set_busy_state(self, busy: bool, label: str = "") -> None:
        self.is_busy = busy
        self.configure(cursor="watch" if busy else "")
        state = "disabled" if busy else "normal"
        for widget in self.busy_controls:
            try:
                widget.configure(state=state)
            except tk.TclError:
                pass
        if hasattr(self, "task_progress"):
            if busy:
                self.task_progress.start(10)
            else:
                self.task_progress.stop()
        if label:
            self.current_process_label.set(f"Running: {label}" if busy else label)

    def run_status_snapshot(self) -> None:
        snapshot = self._status_snapshot()
        level, detail = self._status_level(snapshot)
        self.record_telemetry("status_snapshot", level, detail, snapshot)
        self.refresh_status()
        self._append_output("\nStatus snapshot:\n" + json.dumps({"status": level, "detail": detail, "snapshot": snapshot}, indent=2) + "\n")

    def show_telemetry_summary(self) -> None:
        events = self._telemetry_events(limit=25)
        if not events:
            self._append_output("\nNo local GUI activity events recorded yet.\n")
            return
        self._append_output("\nRecent local GUI activity:\n" + json.dumps(events, indent=2) + "\n")

    def export_telemetry(self) -> None:
        events = self._telemetry_events()
        target = LOCAL_STATE / "gui-telemetry-export.diagnostic.json"
        LOCAL_STATE.mkdir(exist_ok=True)
        target.write_text(json.dumps({"events": events}, indent=2), encoding="utf-8")
        self.record_telemetry("telemetry_exported", "info", short_path(target), {"event_count": len(events)})
        self._append_output(f"\nExported local activity history: {short_path(target)}\n")

    def clear_telemetry(self) -> None:
        self._ram_telemetry_events.clear()
        if GUI_TELEMETRY.exists():
            try:
                GUI_TELEMETRY.unlink()
            except OSError as exc:
                messagebox.showerror("Clear activity history failed", str(exc))
                return
        for history in self.sparkline_history.values():
            history.clear()
        self._update_telemetry_labels(None)
        self._append_output("\nCleared local GUI activity history.\n")

    def choose_browser_path(self) -> None:
        initial = self.browser_executable.get().strip()
        initialdir = str(Path(initial).parent) if initial and Path(initial).parent.exists() else str(ROOT)
        path = filedialog.askopenfilename(
            title="Choose browser executable",
            initialdir=initialdir,
            filetypes=[("Executables", "*.exe"), ("All files", "*.*")] if os.name == "nt" else [("All files", "*.*")],
        )
        if path:
            self.browser_executable.set(path)
            self.record_telemetry("browser_path_selected", "info", "Browser executable path set", {"path_set": True})
            self._append_output(f"\nBrowser path set: {path}\n")

    def _profile_choices(self) -> list[str]:
        return list(self._profile_lookup().keys())

    def _profile_display_name(self, path: Path) -> str:
        try:
            rel = path.relative_to(ROOT)
        except ValueError:
            rel = path
        if path.resolve() == CONFIG.resolve():
            return f"Standard (recommended) - {rel}"
        name = path.name
        label = name.removeprefix("Xray-Cooperative-Overlay.").removesuffix(".json")
        label = label.replace(".altports", " alternate ports")
        friendly = {
            "strict": "Strict (advanced)",
            "balanced": "Balanced",
            "compatibility": "Compatibility (troubleshooting)",
            "debug": "Debug (advanced)",
            "evasion-fragment": "Evasion fragment (lab)",
            "evasion-reality-stub": "Evasion REALITY stub (lab)",
            "evasion-tun-stub": "Evasion TUN stub (lab)",
            "evasion-fakedns": "Evasion FakeDNS (lab)",
            "evasion-high-stealth": "Evasion high stealth (lab)",
        }.get(label, label.replace(".", " ").title())
        return f"{friendly} - {rel}"

    def _profile_lookup(self) -> dict[str, Path]:
        paths = [CONFIG]
        paths.extend(path for path in sorted((ROOT / "Xray-config").glob("Xray-Cooperative-Overlay.*.json")) if path.resolve() != CONFIG.resolve())
        return {self._profile_display_name(path): path for path in paths}

    def _select_profile(self, _event: object | None = None) -> None:
        path = self.active_config_path()
        self.active_config.set(str(path))
        endpoint = config_proxy_endpoint(path)
        proxy_url = f"socks5://{browser_proxy_host(endpoint.get('listen'))}:{endpoint.get('port') or 10808}"
        current_proxy = self.browser_proxy.get().strip()
        if not current_proxy or current_proxy == self.last_profile_proxy_url or current_proxy == "socks5://127.0.0.1:10808":
            self.browser_proxy.set(proxy_url)
            self.last_profile_proxy_url = proxy_url
        self.refresh_status()

    def active_config_path(self) -> Path:
        raw = self.profile_selection.get().strip()
        lookup = self._profile_lookup()
        if raw in lookup:
            return lookup[raw]
        raw = self.active_config.get().strip()
        path = Path(raw) if raw else CONFIG
        if not path.is_absolute():
            path = ROOT / path
        return path

    def _xray_running_from_gui(self) -> bool:
        return self.xray_process is not None and self.xray_process.poll() is None

    def connect_xray(self) -> None:
        if self._xray_running_from_gui():
            self._append_output("\nXray is already running from this app.\n")
            self.record_telemetry("xray_connect", "info", "Already running from GUI")
            self.refresh_status()
            return
        config_path = self.active_config_path()
        proxy_endpoint = config_proxy_endpoint(config_path)
        proxy_port = int(proxy_endpoint.get("port") or 10808)
        if port_accepts_loopback(proxy_port):
            info = listener_process_info(proxy_port)
            process = info.get("name") or "external process"
            pid = info.get("pid") or "unknown PID"
            endpoint = info.get("endpoint") or f"127.0.0.1:{proxy_port}"
            self._append_output(
                f"\nExternal core already active on {endpoint}: {process} ({pid}). "
                "This app will use it for checks and will not stop it.\n",
                stream="xray",
            )
            self.record_telemetry("xray_connect", "info", "External listener already active", {"port": proxy_port, **info})
            self.refresh_status()
            return
        xray = find_local_xray()
        if xray is None:
            self._append_output("\nBundled Xray Core not found. Use Download Xray Core, then Start Core again, or open v2rayN.\n")
            self.record_telemetry("xray_connect", "warn", "Local Xray binary not found")
            if messagebox.askyesno("Xray Core not found", "Download bundled Xray Core runtime now?"):
                self.download_xray()
            return
        if not config_path.exists():
            messagebox.showerror("Missing config", f"Selected config not found: {short_path(config_path)}")
            return
        key_report = ensure_key_material_available(KEY)
        if key_report.status != "pass":
            messagebox.showerror("Private key", key_report.detail)
            self.record_telemetry("xray_connect", "fail", "Private key unavailable", {"detail": key_report.detail})
            return
        if self.gui_preferences.block_connect_on_preflight_fail:
            snapshot = self._status_snapshot()
            _level, blockers = evaluate_startup_gate(snapshot, cached_preflight=load_cached_preflight())
            if blockers:
                lines = "\n".join(f"• {item}" for item in blocker_messages(blockers))
                messagebox.showerror(
                    "Connect blocked",
                    f"Preflight gate failed:\n\n{lines}\n\nRun Full Preflight, fix the issue, or disable blocking in Settings.",
                )
                self.record_telemetry("xray_connect", "fail", "Preflight gate blocked connect", {"blockers": blockers})
                return
        try:
            self.xray_supervisor = ProcessSupervisor(xray, ["run", "-config", str(config_path)], ROOT)
            self.xray_process = self.xray_supervisor.spawn()
        except Exception as exc:  # noqa: BLE001
            self.xray_supervisor = None
            self.xray_process = None
            messagebox.showerror("Connect failed", str(exc))
            self._append_output(f"\nFailed to start Xray: {exc}\n")
            self.record_telemetry("xray_connect", "fail", "Failed to start Xray")
            return
        self._append_output(f"\nStarted bundled Xray Core: {short_path(xray)}\nConfig: {short_path(config_path)}\n")
        self.stream_count = 0
        if hasattr(self, "metric_stream_label"):
            self.metric_stream_label.configure(text="0 Seen")
        self.record_telemetry("xray_connect", "info", "Started GUI-launched Xray", {"xray_path": short_path(xray), "config": short_path(config_path)})
        self.current_process_label.set("Xray Core starting")
        threading.Thread(target=self._read_xray_output, daemon=True).start()
        self.after(900, self.refresh_status)

    def _read_xray_output(self) -> None:
        proc = self.xray_process
        if proc is None or proc.stdout is None:
            return
        for line in proc.stdout:
            self.after(0, lambda item=line: self._handle_xray_log_line(item))
        try:
            code = proc.wait(timeout=0.2)
        except Exception:
            code = proc.poll()
        self.after(0, lambda: self._handle_xray_exit(proc, code))

    def _handle_xray_exit(self, proc: subprocess.Popen[str], code: int | None) -> None:
        if self.xray_process is proc:
            self.xray_process = None
            self.xray_supervisor = None
        self.stream_count = 0
        self.record_telemetry("xray_exit", "info" if code == 0 else "warn", "Xray process exited", {"exit_code": code})
        self._append_output(f"\nXray process exited with code {code}\n")
        self.refresh_status()

    def _handle_xray_log_line(self, line: str) -> None:
        self._append_output("[xray] " + line, stream="xray")
        if "accepted" in line.lower():
            self.stream_count += 1
            if hasattr(self, "metric_stream_label"):
                self.metric_stream_label.configure(text=f"{self.stream_count} Seen")

    def disconnect_xray(self) -> None:
        if not self._xray_running_from_gui():
            proxy_port = int(config_proxy_endpoint(self.active_config_path()).get("port") or 10808)
            if port_accepts_loopback(proxy_port):
                messagebox.showinfo(
                    "External core detected",
                    f"Port {proxy_port} is open, but this app did not launch that process. Stop it in v2rayN/Xray or your process manager.",
                )
                self._append_output("\nExternal core left running. This app stops only the Xray process it launched.\n")
                self.record_telemetry("xray_disconnect", "info", "External listener left untouched")
            else:
                self._append_output("\nNo GUI-launched Xray process is running.\n")
                self.record_telemetry("xray_disconnect", "info", "No GUI-launched process running")
            self.refresh_status()
            return
        assert self.xray_process is not None
        self._stop_gui_xray()
        self.stream_count = 0
        self._append_output("\nStopped app-launched Xray Core.\n")
        self.record_telemetry("xray_disconnect", "info", "Stopped GUI-launched Xray")
        self.current_process_label.set("Xray Core stopped")
        self.refresh_status()

    def _stop_gui_xray(self) -> None:
        proc = self.xray_process
        if proc is None or proc.poll() is not None:
            self.xray_process = None
            self.xray_supervisor = None
            return
        if self.xray_supervisor:
            self.xray_supervisor.terminate()
        elif os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                **hidden_subprocess_kwargs(),
            )
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        else:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        self.xray_process = None
        self.xray_supervisor = None

    def close_app(self) -> None:
        self._status_loop_running = False
        if self._xray_running_from_gui():
            self.record_telemetry("app_closed", "info", "Stopping GUI-launched Xray before close")
            self._stop_gui_xray()
        else:
            self.record_telemetry("app_closed", "info", "GUI closed")
        self.destroy()

    def run_beginner_setup_check(self) -> None:
        steps = [
            ("Validate config", py_script("validate_config.py", str(CONFIG)), 120),
            ("Static preflight", py_script("preflight.py", "--config", str(CONFIG), "--no-dns", "--skip-cert", "--skip-runtime"), 120),
            ("Transport profile policy", py_script("transport_profile_validate.py"), 120),
            ("UDP/443 profile policy", py_script("protocol_smoke.py", "--scenario", "udp443-policy"), 120),
            ("Secret scan", py_script("secret_scan.py"), 120),
        ]
        self.run_sequence("Beginner setup check", steps)

    def refresh_status(self) -> None:
        selected_config = self.active_config_path()
        self.active_config.set(str(selected_config))
        profile_choices = self._profile_choices()
        selected_label = self._profile_display_name(selected_config)
        if hasattr(self, "profile_box"):
            self.profile_box.configure(values=profile_choices)
        if selected_label in profile_choices and self.profile_selection.get() != selected_label:
            self.profile_selection.set(selected_label)
        try:
            data = read_json_config() if selected_config == CONFIG else json.loads(selected_config.read_text(encoding="utf-8")) if selected_config.exists() else {}
        except Exception:
            data = {}
        remarks = data.get("remarks", "unknown")
        min_version = data.get("version", {}).get("min") if isinstance(data.get("version"), dict) else "unknown"
        profiles = sorted((ROOT / "Xray-config").glob("Xray-Cooperative-Overlay.*.json"))
        snapshot = self._status_snapshot()
        level, detail = self._status_level(snapshot)
        self.status_refresh_count += 1
        loopback_open = bool(snapshot["loopback_10808_open"])
        cert_ok = bool(snapshot["cert_exists"] and snapshot["key_exists"])
        self._update_telemetry_labels()
        if level == "pass" and self.last_command_failure:
            self.last_command_failure = None
        status_text = {"pass": "Ready", "warn": "Needs Attention", "fail": "Blocked"}.get(level, "Checking")
        self.overall_status.set(status_text)
        self.overall_detail.set(detail)
        status_bg = {
            "pass": COLORS["green_soft"],
            "warn": COLORS["amber_soft"],
            "fail": COLORS["red_soft"],
        }.get(level, COLORS["blue_soft"])
        status_fg = {"pass": COLORS["green"], "warn": COLORS["amber"], "fail": COLORS["red"]}.get(level, COLORS["blue"])
        self.header_status_label.configure(bg=status_bg, fg=status_fg, font=self.fonts["micro"])
        if level != self.last_status_level:
            self.record_telemetry("status_changed", level, detail, {"previous": self.last_status_level})
            self.last_status_level = level
        exposure = str(snapshot.get("listener_exposure") or "unknown")
        if exposure == "exposed":
            external_name = str(snapshot.get("listener_name") or "external core")
            self.connection_state.set(f"Unsafe external listener: {external_name}")
            self.simple_next_step.set("Fix the external Xray/v2rayN inbound binding to 127.0.0.1 before treating the setup as ready.")
            self.connection_label.configure(fg=COLORS["red"])
        elif self._xray_running_from_gui():
            self.connection_state.set("App core running")
            self.simple_next_step.set("Bundled Xray Core is running from this app. Test the browser, then review Health if anything fails.")
            self.connection_label.configure(fg=COLORS["green"])
        elif loopback_open:
            external_name = str(snapshot.get("listener_name") or "external core")
            self.connection_state.set(f"External core active: {external_name}")
            self.simple_next_step.set(f"A local core is already listening on {snapshot.get('proxy_listen')}:{snapshot.get('proxy_port')}. The app will use it for Page Check and will not stop it.")
            self.connection_label.configure(fg=COLORS["green"])
        else:
            self.connection_state.set("No core listening")
            self.simple_next_step.set("Run Check Setup, then Start Core or open v2rayN before testing the browser.")
            self.connection_label.configure(fg=COLORS["amber"])
        self._set_readiness_primary_action(snapshot)
        if self.last_command_failure:
            self._set_primary_action("Run Health Probe", "A recent command needs attention. Collect a redacted health snapshot next.", self.run_health_probe, "amber")
        if hasattr(self, "metric_tunnel_label"):
            if self._xray_running_from_gui():
                self.metric_tunnel_label.configure(text="ACTIVE", fg=COLORS["green"])
            elif exposure == "exposed":
                self.metric_tunnel_label.configure(text="EXPOSED", fg=COLORS["red"])
            elif loopback_open:
                self.metric_tunnel_label.configure(text="EXTERNAL", fg=COLORS["green"])
            else:
                self.metric_tunnel_label.configure(text="OFFLINE", fg=COLORS["amber"])
            self.metric_stream_label.configure(text=f"{self.stream_count} Seen")
            next_text = str(snapshot.get("readiness_next_action") or "Check Setup")
            self.metric_next_label.configure(text=next_text, fg=COLORS["red"] if exposure == "exposed" else COLORS["blue"] if loopback_open else COLORS["amber"])
            self.metric_refresh_label.configure(text=f"{STATUS_REFRESH_MS // 1000}s / {self.status_refresh_count}", fg=COLORS["blue"])
        if hasattr(self, "proxy_control_status_label"):
            proxy_state = "Exposed" if exposure == "exposed" else "Running" if loopback_open else "Stopped"
            proxy_level = "fail" if exposure == "exposed" else "pass" if loopback_open else "warn"
            pill_bg = {"pass": COLORS["green_soft"], "warn": COLORS["amber_soft"], "fail": COLORS["red_soft"], "info": COLORS["blue_soft"]}.get(proxy_level, COLORS["panel_soft"])
            pill_fg = {"pass": COLORS["green"], "warn": COLORS["amber"], "fail": COLORS["red"], "info": COLORS["blue"]}.get(proxy_level, COLORS["muted"])
            self.proxy_control_status_label.configure(text=proxy_state, bg=pill_bg, fg=pill_fg)
        self.auto_refresh_state.set(f"Auto refresh: every {STATUS_REFRESH_MS // 1000}s, {self.status_refresh_count} checks")
        self._update_readiness_items(snapshot, selected_config)
        self._update_preflight_items(snapshot)
        self._update_runtime_items(snapshot)
        self._update_dashboard_stats(snapshot, level, status_text)
        self._update_network_mode_items(snapshot)
        self._update_network_telemetry(loopback_open)
        self._update_diagnostic_guidance(snapshot, level, detail)
        self._update_dashboard_intelligent_hint(snapshot)
        if "Setup" in self.status_chip_labels:
            self._set_label_state(self.status_chip_labels["Setup"], status_text, level)
        if "Core" in self.status_chip_labels:
            self._set_label_state(
                self.status_chip_labels["Core"],
                "Exposed" if exposure == "exposed" else "Running" if loopback_open else "Stopped",
                "fail" if exposure == "exposed" else "pass" if loopback_open else "warn",
            )
        if "Certificate" in self.status_chip_labels:
            cert_level = "fail" if snapshot.get("cert_key_match") == "mismatch" else "warn" if snapshot.get("trust_status") not in {"pass", "not_supported", "skipped"} else "pass"
            cert_text = "Mismatch" if snapshot.get("cert_key_match") == "mismatch" else "Trust check" if cert_ok and cert_level == "warn" else "Ready" if cert_ok else "Missing"
            self._set_label_state(self.status_chip_labels["Certificate"], cert_text, cert_level if cert_ok else "warn")
        browser_ok = bool(snapshot["diagnostics_script"] and snapshot["stealth_script"])
        if "Browser" in self.status_chip_labels:
            self._set_label_state(self.status_chip_labels["Browser"], "Ready" if browser_ok else "Missing tools", "pass" if browser_ok else "warn")
        if "Privacy" in self.status_chip_labels:
            self._set_label_state(self.status_chip_labels["Privacy"], "Local only", "info")
        self.status_labels["Config"].configure(text=f"{short_path(selected_config)}\nremarks: {remarks}\nXray min: {min_version}", fg=COLORS["green"] if selected_config.exists() else COLORS["red"])
        self.status_labels["Certificate"].configure(text=f"crt: {'present' if CERT.exists() else 'missing'}\nkey: {'present' if KEY.exists() else 'missing'}\nlocal only, ignored by git", fg=COLORS["green"] if CERT.exists() and KEY.exists() else COLORS["amber"])
        lab_profiles = sum(1 for path in profiles if ".evasion-" in path.name)
        profile_lines = f"{len(profiles)} profile configs\nstrict / balanced / compatibility / debug"
        if lab_profiles:
            profile_lines += f"\n+ {lab_profiles} lab evasion profile(s)"
        self.status_labels["Profiles"].configure(
            text=profile_lines,
            fg=COLORS["green"] if len(profiles) >= 4 else COLORS["amber"],
        )
        lock_path = ROOT / "release-geodata-lock.json"
        health_lines = [
            f"geodata lock: {'present' if lock_path.exists() else 'optional'}",
            "Health / Lab Evidence / Decision Report",
            "on Health tab",
        ]
        self.status_labels["Health"].configure(text="\n".join(health_lines), fg=COLORS["green"] if lock_path.exists() else COLORS["amber"])
        host_python = find_host_python()
        runtime = xray_runtime_status()
        local_xray = runtime["executable"]
        dep_lines = [
            f"Python: {'found' if host_python else 'missing'}",
            f"Bundled core: {short_path(local_xray) if local_xray else 'missing'}",
            f"Geodata: {'ready' if runtime['geoip_exists'] and runtime['geosite_exists'] else 'incomplete'}",
            "Install buttons available",
        ]
        self.status_labels["Dependencies"].configure(text="\n".join(dep_lines), fg=COLORS["green"] if host_python and runtime["ready"] else COLORS["amber"])
        browser_cfg = read_browser_integration()
        proxy = browser_cfg.get("default_proxy", "socks5://127.0.0.1:10808")
        diag_ok = (SCRIPTS / "browser_diagnostics.py").exists()
        stealth_ok = (SCRIPTS / "browser_stealth.py").exists()
        self.status_labels["Browser"].configure(
            text=f"proxy: {self.browser_proxy.get().strip() or proxy}\nbrowser: {self.browser_executable.get().strip() or 'bundled/default'}\npage check: {'ready' if diag_ok else 'missing'}",
            fg=COLORS["green"] if diag_ok and stealth_ok else COLORS["amber"],
        )
        self.status_labels["Privacy"].configure(text="Local activity history only\nNo automatic uploads\nNo silent trust install", fg=COLORS["green"])
        self._update_remediation_banner(snapshot, level)

    def run_spec(self, spec: CommandSpec) -> None:
        self.run_async(spec.label, list(spec.args))

    def run_async(self, label: str, args: list[str], timeout: int = 120, after: Callable[[int, str], None] | None = None) -> None:
        if self.is_busy:
            self._append_output(f"\nAnother task is already running. Wait for it to finish before starting: {label}\n", stream="sys")
            return
        self._set_busy_state(True, label)
        self._append_output(f"\n$ {' '.join(args)}\n", stream="sys")
        self.record_telemetry("command_started", "info", label)

        def worker() -> None:
            started = time.perf_counter()
            try:
                code, output = run_command(args, timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                code, output = 124, f"Timed out after {exc.timeout} seconds"
            except Exception as exc:  # noqa: BLE001
                code, output = 1, str(exc)
            duration_ms = int((time.perf_counter() - started) * 1000)
            self.after(0, lambda: self._finish_command(label, code, output, after, duration_ms))

        threading.Thread(target=worker, daemon=True).start()

    def run_sequence(self, label: str, steps: list[tuple[str, list[str], int]]) -> None:
        if self.is_busy:
            self._append_output(f"\nAnother task is already running. Wait for it to finish before starting: {label}\n", stream="sys")
            return
        self._set_busy_state(True, label)
        self._append_output(f"\n== {label} ==\n", stream="audit")
        self.record_telemetry("sequence_started", "info", label, {"steps": len(steps)})

        def worker() -> None:
            started = time.perf_counter()
            chunks: list[str] = []
            final_code = 0
            for step_label, args, timeout in steps:
                chunks.append(f"\n-- {step_label} --\n$ {' '.join(args)}")
                try:
                    code, output = run_command(args, timeout=timeout)
                except subprocess.TimeoutExpired as exc:
                    code, output = 124, f"Timed out after {exc.timeout} seconds"
                except Exception as exc:  # noqa: BLE001
                    code, output = 1, str(exc)
                if output:
                    chunks.append(output)
                chunks.append(f"[{'OK' if code == 0 else 'Needs attention'}] {step_label} exited with code {code}")
                if code != 0:
                    _, advice = self._failure_advice(step_label, code, output)
                    chunks.append(f"Suggested next step: {advice}")
                if code != 0 and final_code == 0:
                    final_code = code
            text = "\n".join(chunks)
            duration_ms = int((time.perf_counter() - started) * 1000)
            self.after(0, lambda: self._finish_command(label, final_code, text, None, duration_ms))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_command(self, label: str, code: int, output: str, after: Callable[[int, str], None] | None, duration_ms: int | None = None) -> None:
        status = "OK" if code == 0 else "Needs attention"
        guidance = ""
        if code != 0:
            summary, advice = self._failure_advice(label, code, output)
            self.last_command_failure = {
                "label": label,
                "summary": summary,
                "advice": advice,
                "exit_code": code,
            }
            guidance = f"\nSuggested next step: {advice}\n"
        else:
            self.last_command_failure = None
        self._append_output(f"{output}\n[{status}] {label} exited with code {code}{guidance}\n", stream="audit")
        self.current_process_label.set(f"{label}: {status}")
        self.record_telemetry(
            "command_finished",
            "pass" if code == 0 else "warn",
            label,
            {"exit_code": code, "duration_ms": duration_ms},
        )
        if after:
            after(code, output)
        self._set_busy_state(False, f"{label}: {status}")
        self.refresh_status()

    def _append_output(self, text: str, stream: str | None = None) -> None:
        if self.log_multiplexer:
            self.log_multiplexer.enqueue(text, stream)
            if hasattr(self, "output_body") and not self.output_visible.get():
                self.logs_have_unread = True
                self.output_toggle_text.set("Show Logs *")
            return
        if hasattr(self, "output"):
            self.output.configure(state="normal")
            self.output.insert("end", text)
            self.output.configure(state="disabled")
            self.output.see("end")

    def copy_output(self) -> None:
        if self.output_buffers:
            sections = []
            for name, widget in self.output_buffers.items():
                sections.append(f"== {name.upper()} ==\n{widget.get('1.0', 'end').strip()}")
            text = "\n\n".join(sections).strip()
        else:
            text = self.output.get("1.0", "end").strip()
        self.clipboard_clear()
        self.clipboard_append(text)
        self.current_process_label.set("Output copied")

    def explain_output(self) -> None:
        self._append_output(
            "\nOutput guide:\n"
            "  OK: the check completed successfully.\n"
            "  Needs attention: read the last lines above first; they usually name the missing file, dependency, port, or route.\n"
            "  Windows proxy warning: review system proxy settings to avoid proxy loops.\n"
            "  Missing certificate: use Generate Local CA, then install mycert.crt manually into the intended trust store.\n"
            "  Browser dependency errors: use Install Page Check Tools or Install Fingerprint Tools in Repair.\n"
        )

    def copy_issue_summary(self) -> None:
        data = read_json_config()
        profiles = sorted((ROOT / "Xray-config").glob("Xray-Cooperative-Overlay.*.json"))
        summary = "\n".join([
            "Xray-Cooperative-Overlay redacted issue summary",
            f"Config: {short_path(CONFIG)}",
            f"Remarks: {data.get('remarks', 'unknown')}",
            f"Xray min: {data.get('version', {}).get('min') if isinstance(data.get('version'), dict) else 'unknown'}",
            f"Certificate present: crt={CERT.exists()} key={KEY.exists()}",
            f"Generated profiles: {len(profiles)}",
            f"Host Python: {' '.join(find_host_python() or ['missing'])}",
            f"Local Xray: {short_path(find_local_xray()) if find_local_xray() else 'missing'}",
            f"Geodata lock: {(ROOT / 'release-geodata-lock.json').exists()}",
            "Run Health tab -> Lab Evidence / Decision Report before filing DNS or captive portal issues.",
            "Sensitive data intentionally omitted: private keys, cookies, full URLs, request bodies.",
        ])
        self.clipboard_clear()
        self.clipboard_append(summary)
        self._append_output("\nCopied redacted issue summary to clipboard.\n" + summary + "\n")
        self.current_process_label.set("Issue summary copied")

    def generate_standard_profiles(self) -> None:
        self.run_async("Generate standard profiles", py_script("generate_profiles.py", "--base", str(CONFIG)))

    def generate_alt_profiles(self) -> None:
        try:
            offset = int(self.profile_offset.get())
        except ValueError:
            messagebox.showerror("Invalid offset", "Port offset must be an integer.")
            return
        suffix = self.profile_suffix.get().strip() or ".altports"
        args = py_script("generate_profiles.py", "--base", str(CONFIG), "--out-dir", str(ROOT / "Xray-config"), "--port-offset", str(offset), "--suffix", suffix)
        self.run_async("Generate alternate profiles", args)

    def run_dns_sweep(self) -> None:
        domain = self.dns_domain.get().strip()
        if not domain:
            messagebox.showerror("Missing domain", "Enter a domain to query.")
            return
        args = py_script("check_dns.py", "--domain", domain, "--all-types")
        for resolver in [item.strip() for item in self.dns_resolvers.get().split(",") if item.strip()]:
            args.extend(["--resolver", resolver])
        self.run_async("DNS query type sweep", args, timeout=45)

    def run_health_probe(self) -> None:
        args = py_script(
            "health_probe.py",
            "--config",
            str(CONFIG),
            "--cert",
            str(CERT),
            "--key",
            str(KEY),
            "--providers-dir",
            str(ROOT / "providers"),
            "--dns-domain",
            self.dns_domain.get().strip() or "example.com",
        )
        for resolver in [item.strip() for item in self.dns_resolvers.get().split(",") if item.strip()]:
            args.extend(["--resolver", resolver])
        xray = find_local_xray()
        if xray is not None:
            args.extend(["--xray-bin", str(xray)])
        self.run_async("Health probe", args, timeout=180)

    def run_platform_capability_check(self) -> None:
        self.run_async("Platform capability", py_script("platform_capability_check.py"), timeout=60)

    def run_trust_store_check(self) -> None:
        self.run_async("Trust store check", py_script("trust_store_check.py", "--cert", str(CERT)), timeout=60)

    def run_fakedns_recovery_check(self) -> None:
        domain = self.dns_domain.get().strip() or "example.com"
        self.run_async("FakeDNS recovery check", py_script("fakedns_recovery_check.py", "--domain", domain), timeout=90)

    def run_lab_evidence(self) -> None:
        LOCAL_STATE.mkdir(parents=True, exist_ok=True)
        report_path = LOCAL_STATE / "lab-evidence.latest.json"
        self.run_async(
            "Lab evidence bundle",
            py_script("lab_evidence_run.py", "--allow-warn", "--json-out", str(report_path)),
            timeout=240,
            after=lambda code, output: self._after_lab_evidence(code, output, report_path),
        )

    def run_decision_report(self) -> None:
        LOCAL_STATE.mkdir(parents=True, exist_ok=True)
        report_path = LOCAL_STATE / "decision-report.latest.json"
        target = self.dns_domain.get().strip() or "www.google.com"
        config_path = self.active_config_path()
        profile_intent = self._active_profile_intent()
        self.run_async(
            "Decision report",
            py_script(
                "decision_report.py",
                "--config",
                str(config_path),
                "--cert",
                str(CERT),
                "--key",
                str(KEY),
                "--profile",
                profile_intent,
                "--target",
                target,
                "--provider-family",
                "unknown",
                "--session-counter",
                str(self.status_refresh_count),
                "--json-out",
                str(report_path),
            ),
            timeout=120,
            after=lambda code, output: self._after_decision_report(code, output, report_path),
        )

    def run_path_scorer(self) -> None:
        report_path = LOCAL_STATE / "decision-report.latest.json"
        if not report_path.exists():
            messagebox.showwarning(
                "Decision report missing",
                "Run Decision Report first, then use Score Decision Report.",
            )
            return
        self.run_async("Score decision report", py_script("path_scorer.py", "--input", str(report_path), "--compact"), timeout=60)

    def _after_decision_report(self, code: int, output: str, report_path: Path) -> None:
        if code != 0:
            return
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            try:
                data = json.loads(report_path.read_text(encoding="utf-8"))
            except Exception:
                return
        if not isinstance(data, dict):
            return
        phase_diag = data.get("phase_diagnostics")
        if not isinstance(phase_diag, dict):
            return
        phase = str(phase_diag.get("phase_classification", "unknown"))
        confidence = phase_diag.get("confidence_score", 0.0)
        recommendation = phase_diag.get("actionable_recommendation", {})
        action = recommendation.get("action", "manual_review_required") if isinstance(recommendation, dict) else "manual_review_required"
        reason = recommendation.get("reason", "") if isinstance(recommendation, dict) else ""
        strategy = data.get("strategy_recommendation") if isinstance(data.get("strategy_recommendation"), dict) else {}
        strategy_id = strategy.get("selected_profile_id", "")
        strategy_reason = strategy.get("reason", "")
        self._append_output(
            "\nPhase diagnostics summary:\n"
            f"  phase: {phase}\n"
            f"  confidence: {confidence}\n"
            f"  action: {action}\n"
            f"  reason: {reason}\n"
            + (f"  strategy_profile: {strategy_id}\n  strategy_reason: {strategy_reason}\n" if strategy_id else "")
            + f"  report file: {short_path(report_path)}\n",
            stream="audit",
        )
        if (
            self.gui_preferences.auto_apply_strategy_on_probe
            and strategy_id
            and phase not in {"healthy", "unknown", ""}
        ):
            self._append_output(
                f"\nAuto-applying strategy profile {strategy_id} (phase={phase})...\n",
                stream="audit",
            )
            self.apply_recommended_profile(confirm=False, restart=False)

    def _after_lab_evidence(self, code: int, output: str, report_path: Path) -> None:
        if code != 0:
            return
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            try:
                data = json.loads(report_path.read_text(encoding="utf-8"))
            except Exception:
                return
        if not isinstance(data, dict):
            return
        overall = str(data.get("overall", "unknown"))
        scenarios = data.get("scenarios", {})
        pass_count = 0
        warn_count = 0
        if isinstance(scenarios, dict):
            for value in scenarios.values():
                if not isinstance(value, dict):
                    continue
                status = str(value.get("status", "")).lower()
                if status == "pass":
                    pass_count += 1
                elif status == "warn":
                    warn_count += 1
        self._append_output(
            "\nLab evidence summary:\n"
            f"  overall: {overall}\n"
            f"  scenarios: pass={pass_count} warn={warn_count}\n"
            f"  report file: {short_path(report_path)}\n",
            stream="audit",
        )

    def copy_phase_summary(self) -> None:
        decision_path = LOCAL_STATE / "decision-report.latest.json"
        evidence_path = LOCAL_STATE / "lab-evidence.latest.json"
        if not decision_path.exists():
            messagebox.showwarning(
                "Missing decision report",
                "Run Decision Report first, then copy the phase summary.",
            )
            return
        try:
            decision = json.loads(decision_path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Copy failed", f"Could not read decision report: {exc}")
            return
        if not isinstance(decision, dict):
            messagebox.showerror("Copy failed", "Decision report JSON is not an object.")
            return

        phase_diag = decision.get("phase_diagnostics", {})
        if not isinstance(phase_diag, dict):
            messagebox.showwarning(
                "Missing phase diagnostics",
                "Decision report is present but does not include phase diagnostics.",
            )
            return

        recommendation = phase_diag.get("actionable_recommendation", {})
        if not isinstance(recommendation, dict):
            recommendation = {}

        evidence_overall = "not-run"
        evidence_pass = 0
        evidence_warn = 0
        if evidence_path.exists():
            try:
                evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
                if isinstance(evidence, dict):
                    evidence_overall = str(evidence.get("overall", "unknown"))
                    scenarios = evidence.get("scenarios", {})
                    if isinstance(scenarios, dict):
                        for value in scenarios.values():
                            if not isinstance(value, dict):
                                continue
                            status = str(value.get("status", "")).lower()
                            if status == "pass":
                                evidence_pass += 1
                            elif status == "warn":
                                evidence_warn += 1
            except Exception:
                evidence_overall = "read-error"

        summary = "\n".join(
            [
                "Xray-Cooperative-Overlay phase summary (redacted)",
                f"Target: {phase_diag.get('target', 'unknown')}",
                f"Provider family: {phase_diag.get('provider_family', 'unknown')}",
                f"Phase: {phase_diag.get('phase_classification', 'unknown')}",
                f"Confidence: {phase_diag.get('confidence_score', 0.0)}",
                f"Recommended action: {recommendation.get('action', 'manual_review_required')}",
                f"Reason: {recommendation.get('reason', '')}",
                f"Decision report: {short_path(decision_path)}",
                (
                    f"Lab evidence: {short_path(evidence_path)} "
                    f"(overall={evidence_overall}, pass={evidence_pass}, warn={evidence_warn})"
                    if evidence_path.exists()
                    else "Lab evidence: not-run"
                ),
                "Sensitive data intentionally omitted: private keys, cookies, request bodies, full browsing history.",
            ]
        )
        self.clipboard_clear()
        self.clipboard_append(summary)
        self._append_output("\nCopied redacted phase summary to clipboard.\n" + summary + "\n", stream="audit")
        self.current_process_label.set("Phase summary copied")

    def run_browser_smoke(self) -> None:
        try:
            url, proxy = self._browser_common_args()
        except ValueError as exc:
            messagebox.showerror("Browser smoke", str(exc))
            return
        args = list(py_script("browser_smoke.py", "--url", url, "--proxy", proxy, "--cert", str(CERT), prefer_host=True))
        if self.browser_headless.get():
            args.append("--headless")
        self.run_async("Browser smoke summary", args, timeout=220)

    def host_python_or_warn(self) -> list[str] | None:
        host_python = find_host_python()
        if host_python is None:
            messagebox.showwarning(
                "Python not found",
                "A normal Python installation is required for one-click dependency installs. Install Python 3, then retry.",
            )
            self._append_output("\nNo host Python found. Install Python 3, then retry dependency fixes.\n")
        return host_python

    def reset_gui_defaults(self) -> None:
        browser_cfg = read_browser_integration()
        self.browser_url.set("https://example.com")
        self.browser_proxy.set(str(browser_cfg.get("default_proxy", "socks5://127.0.0.1:10808")))
        self.browser_executable.set("")
        self.browser_fingerprint_seed.set("")
        self.browser_headless.set(False)
        self.browser_geoip.set(False)
        self.browser_humanize.set(bool((browser_cfg.get("stealth") or {}).get("default_humanize", True)))
        self.dns_domain.set("example.com")
        self.dns_resolvers.set("1.1.1.1, 8.8.8.8")
        self.profile_offset.set("100")
        self.profile_suffix.set(".altports")
        self._append_output("\nGUI defaults restored: proxy, DNS resolvers, target URL, and alternate-port settings.\n")
        self.current_process_label.set("Defaults restored")

    def browser_install_hints(self) -> None:
        host_python = find_host_python()
        python_hint = " ".join(host_python) if host_python else "python"
        self._append_output(
            "\nBrowser dependency hints:\n"
            f"  Host Python detected: {python_hint}\n"
            f"  Page check tools: {python_hint} -m pip install -r requirements-browser-diagnostics.txt\n"
            f"  Page check browser: {python_hint} -m playwright install chromium\n"
            f"  Linux deps if needed: {python_hint} -m playwright install-deps chromium\n"
            f"  Fingerprint tools: {python_hint} -m pip install -r requirements-browser-stealth.txt\n"
            f"  CloakBrowser setup: {python_hint} -m cloakbrowser install\n"
            f"  Xray releases: {XRAY_RELEASES_URL}\n  Project: {CLOAKBROWSER_URL}\n"
        )

    def install_diagnostics_dependencies(self) -> None:
        host_python = self.host_python_or_warn()
        if host_python is None:
            return
        steps = [
            ("Upgrade pip", [*host_python, "-m", "pip", "install", "--upgrade", "pip"], 300),
            ("Install Playwright package", [*host_python, "-m", "pip", "install", "-r", str(ROOT / "requirements-browser-diagnostics.txt")], 600),
            ("Install Playwright Chromium", [*host_python, "-m", "playwright", "install", "chromium"], 900),
        ]
        self.run_sequence("Install Page Check Tools", steps)

    def install_stealth_dependencies(self) -> None:
        host_python = self.host_python_or_warn()
        if host_python is None:
            return
        steps = [
            ("Upgrade pip", [*host_python, "-m", "pip", "install", "--upgrade", "pip"], 300),
            ("Install CloakBrowser package", [*host_python, "-m", "pip", "install", "-r", str(ROOT / "requirements-browser-stealth.txt")], 600),
            ("Run CloakBrowser setup", [*host_python, "-m", "cloakbrowser", "install"], 900),
        ]
        self.run_sequence("Install Fingerprint Tools", steps)

    def install_pyinstaller(self) -> None:
        host_python = self.host_python_or_warn()
        if host_python is None:
            return
        self.run_sequence("Install PyInstaller", [("Install PyInstaller", [*host_python, "-m", "pip", "install", "--upgrade", "pyinstaller"], 600)])

    def download_xray(self) -> None:
        if not messagebox.askyesno(
            "Download Xray Core",
            "Download the latest Xray Core runtime from GitHub into the local xray folder?",
        ):
            return
        self.run_sequence("Download Xray Core", [("Download Xray Core runtime", py_script("install_xray.py", "--out-dir", str(ROOT / "xray"), "--force"), 300)])

    def install_optional_dependencies(self) -> None:
        host_python = self.host_python_or_warn()
        if host_python is None:
            return
        steps = [
            ("Upgrade pip", [*host_python, "-m", "pip", "install", "--upgrade", "pip"], 300),
            ("Install page check dependencies", [*host_python, "-m", "pip", "install", "-r", str(ROOT / "requirements-browser-diagnostics.txt")], 600),
            ("Install Playwright Chromium", [*host_python, "-m", "playwright", "install", "chromium"], 900),
            ("Install stealth dependencies", [*host_python, "-m", "pip", "install", "-r", str(ROOT / "requirements-browser-stealth.txt")], 600),
            ("Run CloakBrowser setup", [*host_python, "-m", "cloakbrowser", "install"], 900),
            ("Install PyInstaller", [*host_python, "-m", "pip", "install", "--upgrade", "pyinstaller"], 600),
        ]
        self.run_sequence("Install Optional Dependencies", steps)

    def safe_auto_fix(self) -> None:
        if not CONFIG.exists():
            messagebox.showerror("Missing config", f"Primary config not found: {short_path(CONFIG)}")
            return
        if not self.browser_proxy.get().strip() or not self.dns_resolvers.get().strip():
            self.reset_gui_defaults()
        try:
            offset = int(self.profile_offset.get())
        except ValueError:
            offset = 100
            self.profile_offset.set(str(offset))
        suffix = self.profile_suffix.get().strip() or ".altports"
        self.profile_suffix.set(suffix)
        steps: list[tuple[str, list[str], int]] = [
            ("Regenerate standard profiles", py_script("generate_profiles.py", "--base", str(CONFIG)), 120),
            (
                "Create alternate-port profiles",
                py_script(
                    "generate_profiles.py",
                    "--base",
                    str(CONFIG),
                    "--out-dir",
                    str(ROOT / "Xray-config"),
                    "--port-offset",
                    str(offset),
                    "--suffix",
                    suffix,
                ),
                120,
            ),
            ("Validate config", py_script("validate_config.py", str(CONFIG)), 120),
            ("Route policy tests", py_test("route_policy_tests.py"), 120),
            ("Protocol policy tests", py_test("protocol_policy_tests.py"), 120),
            ("Metadata validation", py_script("validate_metadata.py"), 120),
            ("Static preflight", py_script("preflight.py", "--config", str(CONFIG), "--no-dns", "--skip-cert", "--skip-runtime"), 120),
            ("Secret scan", py_script("secret_scan.py"), 120),
        ]
        if (not CERT.exists() or not KEY.exists()) and messagebox.askyesno(
            "Local CA files missing",
            "mycert.crt or mycert.key is missing. Generate local CA files now? This does not install trust.",
        ):
            steps.append(("Generate or rotate local CA", py_script("mitm_trust.py", "rotate", "--out-dir", str(ROOT / "Xray-config")), 120))
        self.run_sequence("Repair Setup", steps)

    def cert_status(self) -> None:
        self.run_async("Certificate status", py_script("mitm_trust.py", "status", "--cert", str(CERT), "--key", str(KEY), "--json"))

    def cert_pair(self) -> None:
        self.run_async("Certificate pair check", py_script("mitm_trust.py", "check-pair", "--cert", str(CERT), "--key", str(KEY)))

    def trust_instructions(self) -> None:
        self.run_async("Trust instructions", py_script("trust_assistant.py", "--cert", str(CERT)))

    def generate_ca(self) -> None:
        if not messagebox.askyesno(
            "Generate local CA files",
            "This creates or replaces your local mycert.crt and mycert.key files. It does not install trust or upload keys. Continue?",
        ):
            return
        self.run_async("Generate local CA", py_script("mitm_trust.py", "generate", "--out-dir", str(ROOT / "Xray-config")), timeout=60)

    def _browser_common_args(self) -> tuple[str, str]:
        url = self.browser_url.get().strip()
        proxy = self.browser_proxy.get().strip()
        if not url:
            raise ValueError("Enter a target URL.")
        if not proxy:
            raise ValueError("Enter a proxy URL (default: socks5://127.0.0.1:10808).")
        return url, proxy

    def run_browser_diagnostics(self) -> None:
        try:
            url, proxy = self._browser_common_args()
        except ValueError as exc:
            messagebox.showerror("Browser probe", str(exc))
            return
        args = list(py_script("browser_diagnostics.py", "--url", url, "--proxy", proxy, "--cert", str(CERT), prefer_host=True))
        executable = self.browser_executable.get().strip()
        if executable:
            args.extend(["--executable", executable])
        if self.browser_headless.get():
            args.append("--headless")
        self.run_async("Page check browser test", args, timeout=180)

    def run_browser_stealth(self) -> None:
        try:
            url, proxy = self._browser_common_args()
        except ValueError as exc:
            messagebox.showerror("Browser probe", str(exc))
            return
        args = list(py_script("browser_stealth.py", "--url", url, "--proxy", proxy, "--cert", str(CERT), prefer_host=True))
        if self.browser_headless.get():
            args.append("--headless")
        if self.browser_geoip.get():
            args.append("--geoip")
        if not self.browser_humanize.get():
            args.append("--no-humanize")
        seed = self.browser_fingerprint_seed.get().strip()
        if seed:
            args.extend(["--fingerprint-seed", seed])
        self.run_async("Fingerprint browser check (CloakBrowser)", args, timeout=180)

    def check_cloakbrowser_installed(self) -> None:
        host_python = find_host_python() or [sys.executable]
        code, output = run_command([*host_python, "-c", "import cloakbrowser; print(cloakbrowser.__file__)"], timeout=30)
        if code == 0:
            self._append_output(f"\nCloakBrowser import OK\n{output}\n")
            self.current_process_label.set("CloakBrowser: installed")
        else:
            self._append_output(
                f"\nCloakBrowser not installed.\n{output}\n"
                f"Run: pip install -r requirements-browser-stealth.txt\n"
                f"Then: python -m cloakbrowser install\n"
                f"Or click Install Fingerprint Tools in Repair.\nProject: {CLOAKBROWSER_URL}\n"
            )
            self.current_process_label.set("CloakBrowser: not installed")

    def _active_profile_intent(self) -> str:
        path = self.active_config_path()
        stem = path.stem
        if stem == "Xray-Cooperative-Overlay":
            return "balanced"
        suffix = stem.replace("Xray-Cooperative-Overlay.", "", 1)
        base = suffix.split(".")[0] if suffix else "balanced"
        if base in {"strict", "balanced", "compatibility", "debug"}:
            return base
        return "balanced"

    def apply_recommended_profile(self, *, confirm: bool = True, restart: bool | None = None) -> None:
        report_path = LOCAL_STATE / "decision-report.latest.json"
        labels: tuple[str, ...] = ()
        intent = self._active_profile_intent()
        strategy_block: dict[str, object] | None = None
        if report_path.exists():
            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                report = {}
            if isinstance(report, dict):
                intent = str(report.get("profile") or intent)
                raw_strategy = report.get("strategy_recommendation")
                if isinstance(raw_strategy, dict):
                    strategy_block = raw_strategy
                    labels = tuple(raw_strategy.get("failure_labels") or ())
                phase_diag = report.get("phase_diagnostics")
                if isinstance(phase_diag, dict) and not labels:
                    from core.failure_classifier import derive_strategy_labels

                    labels = derive_strategy_labels(phase=str(phase_diag.get("phase_classification") or ""))
        if strategy_block and strategy_block.get("selected_profile_id"):
            profile_id = str(strategy_block["selected_profile_id"])
            reason = str(strategy_block.get("reason") or "strategy recommendation")
            confidence = str(strategy_block.get("confidence") or "unknown")
        else:
            try:
                decision = recommend_profile(
                    failure_labels=labels,
                    operator_intent=intent,
                    session_counter=self.status_refresh_count,
                )
            except ValueError as exc:
                messagebox.showerror("Strategy profile", str(exc))
                return
            profile_id = decision.selected_profile_id
            reason = decision.reason
            confidence = decision.confidence
        target = ROOT / "Xray-config" / f"Xray-Cooperative-Overlay.{profile_id}.json"
        if not target.exists():
            messagebox.showwarning("Profile missing", f"Recommended profile file not found: {short_path(target)}")
            return
        label = self._profile_display_name(target)
        if label not in self._profile_choices():
            messagebox.showwarning("Profile unavailable", f"{label} is not in the profile picker.")
            return
        if confirm and not messagebox.askyesno(
            "Apply strategy profile",
            f"Switch to {label}?\n\nReason: {reason}\nConfidence: {confidence}",
        ):
            return
        self.profile_selection.set(label)
        self._select_profile()
        try:
            from core.strategy_winner import remember_winner

            remember_winner(profile_id, reason=reason, failure_labels=labels)
        except Exception:
            pass
        self.record_telemetry("strategy_profile_applied", "info", profile_id, {"reason": reason, "confidence": confidence})
        should_restart = restart
        if should_restart is None:
            should_restart = self._xray_running_from_gui() and messagebox.askyesno(
                "Restart core",
                "Restart the app core with the new profile now?",
            )
        if should_restart and self._xray_running_from_gui():
            self.disconnect_xray()
            self.connect_xray()

    def restrict_private_key_acl(self) -> None:
        if not KEY.exists():
            messagebox.showwarning("Missing key", f"Private key not found: {short_path(KEY)}")
            return
        if not messagebox.askyesno(
            "Restrict private key",
            "Tighten ACL on mycert.key to the current user (Windows) or chmod 600 (Unix)?",
        ):
            return
        self.run_async(
            "Restrict private key ACL",
            py_script("mitm_trust.py", "restrict-key", "--key", str(KEY), "--json"),
            timeout=30,
            after=lambda code, output: self.refresh_status() if code == 0 else None,
        )

    def wrap_private_key_dpapi(self) -> None:
        if not KEY.exists():
            messagebox.showwarning("Missing key", f"Private key not found: {short_path(KEY)}")
            return
        if os.name != "nt":
            messagebox.showinfo("DPAPI", "DPAPI wrap is available on Windows only.")
            return
        if not messagebox.askyesno(
            "Wrap private key",
            "Write a DPAPI sidecar (mycert.key.dpapi) and tighten ACL on the plaintext key?",
        ):
            return
        remove_plaintext = messagebox.askyesno(
            "Remove Plaintext Key",
            "Securely delete the plaintext private key file (mycert.key) after wrapping it?\n\n"
            "If deleted, Xray will unwrap the key in-memory during startup using your Windows account credentials, "
            "minimizing private-key exposure at rest."
        )
        args = ["wrap-key", "--key", str(KEY), "--json"]
        if remove_plaintext:
            args.append("--remove-plaintext")
        self.run_async(
            "Wrap private key (DPAPI)",
            py_script("mitm_trust.py", *args),
            timeout=30,
            after=lambda code, output: self.refresh_status() if code == 0 else None,
        )

    def unwrap_private_key_dpapi(self) -> None:
        from core.key_at_rest import dpapi_sidecar_path
        sidecar = dpapi_sidecar_path(KEY)
        if not sidecar.exists():
            messagebox.showwarning("Missing sidecar", f"DPAPI sidecar not found: {short_path(sidecar)}")
            return
        if os.name != "nt":
            messagebox.showinfo("DPAPI", "DPAPI unwrap is available on Windows only.")
            return
        if not messagebox.askyesno(
            "Unwrap private key",
            "Restore the plaintext private key (mycert.key) from the DPAPI sidecar and delete the sidecar?",
        ):
            return
        self.run_async(
            "Unwrap private key (DPAPI)",
            py_script("mitm_trust.py", "unwrap-key", "--key", str(KEY), "--json"),
            timeout=30,
            after=lambda code, output: self.refresh_status() if code == 0 else None,
        )

    def run_full_preflight(self) -> None:
        config_path = self.active_config_path()
        self.run_async(
            "Full preflight",
            py_script(
                "preflight.py",
                "--config",
                str(config_path),
                "--cert",
                str(CERT),
                "--key",
                str(KEY),
                "--json-out",
                str(LOCAL_STATE / "preflight.latest.json"),
            ),
            timeout=120,
            after=lambda _code, _output: self.refresh_status(),
        )

    def launch_isolated_chromium(self) -> None:
        if not CERT.exists():
            messagebox.showwarning("Missing certificate", f"Generate the local CA first: {short_path(CERT)}")
            return
        try:
            _, proxy = self._browser_common_args()
        except ValueError as exc:
            messagebox.showerror("Browser launch", str(exc))
            return
        browser = "edge" if os.name == "nt" else "chromium"
        profile_dir = LOCAL_STATE / "isolated-chromium-profile"
        try:
            session = prepare_chromium_session(
                browser=browser,
                profile_dir=profile_dir,
                proxy_url=proxy,
                cert_path=CERT,
            )
        except (FileNotFoundError, ValueError) as exc:
            messagebox.showerror("Browser launch", str(exc))
            return
        manifest_path = LOCAL_STATE / "trust-broker-session.json"
        LOCAL_STATE.mkdir(exist_ok=True)
        manifest_path.write_text(session_manifest(session) + "\n", encoding="utf-8")
        self.record_telemetry("isolated_browser_prepared", "info", short_path(manifest_path), {"browser": browser})
        self._append_output(
            "\nPrepared isolated Chromium launch (profile-scoped trust only):\n"
            f"{session_manifest(session)}\n"
            "Import/trust the local CA in this profile manually if needed.\n"
        )
        if not messagebox.askyesno(
            "Launch isolated browser",
            "Launch an isolated Chromium profile now?\n\n"
            "CDP assist will open certificate settings in that profile. "
            "You must still import the local CA manually — no silent trust install.",
        ):
            return

        def worker() -> None:
            try:
                _proc, assist = launch_session_with_cdp_assist(session)
            except OSError as exc:
                self.after(0, lambda: messagebox.showerror("Browser launch", str(exc)))
                return
            detail = str(assist.get("detail") or "")
            status = str(assist.get("status") or "unknown")
            self.after(
                0,
                lambda: (
                    self._append_output(f"\nCDP trust assist ({status}): {detail}\n"),
                    self.record_telemetry("isolated_browser_launched", "pass" if status == "pass" else "warn", browser, assist),
                ),
            )

        threading.Thread(target=worker, daemon=True).start()
        self._append_output("\nLaunching isolated Chromium profile with CDP assist...\n")

    def run_ja3_oracle(self) -> None:
        oracle_url = self.browser_ja3_oracle_url.get().strip()
        if not oracle_url:
            messagebox.showwarning("JA3 oracle", "Enter a trusted JA3 echo oracle URL first.")
            return
        if not messagebox.askyesno(
            "JA3 oracle",
            f"Navigate to the oracle through the local proxy?\n\n{oracle_url}\n\n"
            "Only proceed if you trust this endpoint.",
        ):
            return
        try:
            url, proxy = self._browser_common_args()
        except ValueError as exc:
            messagebox.showerror("JA3 oracle", str(exc))
            return
        args = list(
            py_script(
                "browser_diagnostics.py",
                "--url",
                url,
                "--proxy",
                proxy,
                "--cert",
                str(CERT),
                "--ja3-oracle",
                oracle_url,
                prefer_host=True,
            )
        )
        executable = self.browser_executable.get().strip()
        if executable:
            args.extend(["--executable", executable])
        if self.browser_headless.get():
            args.append("--headless")
        snapshot = self._status_snapshot()
        expected = str(snapshot.get("ja3_expected") or "").strip()
        if expected:
            args.extend(["--expected-ja3", expected])
        self.run_async("JA3 oracle measurement", args, timeout=180, after=self._after_ja3_oracle)

    def _after_ja3_oracle(self, code: int, output: str) -> None:
        self.refresh_status()
        if code != 0:
            self._append_output("\nJA3 oracle run failed — see output above.\n", stream="audit")
            return
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            self._append_output("\nJA3 oracle finished but JSON output was not parseable.\n", stream="audit")
            return
        fp = data.get("fingerprint_validation") if isinstance(data.get("fingerprint_validation"), dict) else {}
        observed = fp.get("observed_ja3") or fp.get("ja3") or ""
        match = fp.get("tls_fingerprint_ja3_matches_browser")
        method = fp.get("verification_method") or "unknown"
        self._append_output(
            "\nJA3 oracle summary:\n"
            f"  verification_method: {method}\n"
            f"  observed: {observed or 'none'}\n"
            f"  match: {match}\n",
            stream="audit",
        )

    def launch_diagnostics_chrome_ps(self) -> None:
        ps1 = SCRIPTS / "launch_browser_mitm.ps1"
        if not ps1.exists():
            messagebox.showwarning("Missing script", f"Not found: {short_path(ps1)}")
            return
        try:
            url, proxy = self._browser_common_args()
        except ValueError as exc:
            messagebox.showerror("Browser launch", str(exc))
            return
        args = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ps1),
            "-Mode",
            "Diagnostics",
            "-Url",
            url,
            "-Proxy",
            proxy,
        ]
        if self.browser_headless.get():
            args.append("-Headless")
        self._append_output(f"\n$ {' '.join(args)}\n")
        try:
            subprocess.Popen(args, cwd=str(ROOT), **hidden_subprocess_kwargs())
            self.current_process_label.set("Launched stock Chrome (diagnostics)")
            self._append_output("Started Chrome in a separate process. Check the browser window.\n")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Launch failed", str(exc))

    def open_path(self, path: Path) -> None:
        target = path.resolve()
        if not target.exists():
            messagebox.showwarning("Missing file", f"Not found: {target}")
            return
        webbrowser.open(target.as_uri())


def self_test() -> int:
    required = [
        CONFIG,
        SCRIPTS / "validate_config.py",
        SCRIPTS / "preflight.py",
        SCRIPTS / "generate_profiles.py",
        SCRIPTS / "mitm_trust.py",
        SCRIPTS / "check_dns.py",
        SCRIPTS / "decision_report.py",
        SCRIPTS / "path_scorer.py",
        ROOT / "tests" / "python" / "browser_probe_semantics_test.py",
        ROOT / "tests" / "python" / "failure_classifier_tests.py",
        ROOT / "tests" / "python" / "path_scorer_tests.py",
        ROOT / "tests" / "python" / "gui_readiness_tests.py",
        ROOT / "tests" / "python" / "health_policy_tests.py",
        ROOT / "tests" / "python" / "protocol_policy_tests.py",
        ROOT / "tests" / "python" / "provider_policy_validator_tests.py",
        ROOT / "tests" / "python" / "readiness_tests.py",
        ROOT / "tests" / "python" / "route_policy_tests.py",
        ROOT / "tests" / "python" / "rust_core_tests.py",
        ROOT / "tests" / "python" / "_path.py",
        SCRIPTS / "browser_common.py",
        SCRIPTS / "browser_diagnostics.py",
        SCRIPTS / "browser_stealth.py",
        SCRIPTS / "browser_smoke.py",
        SCRIPTS / "health_probe.py",
        SCRIPTS / "trust_store_check.py",
        SCRIPTS / "trust_assistant.py",
        SCRIPTS / "platform_capability_check.py",
        SCRIPTS / "provider_dossier_validate.py",
        ROOT / "tests" / "python" / "repository_structure_tests.py",
        SCRIPTS / "geodata_pin.py",
        SCRIPTS / "dns_lab_harness.py",
        ROOT / "tests" / "python" / "dns_lab_harness_tests.py",
        SCRIPTS / "fakedns_recovery_check.py",
        SCRIPTS / "install_xray.py",
        SCRIPTS / "route_intent_sync.py",
        SCRIPTS / "route_graph_verify.py",
        SCRIPTS / "route_rule_linter.py",
        SCRIPTS / "config_src_validate.py",
        SCRIPTS / "config_src_build.py",
        SCRIPTS / "config_src_merge.py",
        ROOT / "tests" / "python" / "config_src_merge_test.py",
        SCRIPTS / "lab_evidence_run.py",
        SCRIPTS / "transport_experiment_validate.py",
        SCRIPTS / "transport_profile_validate.py",
        SCRIPTS / "protocol_smoke.py",
        SCRIPTS / "core" / "__init__.py",
        SCRIPTS / "core" / "failure_classifier.py",
        SCRIPTS / "core" / "gui_readiness.py",
        SCRIPTS / "core" / "provider_policy.py",
        SCRIPTS / "core" / "process_supervisor.py",
        SCRIPTS / "core" / "readiness.py",
        SCRIPTS / "core" / "route_rule_linter.py",
        SCRIPTS / "core" / "trust_assistant.py",
        ROOT / "configs" / "health-checks.yml",
        ROOT / "configs" / "route-intent.json",
        ROOT / "configs" / "transport-experiments.json",
        ROOT / "configs" / "transport-profiles.yml",
        ROOT / "config-src" / "manifest.json",
        ROOT / "config-src" / "fragments" / "README.md",
        ROOT / "Cargo.toml",
        ROOT / "src" / "lib.rs",
        ROOT / "src" / "main.rs",
        ROOT / "src" / "alpn_policy.rs",
        ROOT / "src" / "backend_runtime.rs",
        ROOT / "src" / "h2_coalescing.rs",
        ROOT / "src" / "cooperative_overlay.rs",
        ROOT / "src" / "ingress.rs",
        ROOT / "src" / "ingress_android_tun.rs",
        ROOT / "src" / "ingress_loopback.rs",
        ROOT / "src" / "ingress_xdp_gateway.rs",
        ROOT / "src" / "parser.rs",
        ROOT / "src" / "cert_cache.rs",
        ROOT / "src" / "regression_harness.rs",
        ROOT / "src" / "scheduler.rs",
        ROOT / "src" / "tls_orchestrator.rs",
        ROOT / "src" / "tls_orchestrator_backend.rs",
        ROOT / "docs" / "lab-evidence-checklist.md",
        ROOT / "docs" / "local-telemetry.md",
        BROWSER_CONFIG,
        ROOT / "docs" / "chromium-integration.md",
    ]
    missing = [short_path(path) for path in required if not path.exists()]
    if missing:
        print("GUI self-test failed; missing: " + ", ".join(missing))
        return 2
    if IS_FROZEN:
        for script_name in ("preflight.py", "check_dns.py", "install_xray.py"):
            code, output = run_command([sys.executable, "--backend", script_name, "--help"], timeout=30)
            if code != 0:
                print(f"GUI self-test failed; backend {script_name} did not start")
                if output:
                    print(output)
                return code or 1
    print("GUI self-test passed")
    return 0


def main() -> int:
    if len(sys.argv) >= 3 and sys.argv[1] == "--backend":
        return run_backend(sys.argv[2], sys.argv[3:])
    parser = argparse.ArgumentParser(description="Launch the Xray-Cooperative-Overlay local GUI")
    parser.add_argument("--self-test", action="store_true", help="validate GUI dependencies without opening a window")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if os.environ.get("DISPLAY") == "" and os.name != "nt":
        print("No DISPLAY is available; run this on a desktop session or use --self-test.")
        return 2
    app = App()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
