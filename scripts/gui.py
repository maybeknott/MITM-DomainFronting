#!/usr/bin/env python3
"""Local desktop GUI for MITM-DomainFronting maintenance and diagnostics."""
from __future__ import annotations

import argparse
import queue
import re
import datetime as dt
import json
import os
import runpy
import socket
import subprocess
import sys
import threading
import time
import traceback
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core.process_supervisor import ProcessSupervisor

IS_FROZEN = bool(getattr(sys, "frozen", False))
ROOT = Path(sys.executable).resolve().parent if IS_FROZEN else Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
CONFIG = ROOT / "Xray-config" / "MITM-DomainFronting.json"
CERT = ROOT / "Xray-config" / "mycert.crt"
KEY = ROOT / "Xray-config" / "mycert.key"
BROWSER_CONFIG = ROOT / "configs" / "browser-integration.json"
LOCAL_STATE = ROOT / ".local-state"
GUI_TELEMETRY = LOCAL_STATE / "gui-telemetry.jsonl"
CLOAKBROWSER_URL = "https://github.com/CloakHQ/CloakBrowser"
XRAY_RELEASES_URL = "https://github.com/XTLS/Xray-core/releases"

COLORS = {
    "bg": "#f8fafc",
    "panel": "#ffffff",
    "ink": "#0f172a",
    "muted": "#64748b",
    "line": "#e2e8f0",
    "blue": "#2563eb",
    "blue_dark": "#1d4ed8",
    "green": "#16a34a",
    "amber": "#d97706",
    "red": "#dc2626",
    "sidebar": "#0f172a",
    "sidebar_active": "#1e293b",
}


@dataclass(frozen=True)
class CommandSpec:
    label: str
    description: str
    args: tuple[str, ...]


def find_host_python() -> list[str] | None:
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
            )
        except Exception:
            continue
        if proc.returncode == 0:
            return candidate
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


def port_accepts_loopback(port: int, timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def py_script(name: str, *args: str, prefer_host: bool = False) -> list[str]:
    if prefer_host:
        host_python = find_host_python()
        if host_python is not None:
            return [*host_python, str(SCRIPTS / name), *args]
    if IS_FROZEN:
        return [sys.executable, "--backend", name, *args]
    return [sys.executable, str(SCRIPTS / name), *args]


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
        while True:
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


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("MITM-DomainFronting Control Center")
        self.protocol("WM_DELETE_WINDOW", self.close_app)
        self.scaling_factor = self._query_hardware_dpi_scale()
        self.fonts = self._build_fonts()
        self.geometry(f"{self._scaled(1220)}x{self._scaled(820)}")
        self.minsize(self._scaled(1040), self._scaled(700))
        self.configure(bg=COLORS["bg"])
        self.current_process_label = tk.StringVar(value="Ready")
        self.profile_offset = tk.StringVar(value="100")
        self.profile_suffix = tk.StringVar(value=".altports")
        self.dns_domain = tk.StringVar(value="example.com")
        self.dns_resolvers = tk.StringVar(value="1.1.1.1, 8.8.8.8")
        browser_cfg = read_browser_integration()
        self.browser_url = tk.StringVar(value="https://example.com")
        self.browser_proxy = tk.StringVar(value=str(browser_cfg.get("default_proxy", "socks5://127.0.0.1:10808")))
        self.browser_executable = tk.StringVar(value="")
        self.browser_fingerprint_seed = tk.StringVar(value="")
        self.browser_headless = tk.BooleanVar(value=False)
        self.browser_geoip = tk.BooleanVar(value=False)
        self.browser_humanize = tk.BooleanVar(value=bool((browser_cfg.get("stealth") or {}).get("default_humanize", True)))
        self.xray_supervisor: ProcessSupervisor | None = None
        self.xray_process: subprocess.Popen[str] | None = None
        self.active_config = tk.StringVar(value=str(CONFIG))
        self.connection_state = tk.StringVar(value="Not connected")
        self.simple_next_step = tk.StringVar(value="Run Check Setup, then start the proxy and test the browser.")
        self.screen_title = tk.StringVar(value="Dashboard")
        self.overall_status = tk.StringVar(value="Checking")
        self.overall_detail = tk.StringVar(value="Reading local config, certificates, ports, and tools.")
        self.telemetry_summary = tk.StringVar(value="Activity history: local only, 0 events")
        self.telemetry_last = tk.StringVar(value="Last activity: none")
        self.last_status_level = "unknown"
        self.status_chip_labels: dict[str, tk.Label] = {}
        self.nav_button_widgets: dict[str, tk.Button] = {}
        self.output_buffers: dict[str, tk.Text] = {}
        self.log_multiplexer: LogMultiplexer | None = None
        self.busy_controls: list[tk.Widget] = []
        self.is_busy = False
        self.stream_count = 0
        self.active_banner: tk.Frame | None = None
        self.help_topics = self._build_help_topics()
        self._configure_style()
        self._build_layout()
        self.record_telemetry("app_started", "info", "GUI started")
        self.refresh_status()

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

    def _build_fonts(self) -> dict[str, tuple[str, int, str]]:
        family = "Segoe UI" if os.name == "nt" else "Helvetica"
        code_family = "Consolas" if os.name == "nt" else "Courier"
        return {
            "h1": (family, self._scaled(20), "bold"),
            "h2": (family, self._scaled(13), "bold"),
            "body": (family, self._scaled(10), "normal"),
            "body_bold": (family, self._scaled(10), "bold"),
            "caption": (family, self._scaled(9), "normal"),
            "caption_bold": (family, self._scaled(9), "bold"),
            "code": (code_family, self._scaled(10), "normal"),
        }

    def _build_help_topics(self) -> dict[str, str]:
        return {
            "dashboard": (
                "Dashboard\n\n"
                "Purpose: the main place to start, stop, and test the local proxy.\n\n"
                "Proxy metric: shows whether 127.0.0.1:10808 is offline, running from this app, or already used by another local client.\n"
                "Traffic metric: counts accepted Xray connection log lines seen during this app session. It is a live activity hint, not a billing or byte counter.\n"
                "Data metric: reminds you that logs and activity history stay local.\n"
                "Next Step metric: points to the safest next action based on current setup state.\n\n"
                "Start Proxy launches the selected Xray config through this GUI. Stop Proxy only stops a process launched by this GUI. Check Health runs the redacted local health report."
            ),
            "start_here": (
                "Start Here\n\n"
                "Use this screen when setting up the workspace for the first time.\n\n"
                "Check Setup runs the smallest useful validation set. Install Optional Dependencies adds browser and packaging tools. Generate Local CA creates local certificate files but does not install trust. Run Page Check opens a controlled browser check through the local proxy."
            ),
            "checks": (
                "Checks\n\n"
                "This screen runs local validation scripts. Use it before changing configs, publishing a build, or filing an issue.\n\n"
                "Config checks validate JSON, ports, route tags, DNS tags, and required loopback listeners. Route checks verify first-match routing order and decrypted-inbound isolation. Secret Scan checks tracked files for private-key material."
            ),
            "health_report": (
                "Health Report\n\n"
                "This screen produces support-safe local reports.\n\n"
                "Run Health Probe checks ports, certificate files, trust alignment, DNS reachability, provider freshness, and local runtime state. Lab Evidence runs DNS/fakeDNS harness scenarios. Decision Report creates a compact redacted summary for debugging."
            ),
            "fix_tools": (
                "Fix Tools\n\n"
                "These actions repair local workspace files and optional tools. They do not silently install certificate trust, change system proxy settings, or delete browser profiles.\n\n"
                "Repair Local Files regenerates profiles, creates alternate-port profiles, runs policy checks, and offers CA generation only after confirmation."
            ),
            "profiles_dns": (
                "Profiles & DNS\n\n"
                "Operating profiles are generated Xray config variants. The Profile selector on Dashboard chooses which config this GUI starts.\n\n"
                "Offset is added to local listener ports when creating alternate profiles. Suffix is appended to generated alternate profile filenames. DNS Sweep checks A, AAAA, HTTPS, and SVCB records against selected resolvers."
            ),
            "certificates": (
                "Certificates\n\n"
                "Certificate Status inspects local CA files. Check Cert/Key Pair verifies that the certificate and key match. Generate Local CA creates or replaces Xray-config/mycert.crt and mycert.key. Trust Instructions prints copy-paste commands; the GUI does not elevate privileges or install trust silently."
            ),
            "browser_tests": (
                "Browser Tests\n\n"
                "Target URL is the page to test. Proxy is usually socks5://127.0.0.1:10808. Browser path is optional; leave it blank to use the default Playwright browser when available.\n\n"
                "Run Page Check verifies proxy, certificate, and page loading with stock Chromium. Run Fingerprint Check uses CloakBrowser for application-layer fingerprint testing while traffic still goes through the local proxy."
            ),
            "docs": (
                "Docs\n\n"
                "This screen opens local repository documentation. It does not use the network. Pick the guide that matches the problem you are debugging: operating profiles, browser integration, certificates, DNS, local activity history, or platform compatibility."
            ),
            "1_proxy_control": (
                "Proxy Control\n\n"
                "Profile selects the config file used when the GUI starts Xray. Start Proxy launches that config. Stop Proxy stops only the process launched by this GUI. Check Health runs a redacted environment report.\n\n"
                "If another app already owns 127.0.0.1:10808, this GUI will not kill it."
            ),
            "2_browser_check": (
                "Browser Check\n\n"
                "URL is the page to open. Proxy is the local proxy endpoint. Browser path is optional and useful when you want a specific Chrome or Edge executable.\n\n"
                "Run Page Check is the first browser test to use. Run Fingerprint Check is for the CloakBrowser path."
            ),
            "3_quick_actions": (
                "Quick Actions\n\n"
                "Check Setup is the first troubleshooting action. Repair Local Files performs deterministic local regeneration and validation. Generate Local CA creates certificate files. Install Browser Tools installs only optional browser check dependencies."
            ),
            "4_activity_history": (
                "Activity History\n\n"
                "Run Full Status records a local snapshot. Show Activity displays recent GUI events. Export Activity writes a redacted local JSON file. Clear Activity removes the GUI event history."
            ),
            "status_summary": (
                "Status Summary\n\n"
                "These tiles summarize the selected config, certificate files, generated profiles, health tool availability, dependencies, browser setup, and privacy boundaries."
            ),
            "operating_profiles": (
                "Operating Profiles\n\n"
                "Regenerate Standard Profiles rebuilds committed profile variants. Generate Alternate Profiles creates local ignored config variants with shifted ports for machines where default ports are occupied."
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
        }

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", font=self.fonts["body"], background=COLORS["bg"], foreground=COLORS["ink"])
        style.configure("TNotebook", background=COLORS["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", padding=(self._scaled(18), self._scaled(9)), background="#e8edf5", foreground=COLORS["ink"])
        style.map("TNotebook.Tab", background=[("selected", COLORS["panel"])], foreground=[("selected", COLORS["blue_dark"])])
        try:
            style.layout("Sidebar.TNotebook.Tab", [])
        except tk.TclError:
            pass
        style.configure("Accent.TButton", background=COLORS["blue"], foreground="#ffffff", padding=(self._scaled(12), self._scaled(8)), borderwidth=0)
        style.map("Accent.TButton", background=[("active", COLORS["blue_dark"])])
        style.configure("Soft.TButton", background="#eef2ff", foreground=COLORS["blue_dark"], padding=(self._scaled(12), self._scaled(8)), borderwidth=0)
        style.map("Soft.TButton", background=[("active", "#dbeafe")])
        style.configure("Danger.TButton", background="#fee2e2", foreground=COLORS["red"], padding=(self._scaled(12), self._scaled(8)), borderwidth=0)
        style.map("Danger.TButton", background=[("active", "#fecaca")])
        style.configure("TEntry", fieldbackground="#ffffff", bordercolor=COLORS["line"], padding=6)
        style.configure("TLabelframe", background=COLORS["panel"], bordercolor=COLORS["line"], relief="solid")
        style.configure("TLabelframe.Label", background=COLORS["panel"], foreground=COLORS["ink"], font=self.fonts["body_bold"])

    def _build_layout(self) -> None:
        root = tk.Frame(self, bg=COLORS["bg"])
        root.pack(fill="both", expand=True)
        root.columnconfigure(0, minsize=self._scaled(270), weight=0)
        root.columnconfigure(1, weight=1)
        root.rowconfigure(0, weight=1)

        sidebar = tk.Frame(root, bg=COLORS["sidebar"])
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)

        tk.Label(sidebar, text="MITM Fronting", bg=COLORS["sidebar"], fg="#ffffff", font=self.fonts["h1"], anchor="w").pack(fill="x", padx=self._scaled(22), pady=(self._scaled(24), self._scaled(4)))
        tk.Label(sidebar, text="Setup - Run - Verify", bg=COLORS["sidebar"], fg="#cbd5e1", font=self.fonts["body"], anchor="w").pack(fill="x", padx=self._scaled(22))
        tk.Label(
            sidebar,
            text=str(ROOT),
            bg=COLORS["sidebar"],
            fg="#94a3b8",
            font=self.fonts["caption"],
            wraplength=self._scaled(225),
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=self._scaled(22), pady=(self._scaled(10), self._scaled(18)))
        nav_holder = tk.Frame(sidebar, bg=COLORS["sidebar"])
        nav_holder.pack(fill="x", padx=self._scaled(14), pady=(0, self._scaled(12)))
        tk.Label(
            sidebar,
            textvariable=self.current_process_label,
            bg=COLORS["sidebar"],
            fg="#a7f3d0",
            font=self.fonts["caption"],
            wraplength=self._scaled(230),
            justify="left",
        ).pack(side="bottom", fill="x", padx=self._scaled(22), pady=self._scaled(22))

        content = tk.Frame(root, bg=COLORS["bg"])
        content.grid(row=0, column=1, sticky="nsew")
        content.columnconfigure(0, weight=1)

        header = tk.Frame(content, bg=COLORS["bg"])
        header.pack(fill="x", padx=self._scaled(24), pady=(self._scaled(20), self._scaled(10)))
        title_block = tk.Frame(header, bg=COLORS["bg"])
        title_block.pack(side="left", fill="x", expand=True)
        tk.Label(title_block, textvariable=self.screen_title, bg=COLORS["bg"], fg=COLORS["ink"], font=self.fonts["h1"], anchor="w").pack(fill="x")
        tk.Label(title_block, textvariable=self.overall_detail, bg=COLORS["bg"], fg=COLORS["muted"], anchor="w").pack(fill="x", pady=(2, 0))
        status_block = tk.Frame(header, bg=COLORS["bg"])
        status_block.pack(side="right")
        self.header_status_label = tk.Label(status_block, textvariable=self.overall_status, bg="#fef3c7", fg=COLORS["amber"], font=self.fonts["body_bold"], padx=self._scaled(12), pady=self._scaled(6))
        self.header_status_label.pack(side="left", padx=(0, self._scaled(8)))
        self.task_progress = ttk.Progressbar(status_block, mode="indeterminate", length=self._scaled(118))
        self.task_progress.pack(side="left", padx=(0, self._scaled(8)))
        ttk.Button(status_block, text="Help", style="Soft.TButton", command=self.show_current_help).pack(side="left", padx=(0, self._scaled(8)))
        ttk.Button(status_block, text="Refresh Status", style="Soft.TButton", command=self.refresh_status).pack(side="left")

        self._build_metrics_bar(content)
        self.banner_slot = tk.Frame(content, bg=COLORS["bg"])
        self.banner_slot.pack(fill="x", padx=self._scaled(24), pady=(0, self._scaled(10)))

        self.tabs = ttk.Notebook(content, style="Sidebar.TNotebook")
        self.tabs.pack(fill="both", expand=True, padx=self._scaled(24), pady=(0, self._scaled(10)))

        self.start_tab = self._tab()
        self.dashboard_tab = self._tab()
        self.validation_tab = self._tab()
        self.health_tab = self._tab()
        self.fixes_tab = self._tab()
        self.profiles_tab = self._tab()
        self.certs_tab = self._tab()
        self.browser_tab = self._tab()
        self.docs_tab = self._tab()
        self.tabs.add(self.dashboard_tab, text="Dashboard")
        self.tabs.add(self.start_tab, text="Start Here")
        self.tabs.add(self.validation_tab, text="Validation")
        self.tabs.add(self.health_tab, text="Health")
        self.tabs.add(self.fixes_tab, text="Fix Tools")
        self.tabs.add(self.profiles_tab, text="Profiles and DNS")
        self.tabs.add(self.certs_tab, text="Certificates")
        self.tabs.add(self.browser_tab, text="Browser")
        self.tabs.add(self.docs_tab, text="Docs")
        self.tabs.bind("<<NotebookTabChanged>>", lambda _event: self._highlight_active_nav())

        nav_groups: list[tuple[str, list[tuple[str, tk.Frame]]]] = [
            ("Control", [("Dashboard", self.dashboard_tab), ("Start Here", self.start_tab)]),
            ("Verify", [("Checks", self.validation_tab), ("Health Report", self.health_tab), ("Fix Tools", self.fixes_tab), ("Profiles & DNS", self.profiles_tab), ("Certificates", self.certs_tab)]),
            ("Reference", [("Browser Tests", self.browser_tab), ("Docs", self.docs_tab)]),
        ]
        for group_name, items in nav_groups:
            tk.Label(
                nav_holder,
                text=group_name.upper(),
                bg=COLORS["sidebar"],
                fg="#94a3b8",
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
        self.busy_controls = [widget for widget in self._walk_widgets(root) if isinstance(widget, (tk.Button, ttk.Button))]
        self._append_output("Ready. All actions run locally in this repository.\n")
        self._highlight_active_nav()

    def _walk_widgets(self, parent: tk.Widget) -> Iterable[tk.Widget]:
        for child in parent.winfo_children():
            yield child
            yield from self._walk_widgets(child)

    def _make_nav_button(self, parent: tk.Widget, text: str, target: tk.Frame) -> None:
        button = tk.Button(
            parent,
            text=text,
            command=lambda frame=target: self._select_workspace(frame),
            bg=COLORS["sidebar_active"],
            fg="#f8fafc",
            activebackground="#334155",
            activeforeground="#ffffff",
            relief="flat",
            padx=self._scaled(14),
            pady=self._scaled(9),
            anchor="w",
            font=self.fonts["body_bold"],
        )
        button.pack(fill="x", padx=self._scaled(4), pady=self._scaled(3))
        self.nav_button_widgets[text] = button

    def _select_workspace(self, frame: tk.Frame) -> None:
        self.tabs.select(frame)
        self._highlight_active_nav()

    def _current_help_key(self) -> str:
        selected = self.tabs.select() if hasattr(self, "tabs") else ""
        tab_to_key = {
            str(self.dashboard_tab): "dashboard",
            str(self.start_tab): "start_here",
            str(self.validation_tab): "checks",
            str(self.health_tab): "health_report",
            str(self.fixes_tab): "fix_tools",
            str(self.profiles_tab): "profiles_dns",
            str(self.certs_tab): "certificates",
            str(self.browser_tab): "browser_tests",
            str(self.docs_tab): "docs",
        }
        return tab_to_key.get(selected, "dashboard")

    def show_current_help(self) -> None:
        self.show_help_topic(self._current_help_key())

    def show_help_topic(self, key: str) -> None:
        text = self.help_topics.get(key, "No help topic is registered for this item yet.")
        window = tk.Toplevel(self)
        window.title("Help")
        window.configure(bg=COLORS["bg"])
        window.geometry(f"{self._scaled(640)}x{self._scaled(520)}")
        window.minsize(self._scaled(520), self._scaled(360))
        window.transient(self)
        header = tk.Frame(window, bg=COLORS["bg"])
        header.pack(fill="x", padx=self._scaled(18), pady=(self._scaled(16), self._scaled(8)))
        title = text.splitlines()[0] if text else "Help"
        tk.Label(header, text=title, bg=COLORS["bg"], fg=COLORS["ink"], font=self.fonts["h1"], anchor="w").pack(side="left", fill="x", expand=True)
        ttk.Button(header, text="Close", style="Soft.TButton", command=window.destroy).pack(side="right")
        body = tk.Text(window, bg=COLORS["panel"], fg=COLORS["ink"], relief="flat", wrap="word", font=self.fonts["body"], padx=self._scaled(14), pady=self._scaled(12))
        body.pack(fill="both", expand=True, padx=self._scaled(18), pady=(0, self._scaled(18)))
        body.insert("1.0", text)
        body.configure(state="disabled")

    def _highlight_active_nav(self) -> None:
        if not hasattr(self, "tabs"):
            return
        selected = self.tabs.select()
        tab_to_name = {
            str(self.dashboard_tab): "Dashboard",
            str(self.start_tab): "Start Here",
            str(self.validation_tab): "Checks",
            str(self.health_tab): "Health Report",
            str(self.fixes_tab): "Fix Tools",
            str(self.profiles_tab): "Profiles & DNS",
            str(self.certs_tab): "Certificates",
            str(self.browser_tab): "Browser Tests",
            str(self.docs_tab): "Docs",
        }
        active_name = tab_to_name.get(selected)
        if active_name:
            self.screen_title.set(active_name)
        for name, button in self.nav_button_widgets.items():
            is_active = name == active_name
            button.configure(bg=COLORS["blue"] if is_active else COLORS["sidebar_active"], fg="#ffffff" if is_active else "#f8fafc")

    def _build_metrics_bar(self, parent: tk.Widget) -> None:
        bar = tk.Frame(parent, bg=COLORS["bg"])
        bar.pack(fill="x", padx=self._scaled(24), pady=(0, self._scaled(10)))
        self.metric_tunnel_label = self._metric_card(bar, "Proxy", "Checking", COLORS["amber"])
        self.metric_stream_label = self._metric_card(bar, "Traffic", "0 Connections", COLORS["ink"])
        self.metric_privacy_label = self._metric_card(bar, "Data", "Local Only", COLORS["green"])
        self.metric_next_label = self._metric_card(bar, "Next Step", "Check setup", COLORS["blue"])

    def _metric_card(self, parent: tk.Widget, title: str, value: str, color: str) -> tk.Label:
        card = tk.Frame(parent, bg=COLORS["panel"], highlightbackground=COLORS["line"], highlightthickness=1)
        card.pack(side="left", fill="x", expand=True, padx=(0, self._scaled(8)))
        tk.Label(card, text=title.upper(), bg=COLORS["panel"], fg=COLORS["muted"], font=self.fonts["caption_bold"], anchor="w").pack(fill="x", padx=self._scaled(12), pady=(self._scaled(9), 0))
        label = tk.Label(card, text=value, bg=COLORS["panel"], fg=color, font=self.fonts["h2"], anchor="w")
        label.pack(fill="x", padx=self._scaled(12), pady=(self._scaled(2), self._scaled(10)))
        return label

    def _tab(self) -> tk.Frame:
        return tk.Frame(self.tabs, bg=COLORS["panel"], padx=self._scaled(20), pady=self._scaled(18))

    def _card(self, parent: tk.Widget, title: str) -> tk.Frame:
        frame = tk.Frame(parent, bg=COLORS["panel"], highlightbackground=COLORS["line"], highlightthickness=1)
        header = tk.Frame(frame, bg=COLORS["panel"])
        header.pack(fill="x", padx=16, pady=(14, 4))
        tk.Label(header, text=title, bg=COLORS["panel"], fg=COLORS["ink"], font=self.fonts["h2"], anchor="w").pack(side="left", fill="x", expand=True)
        if self._help_key(title) in self.help_topics:
            ttk.Button(header, text="Help", style="Soft.TButton", command=lambda key=self._help_key(title): self.show_help_topic(key)).pack(side="right")
        return frame

    def _help_key(self, raw: str) -> str:
        return re.sub(r"_+", "_", "".join(ch.lower() if ch.isalnum() else "_" for ch in raw)).strip("_")

    def _form_row(self, parent: tk.Widget, label: str, variable: tk.StringVar) -> None:
        row = tk.Frame(parent, bg=COLORS["panel"])
        row.pack(fill="x", padx=16, pady=(4, 6))
        tk.Label(row, text=label, bg=COLORS["panel"], fg=COLORS["muted"], width=12, anchor="w").pack(side="left")
        ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True)

    def _status_chip(self, parent: tk.Widget, name: str) -> tk.Label:
        box = tk.Frame(parent, bg="#f8fafc", highlightbackground=COLORS["line"], highlightthickness=1)
        box.pack(side="left", fill="x", expand=True, padx=(0, 8))
        tk.Label(box, text=name, bg="#f8fafc", fg=COLORS["muted"], font=("Segoe UI", 9), anchor="w").pack(fill="x", padx=10, pady=(8, 1))
        label = tk.Label(box, text="Checking", bg="#f8fafc", fg=COLORS["amber"], font=("Segoe UI", 11, "bold"), anchor="w")
        label.pack(fill="x", padx=10, pady=(0, 8))
        self.status_chip_labels[name] = label
        return label

    def _build_start_here(self) -> None:
        intro = tk.Label(
            self.start_tab,
            text="Recommended first run: check the config, install optional tools only if you need browser probes, create your own local CA, then test one browser page.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            wraplength=900,
            justify="left",
            anchor="w",
        )
        intro.pack(fill="x", pady=(0, 12))

        flow = tk.Frame(self.start_tab, bg=COLORS["panel"])
        flow.pack(fill="x", pady=(0, 14))
        steps = [
            ("1. Validate", "Confirms config, routes, metadata, and static preflight.", self.safe_auto_fix, "Repair Local Files", "Accent.TButton"),
            ("2. Dependencies", "Adds Playwright, CloakBrowser, PyInstaller, and local Xray only when needed.", self.install_optional_dependencies, "Install Optional Dependencies", "Soft.TButton"),
            ("3. Certificate", "Creates personal local CA files; trust-store install stays manual.", self.generate_ca, "Generate Local CA", "Danger.TButton"),
            ("4. Browser Check", "Loads a page through 127.0.0.1:10808 after Xray is running.", self.run_browser_diagnostics, "Run Page Check", "Accent.TButton"),
        ]
        for index, (title, detail, command, button, style) in enumerate(steps):
            card = self._card(flow, title)
            card.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 10, 0), pady=(0, 10))
            flow.columnconfigure(index, weight=1)
            tk.Label(card, text=detail, bg=COLORS["panel"], fg=COLORS["muted"], wraplength=210, justify="left", anchor="nw").pack(fill="x", padx=16, pady=(2, 12))
            ttk.Button(card, text=button, style=style, command=command).pack(anchor="w", padx=16, pady=(0, 16))

        help_card = self._card(self.start_tab, "When Something Fails")
        help_card.pack(fill="x", pady=(0, 14))
        help_text = (
            "WARN usually means the local machine is not fully set up yet: missing CA files, Xray not running, proxy already enabled, "
            "or optional browser dependencies not installed. FAIL means a config or script check needs attention before release."
        )
        tk.Label(help_card, text=help_text, bg=COLORS["panel"], fg=COLORS["muted"], wraplength=900, justify="left", anchor="w").pack(fill="x", padx=16, pady=(4, 10))
        row = tk.Frame(help_card, bg=COLORS["panel"])
        row.pack(fill="x", padx=16, pady=(0, 16))
        ttk.Button(row, text="Explain Output", style="Soft.TButton", command=self.explain_output).pack(side="left", padx=(0, 10))
        ttk.Button(row, text="Copy Issue Summary", style="Soft.TButton", command=self.copy_issue_summary).pack(side="left", padx=(0, 10))
        ttk.Button(row, text="Open Troubleshooting Docs", style="Soft.TButton", command=lambda: self.open_path(ROOT / "docs" / "preflight-and-diagnostics.md")).pack(side="left")

    def _build_dashboard(self) -> None:
        hero = tk.Frame(self.dashboard_tab, bg=COLORS["panel"])
        hero.pack(fill="x", pady=(0, 12))
        left = tk.Frame(hero, bg=COLORS["panel"])
        left.pack(side="left", fill="both", expand=True)
        tk.Label(left, text="Simple Dashboard", bg=COLORS["panel"], fg=COLORS["ink"], font=("Segoe UI", 18, "bold"), anchor="w").pack(fill="x")
        tk.Label(
            left,
            textvariable=self.simple_next_step,
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            wraplength=620,
            justify="left",
            anchor="w",
        ).pack(fill="x", pady=(4, 0))
        right = tk.Frame(hero, bg=COLORS["panel"])
        right.pack(side="right", fill="y", padx=(18, 0))
        tk.Label(right, text="Connection", bg=COLORS["panel"], fg=COLORS["muted"], anchor="e").pack(fill="x")
        self.connection_label = tk.Label(right, textvariable=self.connection_state, bg=COLORS["panel"], fg=COLORS["amber"], font=("Segoe UI", 14, "bold"), anchor="e")
        self.connection_label.pack(fill="x")

        glance = self._card(self.dashboard_tab, "At a glance")
        glance.pack(fill="x", pady=(0, 12))
        chip_row = tk.Frame(glance, bg=COLORS["panel"])
        chip_row.pack(fill="x", padx=16, pady=(8, 16))
        for name in ("Setup", "Proxy", "Certificate", "Browser", "Privacy"):
            self._status_chip(chip_row, name)

        main = tk.Frame(self.dashboard_tab, bg=COLORS["panel"])
        main.pack(fill="x", pady=(0, 12))
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)

        connection = self._card(main, "1. Proxy Control")
        connection.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=(0, 12))
        tk.Label(
            connection,
            text="Start or stop the local Xray process launched by this app. Existing external clients are detected but not killed.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            wraplength=420,
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=16, pady=(2, 10))
        profile_row = tk.Frame(connection, bg=COLORS["panel"])
        profile_row.pack(fill="x", padx=16, pady=(0, 10))
        tk.Label(profile_row, text="Profile", bg=COLORS["panel"], fg=COLORS["muted"], width=12, anchor="w").pack(side="left")
        profile_box = ttk.Combobox(profile_row, textvariable=self.active_config, values=self._profile_choices(), state="readonly")
        profile_box.pack(side="left", fill="x", expand=True)
        profile_box.bind("<<ComboboxSelected>>", lambda _event: self.refresh_status())
        conn_row = tk.Frame(connection, bg=COLORS["panel"])
        conn_row.pack(fill="x", padx=16, pady=(0, 16))
        ttk.Button(conn_row, text="Start Proxy", style="Accent.TButton", command=self.connect_xray).pack(side="left", padx=(0, 10))
        ttk.Button(conn_row, text="Stop Proxy", style="Danger.TButton", command=self.disconnect_xray).pack(side="left", padx=(0, 10))
        ttk.Button(conn_row, text="Check Health", style="Soft.TButton", command=self.run_health_probe).pack(side="left")

        browser = self._card(main, "2. Browser Check")
        browser.grid(row=0, column=1, sticky="nsew", padx=(0, 0), pady=(0, 12))
        self._form_row(browser, "URL", self.browser_url)
        self._form_row(browser, "Proxy", self.browser_proxy)
        path_row = tk.Frame(browser, bg=COLORS["panel"])
        path_row.pack(fill="x", padx=16, pady=(4, 10))
        tk.Label(path_row, text="Browser path", bg=COLORS["panel"], fg=COLORS["muted"], width=12, anchor="w").pack(side="left")
        ttk.Entry(path_row, textvariable=self.browser_executable).pack(side="left", fill="x", expand=True)
        ttk.Button(path_row, text="Browse", style="Soft.TButton", command=self.choose_browser_path).pack(side="left", padx=(8, 0))
        brow_row = tk.Frame(browser, bg=COLORS["panel"])
        brow_row.pack(fill="x", padx=16, pady=(0, 16))
        ttk.Button(brow_row, text="Run Page Check", style="Accent.TButton", command=self.run_browser_diagnostics).pack(side="left", padx=(0, 10))
        ttk.Button(brow_row, text="Run Fingerprint Check", style="Soft.TButton", command=self.run_browser_stealth).pack(side="left", padx=(0, 10))
        ttk.Button(brow_row, text="Reset Fields", style="Soft.TButton", command=self.reset_gui_defaults).pack(side="left")

        fixes = self._card(self.dashboard_tab, "3. Quick Actions")
        fixes.pack(fill="x", pady=(0, 12))
        fix_row = tk.Frame(fixes, bg=COLORS["panel"])
        fix_row.pack(fill="x", padx=16, pady=(8, 16))
        ttk.Button(fix_row, text="Check Setup", style="Accent.TButton", command=self.run_beginner_setup_check).pack(side="left", padx=(0, 10))
        ttk.Button(fix_row, text="Repair Local Files", style="Accent.TButton", command=self.safe_auto_fix).pack(side="left", padx=(0, 10))
        ttk.Button(fix_row, text="Generate Local CA", style="Danger.TButton", command=self.generate_ca).pack(side="left", padx=(0, 10))
        ttk.Button(fix_row, text="Install Browser Tools", style="Soft.TButton", command=self.install_diagnostics_dependencies).pack(side="left", padx=(0, 10))
        ttk.Button(fix_row, text="Copy Issue Summary", style="Soft.TButton", command=self.copy_issue_summary).pack(side="left")

        telemetry = self._card(self.dashboard_tab, "4. Activity History")
        telemetry.pack(fill="x", pady=(0, 12))
        tk.Label(
            telemetry,
            text="Local event history for this GUI only. It records command labels, result codes, durations, and status snapshots; it never uploads data or stores payloads/private keys.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            wraplength=900,
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=16, pady=(2, 8))
        tk.Label(telemetry, textvariable=self.telemetry_summary, bg=COLORS["panel"], fg=COLORS["ink"], font=("Segoe UI", 10, "bold"), anchor="w").pack(fill="x", padx=16)
        tk.Label(telemetry, textvariable=self.telemetry_last, bg=COLORS["panel"], fg=COLORS["muted"], anchor="w").pack(fill="x", padx=16, pady=(2, 8))
        telemetry_row = tk.Frame(telemetry, bg=COLORS["panel"])
        telemetry_row.pack(fill="x", padx=16, pady=(0, 16))
        ttk.Button(telemetry_row, text="Run Full Status", style="Accent.TButton", command=self.run_status_snapshot).pack(side="left", padx=(0, 10))
        ttk.Button(telemetry_row, text="Show Activity", style="Soft.TButton", command=self.show_telemetry_summary).pack(side="left", padx=(0, 10))
        ttk.Button(telemetry_row, text="Export Activity", style="Soft.TButton", command=self.export_telemetry).pack(side="left", padx=(0, 10))
        ttk.Button(telemetry_row, text="Clear Activity", style="Danger.TButton", command=self.clear_telemetry).pack(side="left")

        summary = self._card(self.dashboard_tab, "Status summary")
        summary.pack(fill="x")
        grid = tk.Frame(summary, bg=COLORS["panel"])
        grid.pack(fill="x", padx=16, pady=(8, 16))
        self.status_labels: dict[str, tk.Label] = {}
        for index, title in enumerate(("Config", "Certificate", "Profiles", "Health", "Dependencies", "Browser", "Privacy")):
            box = tk.Frame(grid, bg="#f8fafc", highlightbackground=COLORS["line"], highlightthickness=1)
            box.grid(row=index // 4, column=index % 4, sticky="nsew", padx=(0 if index % 4 == 0 else 8, 0), pady=(0, 8))
            grid.columnconfigure(index % 4, weight=1)
            tk.Label(box, text=title, bg="#f8fafc", fg=COLORS["ink"], font=("Segoe UI", 10, "bold"), anchor="w").pack(fill="x", padx=10, pady=(8, 2))
            label = tk.Label(box, text="Checking...", bg="#f8fafc", fg=COLORS["muted"], font=("Segoe UI", 9), justify="left", anchor="nw", wraplength=210)
            label.pack(fill="both", expand=True, padx=10, pady=(0, 8))
            self.status_labels[title] = label

    @property
    def validation_commands(self) -> list[CommandSpec]:
        return [
            CommandSpec("Validate Config", "Static validation for primary config.", tuple(py_script("validate_config.py", str(CONFIG)))),
            CommandSpec("Static Preflight", "Local preflight without cert/runtime/DNS requirements.", tuple(py_script("preflight.py", "--config", str(CONFIG), "--no-dns", "--skip-cert", "--skip-runtime"))),
            CommandSpec("Metadata", "Provider/profile/health metadata checks.", tuple(py_script("validate_metadata.py"))),
            CommandSpec("Route Tests", "Route order, references, and policy tests.", tuple(py_script("route_policy_tests.py"))),
            CommandSpec("Route Rule Linter", "First-match shadow and decrypted-inbound isolation lint.", tuple(py_script("route_rule_linter.py", str(CONFIG)))),
            CommandSpec("Protocol Tests", "Protocol metadata and docs coverage tests.", tuple(py_script("protocol_policy_tests.py"))),
            CommandSpec("Repository Structure", "Required files and gitignore hygiene checks.", tuple(py_script("repository_structure_tests.py"))),
            CommandSpec("Provider Dossiers", "Provider metadata, route-tag linkage, and rollback/evidence checks.", tuple(py_script("provider_dossier_validate.py"))),
            CommandSpec("Geodata Pin Verify", "Verifies geodata lock file when present; info-only if absent.", tuple(py_script("geodata_pin.py", "--verify"))),
            CommandSpec("Health Probe", "Redacted health report for ports/cert/trust/dns/providers.", tuple(py_script("health_probe.py", "--config", str(CONFIG), "--cert", str(CERT), "--key", str(KEY), "--providers-dir", str(ROOT / "providers")))),
            CommandSpec("Route Intent Sync", "Compare config ruleTags against configs/route-intent.json.", tuple(py_script("route_intent_sync.py", str(CONFIG)))),
            CommandSpec("Config-src Validate", "Validate config-src manifest and run build-time checks.", tuple(py_script("config_src_validate.py", "--run-steps"))),
            CommandSpec("Config-src Build", "Validate and compile config-src output to build/config/.", tuple(py_script("config_src_build.py"))),
            CommandSpec("Transport Governance", "Validate transport experiment manifest guardrails.", tuple(py_script("transport_experiment_validate.py"))),
            CommandSpec("Lab Evidence Bundle", "Run DNS/fakeDNS/captive harness scenarios locally.", tuple(py_script("lab_evidence_run.py", "--allow-warn"))),
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
        intro = tk.Label(self.validation_tab, text="Run local checks before opening issues or publishing changes. Output stays on this machine.", bg=COLORS["panel"], fg=COLORS["muted"], anchor="w")
        intro.pack(fill="x", pady=(0, 12))
        button_grid = tk.Frame(self.validation_tab, bg=COLORS["panel"])
        button_grid.pack(fill="x", pady=(0, 12))
        for index, spec in enumerate(self.validation_commands):
            card = self._card(button_grid, spec.label)
            card.grid(row=index // 3, column=index % 3, sticky="nsew", padx=(0 if index % 3 == 0 else 10, 0), pady=(0, 10))
            button_grid.columnconfigure(index % 3, weight=1)
            tk.Label(card, text=spec.description, bg=COLORS["panel"], fg=COLORS["muted"], wraplength=230, justify="left").pack(fill="x", padx=16, pady=(2, 12))
            ttk.Button(card, text="Run", style="Accent.TButton", command=lambda s=spec: self.run_spec(s)).pack(anchor="w", padx=16, pady=(0, 16))

        controls = tk.Frame(self.validation_tab, bg=COLORS["panel"])
        controls.pack(fill="x", pady=(0, 8))
        ttk.Button(controls, text="Clear Output", style="Soft.TButton", command=self.clear_output).pack(side="left")
        ttk.Button(controls, text="Copy Output", style="Soft.TButton", command=self.copy_output).pack(side="left", padx=8)
        tk.Label(controls, text="Output is always visible in the bottom log streams.", bg=COLORS["panel"], fg=COLORS["muted"]).pack(side="left", padx=8)

    def _build_health(self) -> None:
        intro = tk.Label(
            self.health_tab,
            text=(
                "Health checks are local-only and redacted. They evaluate listener state, cert/key presence, trust-store match, "
                "DNS reachability, provider freshness, geodata hashes, captive portal warnings, read-only policy recommendations, "
                "and optional runtime checks. Use Lab Evidence for DNS harness scenarios and Decision Report for a support-safe summary."
            ),
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            wraplength=900,
            justify="left",
            anchor="w",
        )
        intro.pack(fill="x", pady=(0, 12))

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
        ttk.Button(row, text="Run Health Probe", style="Accent.TButton", command=self.run_health_probe).pack(side="left", padx=(0, 10))
        ttk.Button(row, text="Run Lab Evidence", style="Soft.TButton", command=self.run_lab_evidence).pack(side="left", padx=(0, 10))
        ttk.Button(row, text="Run Decision Report", style="Soft.TButton", command=self.run_decision_report).pack(side="left", padx=(0, 10))
        ttk.Button(row, text="Copy Phase Summary", style="Soft.TButton", command=self.copy_phase_summary).pack(side="left", padx=(0, 10))
        ttk.Button(row, text="Open Health Policy", style="Soft.TButton", command=lambda: self.open_path(ROOT / "configs" / "health-checks.yml")).pack(side="left", padx=(0, 10))
        ttk.Button(row, text="Open Decision Engine Doc", style="Soft.TButton", command=lambda: self.open_path(ROOT / "docs" / "decision-engine.md")).pack(side="left")

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
        ttk.Button(row2, text="Run Browser Smoke", style="Accent.TButton", command=self.run_browser_smoke).pack(side="left", padx=(0, 10))
        ttk.Button(row2, text="Open Browser Integration Guide", style="Soft.TButton", command=lambda: self.open_path(ROOT / "docs" / "chromium-integration.md")).pack(side="left")

    def _build_fixes_help(self) -> None:
        intro = tk.Label(
            self.fixes_tab,
            text="Use these when checks are noisy or the app feels stuck. Fixes stay local and do not install certificate trust.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            anchor="w",
        )
        intro.pack(fill="x", pady=(0, 12))

        quick = self._card(self.fixes_tab, "Safe repair sequence")
        quick.pack(fill="x", pady=(0, 14))
        tk.Label(
            quick,
            text="Regenerates profile JSON, creates alternate-port profiles, validates metadata/routes/protocols, and runs static preflight.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            wraplength=820,
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=16, pady=(4, 10))
        qrow = tk.Frame(quick, bg=COLORS["panel"])
        qrow.pack(fill="x", padx=16, pady=(0, 16))
        ttk.Button(qrow, text="Repair Local Files", style="Accent.TButton", command=self.safe_auto_fix).pack(side="left", padx=(0, 10))
        ttk.Button(qrow, text="Install Optional Dependencies", style="Accent.TButton", command=self.install_optional_dependencies).pack(side="left", padx=(0, 10))
        ttk.Button(qrow, text="Reset GUI Defaults", style="Soft.TButton", command=self.reset_gui_defaults).pack(side="left", padx=(0, 10))
        ttk.Button(qrow, text="Open Preflight Guide", style="Soft.TButton", command=lambda: self.open_path(ROOT / "docs" / "preflight-and-diagnostics.md")).pack(side="left")

        common = self._card(self.fixes_tab, "Common fixes")
        common.pack(fill="x", pady=(0, 14))
        row = tk.Frame(common, bg=COLORS["panel"])
        row.pack(fill="x", padx=16, pady=(8, 8))
        ttk.Button(row, text="Regenerate Profiles", style="Accent.TButton", command=self.generate_standard_profiles).pack(side="left", padx=(0, 10))
        ttk.Button(row, text="Create Alternate Ports", style="Soft.TButton", command=self.generate_alt_profiles).pack(side="left", padx=(0, 10))
        ttk.Button(row, text="Certificate Status", style="Soft.TButton", command=self.cert_status).pack(side="left", padx=(0, 10))
        ttk.Button(row, text="FakeDNS Recovery", style="Soft.TButton", command=lambda: self.open_path(ROOT / "docs" / "fakedns-recovery.md")).pack(side="left")

        row2 = tk.Frame(common, bg=COLORS["panel"])
        row2.pack(fill="x", padx=16, pady=(0, 16))
        ttk.Button(row2, text="Install Page Check Tools", style="Soft.TButton", command=self.install_diagnostics_dependencies).pack(side="left", padx=(0, 10))
        ttk.Button(row2, text="Install Fingerprint Tools", style="Soft.TButton", command=self.install_stealth_dependencies).pack(side="left", padx=(0, 10))
        ttk.Button(row2, text="Browser Install Hints", style="Soft.TButton", command=self.browser_install_hints).pack(side="left", padx=(0, 10))
        ttk.Button(row2, text="Open Xray Releases", style="Soft.TButton", command=lambda: webbrowser.open(XRAY_RELEASES_URL)).pack(side="left")

        row3 = tk.Frame(common, bg=COLORS["panel"])
        row3.pack(fill="x", padx=16, pady=(0, 16))
        ttk.Button(row3, text="Install PyInstaller", style="Soft.TButton", command=self.install_pyinstaller).pack(side="left", padx=(0, 10))
        ttk.Button(row3, text="Download Xray", style="Soft.TButton", command=self.download_xray).pack(side="left", padx=(0, 10))
        ttk.Button(row3, text="Open GUI Guide", style="Soft.TButton", command=lambda: self.open_path(ROOT / "docs" / "gui.md")).pack(side="left", padx=(0, 10))
        ttk.Button(row3, text="Open Xray-config Folder", style="Soft.TButton", command=lambda: self.open_path(ROOT / "Xray-config")).pack(side="left")

    def _build_output_pane(self, parent: tk.Widget) -> None:
        outer = tk.Frame(parent, bg=COLORS["bg"])
        outer.pack(fill="x", padx=self._scaled(24), pady=(0, self._scaled(24)))
        frame = tk.Frame(outer, bg=COLORS["panel"], highlightbackground=COLORS["line"], highlightthickness=1)
        frame.pack(fill="x")
        header = tk.Frame(frame, bg=COLORS["panel"])
        header.pack(fill="x", padx=self._scaled(14), pady=(self._scaled(10), self._scaled(6)))
        tk.Label(header, text="Local Log Streams", bg=COLORS["panel"], fg=COLORS["ink"], font=self.fonts["h2"]).pack(side="left")
        tk.Label(header, text="System output, proxy output, and audit output are separated for easier triage.", bg=COLORS["panel"], fg=COLORS["muted"], font=self.fonts["caption"]).pack(side="left", padx=self._scaled(10))
        ttk.Button(header, text="Clear", style="Soft.TButton", command=self.clear_output).pack(side="right")
        ttk.Button(header, text="Copy All", style="Soft.TButton", command=self.copy_output).pack(side="right", padx=self._scaled(8))
        self.output_notebook = ttk.Notebook(frame)
        self.output_notebook.pack(fill="both", expand=True, padx=self._scaled(14), pady=(0, self._scaled(14)))
        self.output_buffers = {
            "sys": self._create_log_buffer("System"),
            "xray": self._create_log_buffer("Xray Core"),
            "audit": self._create_log_buffer("Preflight / Linters"),
        }
        self.output = self.output_buffers["sys"]
        self.log_multiplexer = LogMultiplexer(self.output_buffers)
        self.after(100, self._drain_log_buffers)

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
        profiles = self._card(self.profiles_tab, "Operating profiles")
        profiles.pack(fill="x", pady=(0, 14))
        tk.Label(profiles, text="Regenerate committed profile configs, or create local alternate-port variants when default ports are occupied.", bg=COLORS["panel"], fg=COLORS["muted"], anchor="w").pack(fill="x", padx=16, pady=(4, 10))
        row = tk.Frame(profiles, bg=COLORS["panel"])
        row.pack(fill="x", padx=16, pady=(0, 16))
        ttk.Button(row, text="Regenerate Standard Profiles", style="Accent.TButton", command=self.generate_standard_profiles).pack(side="left", padx=(0, 10))
        tk.Label(row, text="Offset", bg=COLORS["panel"], fg=COLORS["muted"]).pack(side="left")
        ttk.Entry(row, textvariable=self.profile_offset, width=8).pack(side="left", padx=6)
        tk.Label(row, text="Suffix", bg=COLORS["panel"], fg=COLORS["muted"]).pack(side="left")
        ttk.Entry(row, textvariable=self.profile_suffix, width=14).pack(side="left", padx=6)
        ttk.Button(row, text="Generate Alternate Profiles", style="Soft.TButton", command=self.generate_alt_profiles).pack(side="left", padx=10)

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
        certs = self._card(self.certs_tab, "Certificate lifecycle")
        certs.pack(fill="x", pady=(0, 14))
        text = (
            "Use personal local certificates only. The GUI can inspect or generate local CA files, "
            "but it never installs trust silently and never uploads keys."
        )
        tk.Label(certs, text=text, bg=COLORS["panel"], fg=COLORS["muted"], wraplength=740, justify="left", anchor="w").pack(fill="x", padx=16, pady=(4, 12))
        row = tk.Frame(certs, bg=COLORS["panel"])
        row.pack(fill="x", padx=16, pady=(0, 16))
        ttk.Button(row, text="Certificate Status", style="Accent.TButton", command=self.cert_status).pack(side="left", padx=(0, 10))
        ttk.Button(row, text="Check Cert/Key Pair", style="Soft.TButton", command=self.cert_pair).pack(side="left", padx=(0, 10))
        ttk.Button(row, text="Generate Local CA", style="Danger.TButton", command=self.generate_ca).pack(side="left", padx=(0, 10))
        ttk.Button(row, text="Trust Instructions", style="Soft.TButton", command=self.trust_instructions).pack(side="left", padx=(0, 10))
        ttk.Button(row, text="Open Xray-config Folder", style="Soft.TButton", command=lambda: self.open_path(ROOT / "Xray-config")).pack(side="left")

    def _build_browser(self) -> None:
        intro = (
            "Two-part browser model: Page Check verifies proxy and CA wiring with stock Chromium. "
            "Fingerprint Check uses CloakBrowser (default) for browser fingerprint testing. "
            "Both paths send traffic to the local mixed inbound only."
        )
        tk.Label(self.browser_tab, text=intro, bg=COLORS["panel"], fg=COLORS["muted"], wraplength=820, justify="left", anchor="w").pack(fill="x", pady=(0, 12))

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
        drow = tk.Frame(diag, bg=COLORS["panel"])
        drow.pack(fill="x", padx=16, pady=(0, 8))
        tk.Label(drow, text="Chrome path (optional)", bg=COLORS["panel"], fg=COLORS["muted"]).pack(side="left")
        ttk.Entry(drow, textvariable=self.browser_executable, width=48).pack(side="left", padx=6)
        drow2 = tk.Frame(diag, bg=COLORS["panel"])
        drow2.pack(fill="x", padx=16, pady=(0, 16))
        ttk.Checkbutton(drow2, text="Headless", variable=self.browser_headless).pack(side="left", padx=(0, 12))
        ttk.Button(drow2, text="Run page check", style="Accent.TButton", command=self.run_browser_diagnostics).pack(side="left", padx=(0, 10))
        ttk.Button(
            drow2,
            text="Install hint (Playwright)",
            style="Soft.TButton",
            command=lambda: self._append_output(
                "\nPage check tools install:\n  pip install -r requirements-browser-diagnostics.txt\n"
                "  playwright install chromium\n"
                "  # Linux only, if dependencies are missing: playwright install-deps chromium\n"
            ),
        ).pack(side="left", padx=(0, 10))
        if os.name == "nt":
            ttk.Button(drow2, text="Launch stock Chrome (PS)", style="Soft.TButton", command=self.launch_diagnostics_chrome_ps).pack(side="left")

        stealth = self._card(self.browser_tab, "Path 2 - Fingerprint Check (CloakBrowser)")
        stealth.pack(fill="x", pady=(0, 14))
        stealth_url = read_browser_integration().get("stealth", {}).get("project_url", CLOAKBROWSER_URL)
        tk.Label(
            stealth,
            text=f"Default engine: CloakBrowser — {stealth_url}",
            bg=COLORS["panel"],
            fg=COLORS["ink"],
            wraplength=780,
            justify="left",
            anchor="w",
            font=("Segoe UI", 10, "bold"),
        ).pack(fill="x", padx=16, pady=(2, 4))
        tk.Label(
            stealth,
            text="Browser fingerprint testing only. Xray still owns MITM, routing, and domain fronting.",
            bg=COLORS["panel"],
            fg=COLORS["muted"],
            wraplength=780,
            justify="left",
            anchor="w",
        ).pack(fill="x", padx=16, pady=(0, 8))
        srow = tk.Frame(stealth, bg=COLORS["panel"])
        srow.pack(fill="x", padx=16, pady=(0, 8))
        tk.Label(srow, text="Fingerprint seed", bg=COLORS["panel"], fg=COLORS["muted"]).pack(side="left")
        ttk.Entry(srow, textvariable=self.browser_fingerprint_seed, width=16).pack(side="left", padx=6)
        ttk.Checkbutton(srow, text="geoip (timezone/locale from proxy)", variable=self.browser_geoip).pack(side="left", padx=12)
        ttk.Checkbutton(srow, text="humanize", variable=self.browser_humanize).pack(side="left", padx=12)
        srow2 = tk.Frame(stealth, bg=COLORS["panel"])
        srow2.pack(fill="x", padx=16, pady=(0, 16))
        ttk.Button(srow2, text="Run fingerprint check", style="Accent.TButton", command=self.run_browser_stealth).pack(side="left", padx=(0, 10))
        ttk.Button(
            srow2,
            text="Install hint (CloakBrowser)",
            style="Soft.TButton",
            command=lambda: self._append_output(
                f"\nFingerprint tools install:\n  pip install -r requirements-browser-stealth.txt\n"
                f"  python -m cloakbrowser install\n  Project: {stealth_url}\n"
            ),
        ).pack(side="left", padx=(0, 10))
        ttk.Button(srow2, text="Open CloakBrowser on GitHub", style="Soft.TButton", command=lambda: webbrowser.open(stealth_url)).pack(side="left", padx=(0, 10))
        ttk.Button(srow2, text="Check CloakBrowser import", style="Soft.TButton", command=self.check_cloakbrowser_installed).pack(side="left")

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
        for index, (label, path) in enumerate(docs):
            card = self._card(grid, label)
            card.grid(row=index // 2, column=index % 2, sticky="ew", padx=(0 if index % 2 == 0 else 10, 0), pady=(0, 10))
            grid.columnconfigure(index % 2, weight=1)
            tk.Label(card, text=short_path(path), bg=COLORS["panel"], fg=COLORS["muted"], anchor="w").pack(fill="x", padx=16, pady=(2, 12))
            ttk.Button(card, text="Open", style="Soft.TButton", command=lambda p=path: self.open_path(p)).pack(anchor="w", padx=16, pady=(0, 16))

    def record_telemetry(self, event: str, status: str, detail: str = "", fields: dict[str, object] | None = None) -> None:
        LOCAL_STATE.mkdir(exist_ok=True)
        payload: dict[str, object] = {
            "ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "event": event,
            "status": status,
            "detail": detail[:240],
            "fields": fields or {},
        }
        try:
            with GUI_TELEMETRY.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, sort_keys=True) + "\n")
        except OSError:
            return
        self._update_telemetry_labels(payload)

    def _telemetry_events(self, limit: int | None = None) -> list[dict[str, object]]:
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
        self.telemetry_summary.set(f"Activity history: local only, {len(events)} event{'s' if len(events) != 1 else ''}")
        if latest:
            self.telemetry_last.set(f"Last activity: {latest.get('event', 'unknown')} / {latest.get('status', 'info')} / {latest.get('detail', '')}")
        else:
            self.telemetry_last.set("Last activity: none")

    def _status_snapshot(self) -> dict[str, object]:
        profiles = sorted((ROOT / "Xray-config").glob("MITM-DomainFronting.*.json"))
        host_python = find_host_python()
        local_xray = find_local_xray()
        loopback_open = port_accepts_loopback(10808)
        browser_cfg = read_browser_integration()
        return {
            "config_exists": CONFIG.exists(),
            "cert_exists": CERT.exists(),
            "key_exists": KEY.exists(),
            "profile_count": len(profiles),
            "loopback_10808_open": loopback_open,
            "xray_started_by_gui": self._xray_running_from_gui(),
            "xray_local": bool(local_xray),
            "xray_path": short_path(local_xray) if local_xray else "",
            "host_python": " ".join(host_python or []),
            "browser_proxy": self.browser_proxy.get().strip() or browser_cfg.get("default_proxy", "socks5://127.0.0.1:10808"),
            "browser_path_set": bool(self.browser_executable.get().strip()),
            "diagnostics_script": (SCRIPTS / "browser_diagnostics.py").exists(),
            "stealth_script": (SCRIPTS / "browser_stealth.py").exists(),
            "geodata_lock": (ROOT / "release-geodata-lock.json").exists(),
        }

    def _status_level(self, snapshot: dict[str, object]) -> tuple[str, str]:
        if not snapshot["config_exists"]:
            return "fail", "Primary config is missing."
        if not snapshot["cert_exists"] or not snapshot["key_exists"]:
            return "warn", "Generate local CA files before browser MITM testing."
        if not snapshot["loopback_10808_open"]:
            return "warn", "Local proxy is not listening yet. Start Proxy or start v2rayN."
        if not snapshot["diagnostics_script"] or not snapshot["stealth_script"]:
            return "warn", "Browser check scripts are missing."
        return "pass", "Ready for browser testing through the local proxy."

    def _set_label_state(self, label: tk.Label, text: str, level: str) -> None:
        color = {"pass": COLORS["green"], "warn": COLORS["amber"], "fail": COLORS["red"], "info": COLORS["blue"]}.get(level, COLORS["muted"])
        label.configure(text=text, fg=color)

    def _show_remediation_banner(self, level: str, code: str, message: str, action_text: str, action: Callable[[], None]) -> None:
        self._clear_remediation_banner()
        palette = {
            "fail": ("#fee2e2", "#fca5a5", "#991b1b", COLORS["red"]),
            "warn": ("#fffbeb", "#fde68a", "#92400e", COLORS["amber"]),
            "info": ("#eff6ff", "#bfdbfe", "#1e40af", COLORS["blue"]),
        }.get(level, ("#eff6ff", "#bfdbfe", "#1e40af", COLORS["blue"]))
        bg, border, fg, button_bg = palette
        banner = tk.Frame(self.banner_slot, bg=bg, highlightbackground=border, highlightthickness=1)
        banner.pack(fill="x")
        text_block = tk.Frame(banner, bg=bg)
        text_block.pack(side="left", fill="x", expand=True, padx=self._scaled(14), pady=self._scaled(10))
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
            padx=self._scaled(12),
            pady=self._scaled(7),
            font=self.fonts["body_bold"],
        ).pack(side="right", padx=self._scaled(14), pady=self._scaled(10))
        self.active_banner = banner

    def _clear_remediation_banner(self) -> None:
        if self.active_banner is not None:
            self.active_banner.destroy()
            self.active_banner = None

    def _update_remediation_banner(self, snapshot: dict[str, object], level: str) -> None:
        if not snapshot["config_exists"]:
            self._show_remediation_banner("fail", "CONFIG-MISSING", "Primary configuration is missing.", "Open Xray-config", lambda: self.open_path(ROOT / "Xray-config"))
        elif not snapshot["xray_local"]:
            self._show_remediation_banner("warn", "XRAY-MISSING", "The GUI cannot find a local Xray runtime.", "Download Xray", self.download_xray)
        elif not snapshot["cert_exists"] or not snapshot["key_exists"]:
            self._show_remediation_banner("warn", "CA-MISSING", "Local CA files are missing; browser MITM tests will fail until they exist and are trusted manually.", "Generate Local CA", self.generate_ca)
        elif not snapshot["loopback_10808_open"]:
            self._show_remediation_banner("info", "PROXY-OFFLINE", "No local proxy is listening yet. Start the dashboard-managed Xray process, or run Health if another client should be active.", "Start Proxy", self.connect_xray)
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
        if GUI_TELEMETRY.exists():
            try:
                GUI_TELEMETRY.unlink()
            except OSError as exc:
                messagebox.showerror("Clear activity history failed", str(exc))
                return
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
        choices = [str(CONFIG)]
        choices.extend(str(path) for path in sorted((ROOT / "Xray-config").glob("MITM-DomainFronting.*.json")))
        return choices

    def active_config_path(self) -> Path:
        raw = self.active_config.get().strip()
        path = Path(raw) if raw else CONFIG
        if not path.is_absolute():
            path = ROOT / path
        return path

    def _xray_running_from_gui(self) -> bool:
        return self.xray_process is not None and self.xray_process.poll() is None

    def connect_xray(self) -> None:
        if self._xray_running_from_gui():
            self._append_output("\nXray is already running from this dashboard.\n")
            self.record_telemetry("xray_connect", "info", "Already running from GUI")
            self.refresh_status()
            return
        if port_accepts_loopback(10808):
            self._append_output("\nPort 10808 is already accepting loopback connections. An external Xray/v2rayN instance may already be running.\n")
            self.record_telemetry("xray_connect", "info", "External listener already active", {"port": 10808})
            self.refresh_status()
            return
        xray = find_local_xray()
        if xray is None:
            self._append_output("\nLocal Xray binary not found. Use Download Xray, then Start Proxy again.\n")
            self.record_telemetry("xray_connect", "warn", "Local Xray binary not found")
            if messagebox.askyesno("Xray not found", "Download local Xray runtime now?"):
                self.download_xray()
            return
        config_path = self.active_config_path()
        if not config_path.exists():
            messagebox.showerror("Missing config", f"Selected config not found: {short_path(config_path)}")
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
        self._append_output(f"\nStarted Xray: {short_path(xray)}\nConfig: {short_path(config_path)}\n")
        self.stream_count = 0
        if hasattr(self, "metric_stream_label"):
            self.metric_stream_label.configure(text="0 Connections")
        self.record_telemetry("xray_connect", "info", "Started dashboard-launched Xray", {"xray_path": short_path(xray), "config": short_path(config_path)})
        self.current_process_label.set("Xray starting")
        threading.Thread(target=self._read_xray_output, daemon=True).start()
        self.after(900, self.refresh_status)

    def _read_xray_output(self) -> None:
        proc = self.xray_process
        if proc is None or proc.stdout is None:
            return
        for line in proc.stdout:
            self.after(0, lambda item=line: self._handle_xray_log_line(item))
        code = proc.poll()
        if self.xray_process is proc:
            self.xray_process = None
            self.xray_supervisor = None
        self.stream_count = 0
        self.after(0, lambda: self.record_telemetry("xray_exit", "info" if code == 0 else "warn", "Xray process exited", {"exit_code": code}))
        self.after(0, lambda: self._append_output(f"\nXray process exited with code {code}\n"))
        self.after(0, self.refresh_status)

    def _handle_xray_log_line(self, line: str) -> None:
        self._append_output("[xray] " + line, stream="xray")
        if "accepted" in line.lower():
            self.stream_count += 1
            if hasattr(self, "metric_stream_label"):
                self.metric_stream_label.configure(text=f"{self.stream_count} Connections")

    def disconnect_xray(self) -> None:
        if not self._xray_running_from_gui():
            if port_accepts_loopback(10808):
                messagebox.showinfo(
                    "External Xray detected",
                    "Port 10808 is open, but this app did not launch that process. Stop it in v2rayN/Xray or your process manager.",
                )
                self._append_output("\nCannot stop external Xray/v2rayN from this dashboard.\n")
                self.record_telemetry("xray_disconnect", "info", "External listener left untouched")
            else:
                self._append_output("\nNo dashboard-launched Xray process is running.\n")
                self.record_telemetry("xray_disconnect", "info", "No GUI-launched process running")
            self.refresh_status()
            return
        assert self.xray_process is not None
        self._stop_gui_xray()
        self.stream_count = 0
        self._append_output("\nStopped dashboard-launched Xray.\n")
        self.record_telemetry("xray_disconnect", "info", "Stopped dashboard-launched Xray")
        self.current_process_label.set("Xray stopped")
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
        if self._xray_running_from_gui():
            self.record_telemetry("app_closed", "info", "Stopping dashboard-launched Xray before close")
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
        try:
            data = read_json_config() if selected_config == CONFIG else json.loads(selected_config.read_text(encoding="utf-8")) if selected_config.exists() else {}
        except Exception:
            data = {}
        remarks = data.get("remarks", "unknown")
        min_version = data.get("version", {}).get("min") if isinstance(data.get("version"), dict) else "unknown"
        profiles = sorted((ROOT / "Xray-config").glob("MITM-DomainFronting.*.json"))
        snapshot = self._status_snapshot()
        level, detail = self._status_level(snapshot)
        loopback_open = bool(snapshot["loopback_10808_open"])
        cert_ok = bool(snapshot["cert_exists"] and snapshot["key_exists"])
        self._update_telemetry_labels()
        status_text = {"pass": "Ready", "warn": "Needs Attention", "fail": "Blocked"}.get(level, "Checking")
        self.overall_status.set(status_text)
        self.overall_detail.set(detail)
        status_bg = {"pass": "#dcfce7", "warn": "#fef3c7", "fail": "#fee2e2"}.get(level, "#dbeafe")
        status_fg = {"pass": COLORS["green"], "warn": COLORS["amber"], "fail": COLORS["red"]}.get(level, COLORS["blue"])
        self.header_status_label.configure(bg=status_bg, fg=status_fg)
        if level != self.last_status_level:
            self.record_telemetry("status_changed", level, detail, {"previous": self.last_status_level})
            self.last_status_level = level
        if self._xray_running_from_gui():
            self.connection_state.set("Connected")
            self.simple_next_step.set("Xray is running from the dashboard. Test the browser, then review Health if anything fails.")
            self.connection_label.configure(fg=COLORS["green"])
        elif loopback_open:
            self.connection_state.set("External client active")
            self.simple_next_step.set("A local proxy is already listening on 127.0.0.1:10808. Test the browser or run Health.")
            self.connection_label.configure(fg=COLORS["green"])
        else:
            self.connection_state.set("Not connected")
            self.simple_next_step.set("Run Check Setup, then Start Proxy or start v2rayN before testing the browser.")
            self.connection_label.configure(fg=COLORS["amber"])
        if hasattr(self, "metric_tunnel_label"):
            if self._xray_running_from_gui():
                self.metric_tunnel_label.configure(text="ACTIVE", fg=COLORS["green"])
            elif loopback_open:
                self.metric_tunnel_label.configure(text="EXTERNAL", fg=COLORS["green"])
            else:
                self.metric_tunnel_label.configure(text="OFFLINE", fg=COLORS["amber"])
            self.metric_stream_label.configure(text=f"{self.stream_count} Connections")
            next_text = "Browser test" if loopback_open and cert_ok else "Generate CA" if not cert_ok else "Start Proxy"
            self.metric_next_label.configure(text=next_text, fg=COLORS["blue"] if loopback_open else COLORS["amber"])
        self._set_label_state(self.status_chip_labels["Setup"], status_text, level)
        self._set_label_state(self.status_chip_labels["Proxy"], "Running" if loopback_open else "Stopped", "pass" if loopback_open else "warn")
        self._set_label_state(self.status_chip_labels["Certificate"], "Ready" if cert_ok else "Missing", "pass" if cert_ok else "warn")
        browser_ok = bool(snapshot["diagnostics_script"] and snapshot["stealth_script"])
        self._set_label_state(self.status_chip_labels["Browser"], "Ready" if browser_ok else "Missing tools", "pass" if browser_ok else "warn")
        self._set_label_state(self.status_chip_labels["Privacy"], "Local only", "info")
        self.status_labels["Config"].configure(text=f"{short_path(selected_config)}\nremarks: {remarks}\nXray min: {min_version}", fg=COLORS["green"] if selected_config.exists() else COLORS["red"])
        self.status_labels["Certificate"].configure(text=f"crt: {'present' if CERT.exists() else 'missing'}\nkey: {'present' if KEY.exists() else 'missing'}\nlocal only, ignored by git", fg=COLORS["green"] if CERT.exists() and KEY.exists() else COLORS["amber"])
        self.status_labels["Profiles"].configure(text=f"{len(profiles)} generated profile configs\nstrict / balanced / compatibility / debug", fg=COLORS["green"] if len(profiles) >= 4 else COLORS["amber"])
        lock_path = ROOT / "release-geodata-lock.json"
        health_lines = [
            f"geodata lock: {'present' if lock_path.exists() else 'optional'}",
            "Health / Lab Evidence / Decision Report",
            "on Health tab",
        ]
        self.status_labels["Health"].configure(text="\n".join(health_lines), fg=COLORS["green"] if lock_path.exists() else COLORS["amber"])
        host_python = find_host_python()
        local_xray = find_local_xray()
        dep_lines = [
            f"Python: {'found' if host_python else 'missing'}",
            f"Xray: {short_path(local_xray) if local_xray else 'not local'}",
            "Install buttons available",
        ]
        self.status_labels["Dependencies"].configure(text="\n".join(dep_lines), fg=COLORS["green"] if host_python and local_xray else COLORS["amber"])
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
                if code != 0 and final_code == 0:
                    final_code = code
            text = "\n".join(chunks)
            duration_ms = int((time.perf_counter() - started) * 1000)
            self.after(0, lambda: self._finish_command(label, final_code, text, None, duration_ms))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_command(self, label: str, code: int, output: str, after: Callable[[int, str], None] | None, duration_ms: int | None = None) -> None:
        status = "OK" if code == 0 else "Needs attention"
        self._append_output(f"{output}\n[{status}] {label} exited with code {code}\n", stream="audit")
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
            "  Browser dependency errors: use Install Diagnostics or Install Fingerprint Tools in Fix Tools.\n"
        )

    def copy_issue_summary(self) -> None:
        data = read_json_config()
        profiles = sorted((ROOT / "Xray-config").glob("MITM-DomainFronting.*.json"))
        summary = "\n".join([
            "MITM-DomainFronting redacted issue summary",
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
        self.run_async(
            "Decision report",
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
                target,
                "--provider-family",
                "unknown",
                "--json-out",
                str(report_path),
            ),
            timeout=120,
            after=lambda code, output: self._after_decision_report(code, output, report_path),
        )

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
        self._append_output(
            "\nPhase diagnostics summary:\n"
            f"  phase: {phase}\n"
            f"  confidence: {confidence}\n"
            f"  action: {action}\n"
            f"  reason: {reason}\n"
            f"  report file: {short_path(report_path)}\n",
            stream="audit",
        )

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
                "MITM-DomainFronting phase summary (redacted)",
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
            "Download Xray",
            "Download the latest Xray runtime from GitHub into the local xray folder?",
        ):
            return
        self.run_sequence("Download Xray", [("Download Xray runtime", py_script("install_xray.py", "--out-dir", str(ROOT / "xray")), 300)])

    def install_optional_dependencies(self) -> None:
        host_python = self.host_python_or_warn()
        if host_python is None:
            return
        steps = [
            ("Upgrade pip", [*host_python, "-m", "pip", "install", "--upgrade", "pip"], 300),
            ("Install diagnostics dependencies", [*host_python, "-m", "pip", "install", "-r", str(ROOT / "requirements-browser-diagnostics.txt")], 600),
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
            ("Route policy tests", py_script("route_policy_tests.py"), 120),
            ("Protocol policy tests", py_script("protocol_policy_tests.py"), 120),
            ("Metadata validation", py_script("validate_metadata.py"), 120),
            ("Static preflight", py_script("preflight.py", "--config", str(CONFIG), "--no-dns", "--skip-cert", "--skip-runtime"), 120),
            ("Secret scan", py_script("secret_scan.py"), 120),
        ]
        if (not CERT.exists() or not KEY.exists()) and messagebox.askyesno(
            "Local CA files missing",
            "mycert.crt or mycert.key is missing. Generate local CA files now? This does not install trust.",
        ):
            steps.append(("Generate or rotate local CA", py_script("mitm_trust.py", "rotate", "--out-dir", str(ROOT / "Xray-config")), 120))
        self.run_sequence("Repair Local Files", steps)

    def cert_status(self) -> None:
        self.run_async("Certificate status", py_script("mitm_trust.py", "status", "--cert", str(CERT), "--key", str(KEY), "--json"))

    def cert_pair(self) -> None:
        self.run_async("Certificate pair check", py_script("mitm_trust.py", "check-pair", "--cert", str(CERT), "--key", str(KEY)))

    def trust_instructions(self) -> None:
        self.run_async("Trust instructions", py_script("trust_assistant.py", "--cert", str(CERT)))

    def generate_ca(self) -> None:
        if not messagebox.askyesno("Generate local CA", "This creates or replaces local CA files in Xray-config. Continue?"):
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
                f"Or click Install Fingerprint Tools in Fix Tools.\nProject: {CLOAKBROWSER_URL}\n"
            )
            self.current_process_label.set("CloakBrowser: not installed")

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
            subprocess.Popen(args, cwd=str(ROOT))
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
        SCRIPTS / "path_scorer_tests.py",
        SCRIPTS / "browser_common.py",
        SCRIPTS / "browser_diagnostics.py",
        SCRIPTS / "browser_stealth.py",
        SCRIPTS / "browser_smoke.py",
        SCRIPTS / "health_probe.py",
        SCRIPTS / "trust_store_check.py",
        SCRIPTS / "trust_assistant.py",
        SCRIPTS / "platform_capability_check.py",
        SCRIPTS / "provider_dossier_validate.py",
        SCRIPTS / "repository_structure_tests.py",
        SCRIPTS / "geodata_pin.py",
        SCRIPTS / "dns_lab_harness.py",
        SCRIPTS / "dns_lab_harness_tests.py",
        SCRIPTS / "fakedns_recovery_check.py",
        SCRIPTS / "install_xray.py",
        SCRIPTS / "route_intent_sync.py",
        SCRIPTS / "route_graph_verify.py",
        SCRIPTS / "route_rule_linter.py",
        SCRIPTS / "config_src_validate.py",
        SCRIPTS / "config_src_build.py",
        SCRIPTS / "config_src_merge.py",
        SCRIPTS / "config_src_merge_test.py",
        SCRIPTS / "lab_evidence_run.py",
        SCRIPTS / "transport_experiment_validate.py",
        SCRIPTS / "transport_profile_validate.py",
        SCRIPTS / "protocol_smoke.py",
        SCRIPTS / "core" / "__init__.py",
        SCRIPTS / "core" / "failure_classifier.py",
        SCRIPTS / "core" / "provider_policy.py",
        SCRIPTS / "core" / "process_supervisor.py",
        SCRIPTS / "core" / "route_rule_linter.py",
        SCRIPTS / "core" / "trust_assistant.py",
        ROOT / "configs" / "health-checks.yml",
        ROOT / "configs" / "route-intent.json",
        ROOT / "configs" / "transport-experiments.json",
        ROOT / "configs" / "transport-profiles.yml",
        ROOT / "config-src" / "manifest.json",
        ROOT / "config-src" / "fragments" / "README.md",
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
        for script_name in ("preflight.py", "check_dns.py", "route_policy_tests.py", "install_xray.py"):
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
    parser = argparse.ArgumentParser(description="Launch the MITM-DomainFronting local GUI")
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
