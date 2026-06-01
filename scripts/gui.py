#!/usr/bin/env python3
"""Local desktop GUI for MITM-DomainFronting maintenance and diagnostics."""
from __future__ import annotations

import argparse
import json
import os
import runpy
import subprocess
import sys
import threading
import traceback
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

import tkinter as tk
from tkinter import messagebox, ttk

IS_FROZEN = bool(getattr(sys, "frozen", False))
ROOT = Path(sys.executable).resolve().parent if IS_FROZEN else Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
CONFIG = ROOT / "Xray-config" / "MITM-DomainFronting.json"
CERT = ROOT / "Xray-config" / "mycert.crt"
KEY = ROOT / "Xray-config" / "mycert.key"
BROWSER_CONFIG = ROOT / "configs" / "browser-integration.json"
CLOAKBROWSER_URL = "https://github.com/CloakHQ/CloakBrowser"
XRAY_RELEASES_URL = "https://github.com/XTLS/Xray-core/releases"

COLORS = {
    "bg": "#f5f7fb",
    "panel": "#ffffff",
    "ink": "#18202f",
    "muted": "#667085",
    "line": "#d9e0ea",
    "blue": "#2563eb",
    "blue_dark": "#1d4ed8",
    "green": "#15803d",
    "amber": "#b45309",
    "red": "#b91c1c",
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


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("MITM-DomainFronting Control Center")
        self.geometry("1180x760")
        self.minsize(1040, 680)
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
        self._configure_style()
        self._build_layout()
        self.refresh_status()

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", font=("Segoe UI", 10), background=COLORS["bg"], foreground=COLORS["ink"])
        style.configure("TNotebook", background=COLORS["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", padding=(18, 9), background="#e8edf5", foreground=COLORS["ink"])
        style.map("TNotebook.Tab", background=[("selected", COLORS["panel"])], foreground=[("selected", COLORS["blue_dark"])])
        style.configure("Accent.TButton", background=COLORS["blue"], foreground="#ffffff", padding=(12, 8), borderwidth=0)
        style.map("Accent.TButton", background=[("active", COLORS["blue_dark"])])
        style.configure("Soft.TButton", background="#eef2ff", foreground=COLORS["blue_dark"], padding=(12, 8), borderwidth=0)
        style.map("Soft.TButton", background=[("active", "#dbeafe")])
        style.configure("Danger.TButton", background="#fee2e2", foreground=COLORS["red"], padding=(12, 8), borderwidth=0)
        style.map("Danger.TButton", background=[("active", "#fecaca")])
        style.configure("TEntry", fieldbackground="#ffffff", bordercolor=COLORS["line"], padding=6)
        style.configure("TLabelframe", background=COLORS["panel"], bordercolor=COLORS["line"], relief="solid")
        style.configure("TLabelframe.Label", background=COLORS["panel"], foreground=COLORS["ink"], font=("Segoe UI", 10, "bold"))

    def _build_layout(self) -> None:
        root = tk.Frame(self, bg=COLORS["bg"])
        root.pack(fill="both", expand=True)

        sidebar = tk.Frame(root, width=278, bg="#111827")
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="MITM-DomainFronting", bg="#111827", fg="#ffffff", font=("Segoe UI", 18, "bold"), anchor="w").pack(fill="x", padx=22, pady=(24, 6))
        tk.Label(sidebar, text="Local control center", bg="#111827", fg="#cbd5e1", font=("Segoe UI", 10), anchor="w").pack(fill="x", padx=22)
        tk.Label(sidebar, text=str(ROOT), bg="#111827", fg="#94a3b8", font=("Segoe UI", 8), wraplength=230, justify="left", anchor="w").pack(fill="x", padx=22, pady=(10, 22))

        self.nav_buttons: list[tuple[str, Callable[[], None]]] = [
            ("Start Here", lambda: self.tabs.select(self.start_tab)),
            ("Dashboard", lambda: self.tabs.select(self.dashboard_tab)),
            ("Validation", lambda: self.tabs.select(self.validation_tab)),
            ("Health", lambda: self.tabs.select(self.health_tab)),
            ("Fixes and Help", lambda: self.tabs.select(self.fixes_tab)),
            ("Profiles and DNS", lambda: self.tabs.select(self.profiles_tab)),
            ("Certificates", lambda: self.tabs.select(self.certs_tab)),
            ("Browser", lambda: self.tabs.select(self.browser_tab)),
            ("Documentation", lambda: self.tabs.select(self.docs_tab)),
        ]
        for text, command in self.nav_buttons:
            tk.Button(
                sidebar,
                text=text,
                command=command,
                bg="#1f2937",
                fg="#f8fafc",
                activebackground="#374151",
                activeforeground="#ffffff",
                relief="flat",
                padx=16,
                pady=10,
                anchor="w",
                font=("Segoe UI", 10, "bold"),
            ).pack(fill="x", padx=16, pady=4)

        tk.Label(sidebar, textvariable=self.current_process_label, bg="#111827", fg="#a7f3d0", font=("Segoe UI", 9), wraplength=230, justify="left").pack(side="bottom", fill="x", padx=22, pady=22)

        content = tk.Frame(root, bg=COLORS["bg"])
        content.pack(side="left", fill="both", expand=True)

        header = tk.Frame(content, bg=COLORS["bg"])
        header.pack(fill="x", padx=24, pady=(20, 10))
        tk.Label(header, text="Control Center", bg=COLORS["bg"], fg=COLORS["ink"], font=("Segoe UI", 22, "bold")).pack(side="left")
        ttk.Button(header, text="Refresh", style="Soft.TButton", command=self.refresh_status).pack(side="right")

        self.tabs = ttk.Notebook(content)
        self.tabs.pack(fill="both", expand=True, padx=24, pady=(0, 10))

        self.start_tab = self._tab()
        self.dashboard_tab = self._tab()
        self.validation_tab = self._tab()
        self.health_tab = self._tab()
        self.fixes_tab = self._tab()
        self.profiles_tab = self._tab()
        self.certs_tab = self._tab()
        self.browser_tab = self._tab()
        self.docs_tab = self._tab()
        self.tabs.add(self.start_tab, text="Start Here")
        self.tabs.add(self.dashboard_tab, text="Dashboard")
        self.tabs.add(self.validation_tab, text="Validation")
        self.tabs.add(self.health_tab, text="Health")
        self.tabs.add(self.fixes_tab, text="Fixes and Help")
        self.tabs.add(self.profiles_tab, text="Profiles and DNS")
        self.tabs.add(self.certs_tab, text="Certificates")
        self.tabs.add(self.browser_tab, text="Browser")
        self.tabs.add(self.docs_tab, text="Docs")

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
        self._append_output("Ready. All actions run locally in this repository.\n")

    def _tab(self) -> tk.Frame:
        return tk.Frame(self.tabs, bg=COLORS["panel"], padx=20, pady=18)

    def _card(self, parent: tk.Widget, title: str) -> tk.Frame:
        frame = tk.Frame(parent, bg=COLORS["panel"], highlightbackground=COLORS["line"], highlightthickness=1)
        tk.Label(frame, text=title, bg=COLORS["panel"], fg=COLORS["ink"], font=("Segoe UI", 12, "bold"), anchor="w").pack(fill="x", padx=16, pady=(14, 4))
        return frame

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
            ("1. Validate", "Confirms config, routes, metadata, and static preflight.", self.safe_auto_fix, "Run Safe Auto-Fix", "Accent.TButton"),
            ("2. Dependencies", "Adds Playwright, CloakBrowser, PyInstaller, and local Xray only when needed.", self.install_optional_dependencies, "Install Optional Dependencies", "Soft.TButton"),
            ("3. Certificate", "Creates personal local CA files; trust-store install stays manual.", self.generate_ca, "Generate Local CA", "Danger.TButton"),
            ("4. Browser Probe", "Loads a page through 127.0.0.1:10808 after Xray is running.", self.run_browser_diagnostics, "Run Diagnostics Probe", "Accent.TButton"),
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
        grid = tk.Frame(self.dashboard_tab, bg=COLORS["panel"])
        grid.pack(fill="x")
        self.status_labels: dict[str, tk.Label] = {}
        for index, title in enumerate(("Config", "Certificate", "Profiles", "Dependencies", "Browser", "Privacy")):
            card = self._card(grid, title)
            card.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 12, 0), pady=(0, 14))
            grid.columnconfigure(index, weight=1)
            label = tk.Label(card, text="Checking...", bg=COLORS["panel"], fg=COLORS["muted"], font=("Segoe UI", 10), justify="left", anchor="nw", wraplength=190)
            label.pack(fill="both", expand=True, padx=16, pady=(0, 16))
            self.status_labels[title] = label

        actions = self._card(self.dashboard_tab, "Recommended quick actions")
        actions.pack(fill="x", pady=(4, 14))
        row = tk.Frame(actions, bg=COLORS["panel"])
        row.pack(fill="x", padx=16, pady=(8, 16))
        for spec in self.validation_commands[:3]:
            ttk.Button(row, text=spec.label, style="Accent.TButton", command=lambda s=spec: self.run_spec(s)).pack(side="left", padx=(0, 10))
        ttk.Button(row, text="Safe Auto-Fix", style="Accent.TButton", command=self.safe_auto_fix).pack(side="left", padx=(0, 10))
        ttk.Button(row, text="Diagnostics Browser Probe", style="Soft.TButton", command=self.run_browser_diagnostics).pack(side="left", padx=(0, 10))

    @property
    def validation_commands(self) -> list[CommandSpec]:
        return [
            CommandSpec("Validate Config", "Static validation for primary config.", tuple(py_script("validate_config.py", str(CONFIG)))),
            CommandSpec("Static Preflight", "Local preflight without cert/runtime/DNS requirements.", tuple(py_script("preflight.py", "--config", str(CONFIG), "--no-dns", "--skip-cert", "--skip-runtime"))),
            CommandSpec("Metadata", "Provider/profile/health metadata checks.", tuple(py_script("validate_metadata.py"))),
            CommandSpec("Route Tests", "Route order, references, and policy tests.", tuple(py_script("route_policy_tests.py"))),
            CommandSpec("Protocol Tests", "Protocol metadata and docs coverage tests.", tuple(py_script("protocol_policy_tests.py"))),
            CommandSpec("Repository Structure", "Required files and gitignore hygiene checks.", tuple(py_script("repository_structure_tests.py"))),
            CommandSpec("Provider Dossiers", "Provider metadata, route-tag linkage, and rollback/evidence checks.", tuple(py_script("provider_dossier_validate.py"))),
            CommandSpec("Geodata Pin Verify", "Verifies geodata lock file when present; info-only if absent.", tuple(py_script("geodata_pin.py", "--verify"))),
            CommandSpec("Health Probe", "Redacted health report for ports/cert/trust/dns/providers.", tuple(py_script("health_probe.py", "--config", str(CONFIG), "--cert", str(CERT), "--key", str(KEY), "--providers-dir", str(ROOT / "providers")))),
            CommandSpec("Route Intent Sync", "Compare config ruleTags against configs/route-intent.json.", tuple(py_script("route_intent_sync.py", str(CONFIG)))),
            CommandSpec("Config-src Validate", "Validate config-src manifest and run build-time checks.", tuple(py_script("config_src_validate.py", "--run-steps"))),
            CommandSpec("Transport Governance", "Validate transport experiment manifest guardrails.", tuple(py_script("transport_experiment_validate.py"))),
            CommandSpec("Lab Evidence Bundle", "Run DNS/fakeDNS/captive harness scenarios locally.", tuple(py_script("lab_evidence_run.py"))),
            CommandSpec("Secret Scan", "Tracked-file private key scan.", tuple(py_script("secret_scan.py"))),
            CommandSpec("Decision Report", "Redacted local decision summary.", tuple(py_script("decision_report.py", "--config", str(CONFIG), "--profile", "balanced"))),
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
        ttk.Button(controls, text="Clear Output", style="Soft.TButton", command=lambda: self.output.delete("1.0", "end")).pack(side="left")
        ttk.Button(controls, text="Copy Output", style="Soft.TButton", command=self.copy_output).pack(side="left", padx=8)
        tk.Label(controls, text="Output is always visible in the bottom panel.", bg=COLORS["panel"], fg=COLORS["muted"]).pack(side="left", padx=8)

    def _build_health(self) -> None:
        intro = tk.Label(
            self.health_tab,
            text=(
                "Health checks are local-only and redacted. They evaluate listener state, cert/key presence, trust-store match, "
                "DNS reachability, provider freshness, geodata hashes, and optional runtime checks."
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
        ttk.Button(row, text="Open Health Policy", style="Soft.TButton", command=lambda: self.open_path(ROOT / "configs" / "health-checks.yml")).pack(side="left", padx=(0, 10))
        ttk.Button(row, text="Open Decision Engine Doc", style="Soft.TButton", command=lambda: self.open_path(ROOT / "docs" / "decision-engine.md")).pack(side="left")

        smoke = self._card(self.health_tab, "Browser smoke summary")
        smoke.pack(fill="x", pady=(0, 12))
        tk.Label(
            smoke,
            text="Optional wrapper that runs diagnostics and stealth probes against the same URL/proxy and summarizes pass/warn state.",
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
            text="Use these when diagnostics are noisy or the app feels stuck. Fixes stay local and do not install certificate trust.",
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
        ttk.Button(qrow, text="Run Safe Auto-Fix", style="Accent.TButton", command=self.safe_auto_fix).pack(side="left", padx=(0, 10))
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
        ttk.Button(row2, text="Install Diagnostics", style="Soft.TButton", command=self.install_diagnostics_dependencies).pack(side="left", padx=(0, 10))
        ttk.Button(row2, text="Install Stealth", style="Soft.TButton", command=self.install_stealth_dependencies).pack(side="left", padx=(0, 10))
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
        outer.pack(fill="x", padx=24, pady=(0, 24))
        frame = tk.Frame(outer, bg=COLORS["panel"], highlightbackground=COLORS["line"], highlightthickness=1)
        frame.pack(fill="x")
        header = tk.Frame(frame, bg=COLORS["panel"])
        header.pack(fill="x", padx=14, pady=(10, 6))
        tk.Label(header, text="Local Output", bg=COLORS["panel"], fg=COLORS["ink"], font=("Segoe UI", 11, "bold")).pack(side="left")
        ttk.Button(header, text="Clear", style="Soft.TButton", command=lambda: self.output.delete("1.0", "end")).pack(side="right")
        ttk.Button(header, text="Copy", style="Soft.TButton", command=self.copy_output).pack(side="right", padx=8)
        self.output = tk.Text(frame, height=8, bg="#0f172a", fg="#dbeafe", insertbackground="#ffffff", relief="flat", padx=12, pady=10, font=("Consolas", 10), wrap="word")
        self.output.pack(fill="x", padx=14, pady=(0, 14))

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

        dns = self._card(self.profiles_tab, "DNS diagnostics")
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
        ttk.Button(row, text="Open Xray-config Folder", style="Soft.TButton", command=lambda: self.open_path(ROOT / "Xray-config")).pack(side="left")

    def _build_browser(self) -> None:
        intro = (
            "Two-part browser model: Diagnostics verifies proxy and CA wiring with stock Chromium. "
            "Stealth uses CloakBrowser (default) for fingerprint and anti-bot evasion. "
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

        diag = self._card(self.browser_tab, "Path 1 — Diagnostics (stock Chromium)")
        diag.pack(fill="x", pady=(0, 14))
        tk.Label(
            diag,
            text="Playwright + optional system Chrome/Edge. Use after preflight passes to confirm page load through mixed-in.",
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
        ttk.Button(drow2, text="Run diagnostics probe", style="Accent.TButton", command=self.run_browser_diagnostics).pack(side="left", padx=(0, 10))
        ttk.Button(
            drow2,
            text="Install hint (Playwright)",
            style="Soft.TButton",
            command=lambda: self._append_output(
                "\nDiagnostics install:\n  pip install -r requirements-browser-diagnostics.txt\n"
                "  playwright install chromium\n"
                "  # Linux only, if dependencies are missing: playwright install-deps chromium\n"
            ),
        ).pack(side="left", padx=(0, 10))
        if os.name == "nt":
            ttk.Button(drow2, text="Launch stock Chrome (PS)", style="Soft.TButton", command=self.launch_diagnostics_chrome_ps).pack(side="left")

        stealth = self._card(self.browser_tab, "Path 2 — Stealth (CloakBrowser, default)")
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
            text="Application-layer evasion only. Xray still owns MITM, routing, and domain fronting.",
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
        ttk.Button(srow2, text="Run stealth probe", style="Accent.TButton", command=self.run_browser_stealth).pack(side="left", padx=(0, 10))
        ttk.Button(
            srow2,
            text="Install hint (CloakBrowser)",
            style="Soft.TButton",
            command=lambda: self._append_output(
                f"\nStealth install:\n  pip install -r requirements-browser-stealth.txt\n"
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
            ("Preflight and diagnostics", ROOT / "docs" / "preflight-and-diagnostics.md"),
            ("Certificate lifecycle", ROOT / "docs" / "certificate-lifecycle.md"),
            ("DNS resilience", ROOT / "docs" / "dns-resilience.md"),
            ("Platform compatibility", ROOT / "docs" / "platform-compatibility.md"),
            ("FakeDNS recovery", ROOT / "docs" / "fakedns-recovery.md"),
            ("Provider status", ROOT / "docs" / "provider-status.md"),
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

    def refresh_status(self) -> None:
        data = read_json_config()
        remarks = data.get("remarks", "unknown")
        min_version = data.get("version", {}).get("min") if isinstance(data.get("version"), dict) else "unknown"
        profiles = sorted((ROOT / "Xray-config").glob("MITM-DomainFronting.*.json"))
        self.status_labels["Config"].configure(text=f"{short_path(CONFIG)}\nremarks: {remarks}\nXray min: {min_version}", fg=COLORS["green"] if CONFIG.exists() else COLORS["red"])
        self.status_labels["Certificate"].configure(text=f"crt: {'present' if CERT.exists() else 'missing'}\nkey: {'present' if KEY.exists() else 'missing'}\nlocal only, ignored by git", fg=COLORS["green"] if CERT.exists() and KEY.exists() else COLORS["amber"])
        self.status_labels["Profiles"].configure(text=f"{len(profiles)} generated profile configs\nstrict / balanced / compatibility / debug", fg=COLORS["green"] if len(profiles) >= 4 else COLORS["amber"])
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
            text=f"proxy: {proxy}\ndiagnostics: {'ready' if diag_ok else 'missing'}\nstealth: CloakBrowser",
            fg=COLORS["green"] if diag_ok and stealth_ok else COLORS["amber"],
        )
        self.status_labels["Privacy"].configure(text="No telemetry\nNo automatic uploads\nNo silent trust install", fg=COLORS["green"])

    def run_spec(self, spec: CommandSpec) -> None:
        self.run_async(spec.label, list(spec.args))

    def run_async(self, label: str, args: list[str], timeout: int = 120, after: Callable[[int, str], None] | None = None) -> None:
        self.current_process_label.set(f"Running: {label}")
        self._append_output(f"\n$ {' '.join(args)}\n")

        def worker() -> None:
            try:
                code, output = run_command(args, timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                code, output = 124, f"Timed out after {exc.timeout} seconds"
            except Exception as exc:  # noqa: BLE001
                code, output = 1, str(exc)
            self.after(0, lambda: self._finish_command(label, code, output, after))

        threading.Thread(target=worker, daemon=True).start()

    def run_sequence(self, label: str, steps: list[tuple[str, list[str], int]]) -> None:
        self.current_process_label.set(f"Running: {label}")
        self._append_output(f"\n== {label} ==\n")

        def worker() -> None:
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
                chunks.append(f"[{'PASS' if code == 0 else 'WARN/FAIL'}] {step_label} exited with code {code}")
                if code != 0 and final_code == 0:
                    final_code = code
            text = "\n".join(chunks)
            self.after(0, lambda: self._finish_command(label, final_code, text, None))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_command(self, label: str, code: int, output: str, after: Callable[[int, str], None] | None) -> None:
        status = "PASS" if code == 0 else "WARN/FAIL"
        self._append_output(f"{output}\n[{status}] {label} exited with code {code}\n")
        self.current_process_label.set(f"{label}: {status}")
        if after:
            after(code, output)
        self.refresh_status()

    def _append_output(self, text: str) -> None:
        self.output.insert("end", text)
        self.output.see("end")

    def copy_output(self) -> None:
        text = self.output.get("1.0", "end").strip()
        self.clipboard_clear()
        self.clipboard_append(text)
        self.current_process_label.set("Output copied")

    def explain_output(self) -> None:
        self._append_output(
            "\nOutput guide:\n"
            "  PASS: the check completed successfully.\n"
            "  WARN/FAIL: read the last lines above first; they usually name the missing file, dependency, port, or route.\n"
            "  Static preflight WARN about Windows proxy: review system proxy to avoid proxy loops.\n"
            "  Missing certificate: use Generate Local CA, then install mycert.crt manually into the intended trust store.\n"
            "  Browser dependency errors: use Install Diagnostics or Install Stealth in Fixes and Help.\n"
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
        self.run_async("Lab evidence bundle", py_script("lab_evidence_run.py"), timeout=240)

    def run_decision_report(self) -> None:
        self.run_async(
            "Decision report",
            py_script("decision_report.py", "--config", str(CONFIG), "--cert", str(CERT), "--key", str(KEY), "--profile", "balanced"),
            timeout=120,
        )

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
            f"  Diagnostics: {python_hint} -m pip install -r requirements-browser-diagnostics.txt\n"
            f"  Diagnostics browser: {python_hint} -m playwright install chromium\n"
            f"  Linux deps if needed: {python_hint} -m playwright install-deps chromium\n"
            f"  Stealth: {python_hint} -m pip install -r requirements-browser-stealth.txt\n"
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
        self.run_sequence("Install Diagnostics Dependencies", steps)

    def install_stealth_dependencies(self) -> None:
        host_python = self.host_python_or_warn()
        if host_python is None:
            return
        steps = [
            ("Upgrade pip", [*host_python, "-m", "pip", "install", "--upgrade", "pip"], 300),
            ("Install CloakBrowser package", [*host_python, "-m", "pip", "install", "-r", str(ROOT / "requirements-browser-stealth.txt")], 600),
            ("Run CloakBrowser setup", [*host_python, "-m", "cloakbrowser", "install"], 900),
        ]
        self.run_sequence("Install Stealth Dependencies", steps)

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
        self.run_sequence("Safe Auto-Fix", steps)

    def cert_status(self) -> None:
        self.run_async("Certificate status", py_script("mitm_trust.py", "status", "--cert", str(CERT), "--key", str(KEY), "--json"))

    def cert_pair(self) -> None:
        self.run_async("Certificate pair check", py_script("mitm_trust.py", "check-pair", "--cert", str(CERT), "--key", str(KEY)))

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
        self.run_async("Diagnostics browser probe", args, timeout=180)

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
        self.run_async("Stealth browser probe (CloakBrowser)", args, timeout=180)

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
                f"Or click Install Stealth in Fixes and Help.\nProject: {CLOAKBROWSER_URL}\n"
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
        SCRIPTS / "browser_common.py",
        SCRIPTS / "browser_diagnostics.py",
        SCRIPTS / "browser_stealth.py",
        SCRIPTS / "browser_smoke.py",
        SCRIPTS / "health_probe.py",
        SCRIPTS / "trust_store_check.py",
        SCRIPTS / "platform_capability_check.py",
        SCRIPTS / "provider_dossier_validate.py",
        SCRIPTS / "repository_structure_tests.py",
        SCRIPTS / "geodata_pin.py",
        SCRIPTS / "dns_lab_harness.py",
        SCRIPTS / "fakedns_recovery_check.py",
        SCRIPTS / "install_xray.py",
        SCRIPTS / "route_intent_sync.py",
        SCRIPTS / "config_src_validate.py",
        SCRIPTS / "lab_evidence_run.py",
        SCRIPTS / "transport_experiment_validate.py",
        ROOT / "config-src" / "manifest.json",
        ROOT / "docs" / "lab-evidence-checklist.md",
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
