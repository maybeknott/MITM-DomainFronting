# Local GUI

`scripts/gui.py` is a local desktop control center for common maintenance and troubleshooting tasks. It uses only the Python standard library and does not upload diagnostics, keys, logs, cookies, request bodies, browser traffic, or generated reports.

## Start

```bash
python scripts/gui.py
```

On Windows, if `python` is not available:

```powershell
py scripts\gui.py
```

## What It Does

- Opens on a guided **Control Hub** for new users with:
  - grouped sidebar navigation for **Control**, **Verify**, and **Reference** instead of a long flat tab row;
  - DPI-aware sizing and a semantic color palette for setup, warning, and blocked states;
  - a top metrics strip for proxy state, observed connection activity, local data boundary, and the next recommended action;
  - screen-level and panel-level **Help** buttons that explain fields, buttons, parameters, expected outputs, and safety boundaries without cluttering the default view;
  - an inline remediation banner that turns common first-run problems into clear actions such as **Generate Local CA**, **Download Xray**, or **Start Proxy**;
  - connection status for local `127.0.0.1:10808`;
  - at-a-glance setup, proxy, certificate, browser, and local privacy status;
  - **Start Proxy** / **Stop Proxy** controls for the Xray process launched by the GUI;
  - a **Profile** selector for the base, strict, balanced, compatibility, and debug config files;
  - URL, proxy, and browser executable path fields;
  - one-click **Check Setup**, **Repair Local Files**, **Generate Local CA**, **Install Browser Tools**, and **Run Page Check** actions;
  - local-only activity history controls for status snapshots, recent events, export, and clear;
  - always-visible multi-buffer local logs with separate **System**, **Xray Core**, and **Preflight / Linters** streams.
- Shows the primary config, local certificate presence, generated profile status, and privacy boundaries.
- Locks conflicting controls and shows an indeterminate progress indicator while long-running local checks are active, so repeated clicks do not create overlapping subprocesses.
- Runs config validation, static preflight, metadata checks, route policy tests, protocol policy tests, secret scan, route intent sync, config-src validation, transport governance validation, lab evidence bundle, and decision report.
- Runs route graph verification and first-match route rule linting for decrypted-inbound isolation.
- Runs repository-structure checks, provider dossier validation, geodata lock verification (when present), and local health probe checks.
- Provides a **Fix Tools** screen with safe local repair actions.
- Provides a **Health** tab for redacted local health probes, lab evidence bundles, decision reports, and browser smoke summaries:
  - **Run Health Probe** — `health_probe.py` (ports, cert, trust store, DNS, providers, read-only `policy_recommendation`).
  - **Run Lab Evidence** — `lab_evidence_run.py` (DNS harness scenarios + fakeDNS recovery; see `docs/lab-evidence-checklist.md`).
  - **Run Decision Report** — `decision_report.py` (captive portal warning + policy recommendation + redacted routing summary).
  - **Open Health Policy** / **Open Decision Engine Doc** — local reference files.
- Regenerates standard operating profiles.
- Generates optional alternate-port profile files for local port conflicts.
- Runs a **Repair Local Files** sequence that regenerates profiles, creates alternate-port variants, validates routes/protocols/metadata, runs static preflight, and optionally generates local CA files after confirmation.
- Provides one-click installers for optional page-check tools, Playwright Chromium, CloakBrowser fingerprint tools, PyInstaller, and a local Xray runtime download.
- Runs DNS query-type sweeps for `A`, `AAAA`, `HTTPS`, and `SVCB`.
- Shows certificate status, certificate/key pair checks, and advisory trust-store command instructions without installing trust automatically.
- Records local GUI activity history under `.local-state/` only. It never uploads diagnostics or payloads.
- Runs the **two-part browser model** from the **Browser** tab:
  - **Page Check** — stock Chromium via `browser_diagnostics.py` (proxy/CA/page-load checks).
  - **Fingerprint Check** — [CloakBrowser](https://github.com/CloakHQ/CloakBrowser) via `browser_stealth.py` (browser fingerprint path).
- Runs optional combined browser smoke summary via `browser_smoke.py`.
- Shared fields: target URL and proxy (`socks5://127.0.0.1:10808` by default, from `configs/browser-integration.json`).
- Optional: launch stock Chrome on Windows through `launch_browser_mitm.ps1`, check whether `cloakbrowser` imports, open `docs/chromium-integration.md`.
- Opens local documentation.

## Safety Boundaries

- The GUI runs locally from the repository checkout.
- It does not silently install a root CA.
- It does not upload diagnostics or reports.
- It does not send activity history to remote services.
- It does not inspect browser payloads.
- It does not commit generated files.
- Local CA files and alternate-port outputs remain subject to `.gitignore` and normal review.
- Auto-fix and dependency buttons do not install certificate trust, change system proxy settings, or delete browser profiles.
- Xray download writes local runtime files under `xray/`, which is ignored by git.

## Self-Test

```bash
python scripts/gui.py --self-test
```

This checks that the expected local scripts and primary config are present without opening a window.

## Build The Windows EXE

Double-click:

```text
build_gui_exe.bat
```

Or run:

```powershell
py scripts\build_gui_exe.py
```

The builder installs PyInstaller if it is missing, compiles the GUI, and copies the local backend scripts, configs, docs, providers, and runtime JSON files into:

```text
dist\MITM-DomainFronting-Control-Center\
```

Launch:

```text
dist\MITM-DomainFronting-Control-Center\MITM-DomainFronting-Control-Center.exe
```

The generated `build/` and `dist/` folders are local packaging artifacts and must not be committed.

## Packaged Backend Checks

The Windows executable runs backend scripts through the same bundled GUI executable. The builder includes backend-only Python standard-library modules, and `--self-test` checks that packaged backend commands can start:

```powershell
dist\MITM-DomainFronting-Control-Center\MITM-DomainFronting-Control-Center.exe --self-test
```
