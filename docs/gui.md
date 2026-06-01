# Local GUI

`scripts/gui.py` is the local desktop control center for setup, repair, and support-safe diagnostics. It uses only the Python standard library. It does not upload diagnostics, keys, logs, cookies, request bodies, browser traffic, or generated reports.

## Start

```bash
python scripts/gui.py
```

On Windows, if `python` opens the Microsoft Store or is not available:

```powershell
py -3 scripts\gui.py
```

## Recommended Flow

The GUI opens on **Start Here**. Follow the visible steps in order:

1. **Check Setup** - runs the small local validation set.
2. **Generate Local CA** - creates personal `mycert.crt` and `mycert.key` files only after confirmation.
3. **Start Proxy** - starts the GUI-managed local Xray process when a local runtime is present.
4. **Run Page Check** - loads a target page through `127.0.0.1:10808`.

Advanced setup tools are hidden by default. Open them only when a check asks for missing browser tools, a local Xray runtime, fingerprint tooling, or packaging dependencies.

## Main Screens

- **Start Here**: the guided first-run checklist, optional setup installers, and plain-language troubleshooting help.
- **Run & Test**: proxy start/stop, page check, setup repair, local issue summary, activity history, and detailed status.
- **Health Report**: redacted local health probe first, plus platform and trust-store checks, with lab evidence and decision reports hidden under advanced support reports.
- **Repair**: safe repair sequence first, with optional installers and profile regeneration hidden under advanced repair tools.
- **Certificates**: certificate status, cert/key matching, local CA generation, trust-store check, and manual trust instructions.
- **Browser Check**: page check first; custom browser path, headless mode, and CloakBrowser fingerprint checks are advanced.
- **Advanced Checks**: recommended local checks first, with deeper project checks hidden until expanded.
- **Profiles & DNS**: standard profile regeneration and DNS sweep; alternate-port generation is advanced.
- **Docs**: quick links to local repository guides.

## Safety Boundaries

- The GUI runs locally from the repository checkout.
- It does not silently install a root CA.
- It does not upload diagnostics or reports.
- It does not send activity history to remote services.
- It does not inspect browser payloads.
- It does not commit generated files.
- It does not stop Xray/v2rayN processes that were started outside the GUI.
- Auto-repair and dependency buttons do not install certificate trust, change system proxy settings, or delete browser profiles.
- Xray download writes local runtime files under `xray/`, which is ignored by git.

## Local Logs And Activity

The bottom pane separates local output into **System**, **Proxy**, and **Checks** streams. The activity history records only GUI events, command labels, result codes, durations, and file-presence status under `.local-state/`.

Use **Copy Issue Summary** or **Copy Phase Summary** when sharing support information. Review exported files before sharing; they are designed to omit private keys, cookies, full URLs, request bodies, and decrypted payloads.

## Self-Test

```bash
python scripts/gui.py --self-test
```

Windows launcher fallback:

```powershell
py -3 scripts\gui.py --self-test
```

This checks that expected local scripts and the primary config are present without opening a window.

## Build The Windows EXE

Double-click:

```text
build_gui_exe.bat
```

Or run:

```powershell
py -3 scripts\build_gui_exe.py
```

The builder installs PyInstaller if it is missing, compiles the GUI, and copies local backend scripts, configs, docs, providers, and runtime JSON files into:

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
