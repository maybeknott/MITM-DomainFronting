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

- Shows the primary config, local certificate presence, generated profile status, and privacy boundaries.
- Runs config validation, static preflight, metadata checks, route policy tests, protocol policy tests, secret scan, and decision report.
- Regenerates standard operating profiles.
- Generates optional alternate-port profile files for local port conflicts.
- Runs DNS query-type sweeps for `A`, `AAAA`, `HTTPS`, and `SVCB`.
- Shows certificate status and certificate/key pair checks.
- Opens local documentation.

## Safety Boundaries

- The GUI runs locally from the repository checkout.
- It does not silently install a root CA.
- It does not upload diagnostics or reports.
- It does not inspect browser payloads.
- It does not commit generated files.
- Local CA files and alternate-port outputs remain subject to `.gitignore` and normal review.

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
