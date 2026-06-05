# Source And Generated Files

## Purpose

Define which files are edited by hand, which runtime outputs are committed for users, and which artifacts stay local-only. Use this boundary when reviewing diffs and release ZIP contents.

This project has one clear source/generated boundary.

## Source Of Truth

These files are edited by maintainers:

```text
config-src/base.json
config-src/*.yml
config-src/manifest.json
configs/*.yml
configs/*.json
providers/*.yml
scripts/
scripts/core/
tests/python/
docs/
  reference/          # engineering handbook (edit Markdown directly — no generator scripts)
    00-engineering-handbook.md
    01-architecture-runtime-delivery.md
    02-decisions-evasion-engineering.md
    03-issues-risks-validation.md
src/
```

## Committed Runtime Outputs

These are generated outputs that are committed because users and release bundles consume them directly:

```text
Xray-config/Xray-Cooperative-Overlay.json
Xray-config/Xray-Cooperative-Overlay.strict.json
Xray-config/Xray-Cooperative-Overlay.balanced.json
Xray-config/Xray-Cooperative-Overlay.compatibility.json
Xray-config/Xray-Cooperative-Overlay.debug.json
Xray-config/Xray-Cooperative-Overlay.evasion-fragment.json
Xray-config/Xray-Cooperative-Overlay.evasion-reality-stub.json
Xray-config/Xray-Cooperative-Overlay.evasion-tun-stub.json
Xray-config/Xray-Cooperative-Overlay.evasion-fakedns.json
Xray-config/Xray-Cooperative-Overlay.evasion-high-stealth.json
```

Regenerate operating profiles and evasion lab configs with:

```powershell
py -3 scripts\build_config.py --check-runtime-sync --generate-profiles --check-profile-sync
py -3 scripts\generate_evasion_profiles.py
py -3 main.py lab-prepare --allow-warn
```

Evasion lab JSON is listed in `config-src/manifest.json` under `generated_evasion_lab_profiles`. Use only in controlled lab environments.

## Local-Only Generated Artifacts

These are not product source and should not be committed:

```text
build/
dist/
target/
browser-profiles/
.local-state/
xray/
Xray-config/mycert.crt
Xray-config/mycert.key
validation-report.json
checksums.txt
lab-evidence.bundle.json
build/pyinstaller-runs/
*.spec.bak
```

### Build artifact hygiene (T-03)

PyInstaller and local packaging write under `build/` and `dist/`. These trees are **POLICY: MUST NOT** be committed.

| Path | Producer | Committed? |
|---|---|---|
| `build/config/` | `scripts/build_config.py` | No — compile staging |
| `build/pyinstaller-runs/` | `scripts/build_gui_exe.py` | No — per-run workdirs |
| `dist/*.exe`, `dist/*.zip` | PyInstaller / release scripts | No — attach to GitHub Releases only |
| `target/` | `cargo build` | No — Rust validation crate |

**Before sharing a diff or ZIP**, confirm no local artifacts leaked in:

```powershell
git status --ignored
git check-ignore -v build dist target .local-state 2>$null
```

**Clean local packaging outputs** (safe — regenerates on next build):

```powershell
Remove-Item -Recurse -Force build, dist, target -ErrorAction SilentlyContinue
py -3 scripts\build_gui_exe.py --help   # rebuild GUI when needed
```

GUI builds: `scripts/build_gui_exe.py` stages each run under `build/pyinstaller-runs/<timestamp>/` so failed PyInstaller attempts do not overwrite prior artifacts.

## Release Bundle Rule

Release ZIPs may include runtime files such as `xray/xray.exe`, `xray/geoip.dat`, and `xray/geosite.dat`, but must not include local certificates, private keys, Git history, or historical patch files.

Verify a ZIP with:

```powershell
py -3 scripts\verify_release_artifact.py dist\Xray-Cooperative-Overlay-Control-Center-vX.Y.Z-windows-x64.zip --checksum dist\Xray-Cooperative-Overlay-Control-Center-vX.Y.Z-windows-x64.zip.sha256
```

## Related documents

| Document | Topic |
|---|---|
| [`repository-structure.md`](../repository-structure.md) | Full repository tree |
| [`release-engineering.md`](../release-engineering.md) | Release build workflow |
| [`config-src/README.md`](../../config-src/README.md) | Config source boundary |
| [`.gitignore`](../../.gitignore) | Ignored local artifacts |
