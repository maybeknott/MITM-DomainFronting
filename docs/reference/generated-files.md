# Source And Generated Files

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
src/
```

## Committed Runtime Outputs

These are generated outputs that are committed because users and release bundles consume them directly:

```text
Xray-config/MITM-DomainFronting.json
Xray-config/MITM-DomainFronting.strict.json
Xray-config/MITM-DomainFronting.balanced.json
Xray-config/MITM-DomainFronting.compatibility.json
Xray-config/MITM-DomainFronting.debug.json
```

Regenerate and verify them with:

```powershell
py -3 scripts\build_config.py --check-runtime-sync --generate-profiles --check-profile-sync
```

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
```

## Release Bundle Rule

Release ZIPs may include runtime files such as `xray/xray.exe`, `xray/geoip.dat`, and `xray/geosite.dat`, but must not include local certificates, private keys, Git history, or historical patch files.

Verify a ZIP with:

```powershell
py -3 scripts\verify_release_artifact.py dist\MITM-DomainFronting-Control-Center-vX.Y.Z-windows-x64.zip --checksum dist\MITM-DomainFronting-Control-Center-vX.Y.Z-windows-x64.zip.sha256
```
