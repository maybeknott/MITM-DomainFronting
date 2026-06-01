# Release Engineering

## Objective

Make every release reproducible enough that maintainers and users can understand what changed and whether the config was validated.

## Minimal release process

No complex build pipeline is required. A release can remain simple:

1. Validate JSON.
2. Validate route references.
3. Validate local listener binding expectations.
4. Validate scripts syntax.
5. Run `xray run -test` when Xray is available.
6. Generate checksums.
7. Generate `validation-report.json`.
8. Update `KNOWN_ISSUES.md`.
9. Update `SUPPORT_MATRIX.md`.
10. Publish artifacts.

## Required release artifacts

```text
Xray-config/MITM-DomainFronting.json
Xray-config/certificate_generator.bat
Xray-config/certificate_generator.sh
checksums.txt
validation-report.json
SUPPORT_MATRIX.md
KNOWN_ISSUES.md
CHANGELOG.md
```

## Validation command sequence

```bash
python scripts/validate_config.py Xray-config/MITM-DomainFronting.json
python scripts/preflight.py --config Xray-config/MITM-DomainFronting.json --no-dns --skip-cert --skip-runtime
python scripts/geodata_pin.py --verify
python scripts/route_intent_sync.py Xray-config/MITM-DomainFronting.json
python scripts/config_src_validate.py --run-steps
python scripts/build_release_manifest.py --root . --out validation-report.json --checksums checksums.txt --skip-xray-test
```

To pin geodata for a release after downloading Xray locally:

```bash
python scripts/install_xray.py --out-dir xray --force
python scripts/geodata_pin.py --write-lock --xray-bin xray/xray --root .
# Commit release-geodata-lock.json only after maintainer review (see release-geodata-lock.example.json)
```

For a local maintainer machine with generated CA material, also run:

```bash
python scripts/preflight.py --config Xray-config/MITM-DomainFronting.json --cert Xray-config/mycert.crt --key Xray-config/mycert.key --no-dns
```

If Xray is available:

```bash
xray run -test -config Xray-config/MITM-DomainFronting.json
python scripts/build_release_manifest.py --root . --out validation-report.json --checksums checksums.txt --xray-bin xray
```

## Release checklist

- [ ] JSON is valid.
- [ ] Xray config test passed or failure reason is documented.
- [ ] Route validation passed.
- [ ] Required inbound tags exist.
- [ ] Required outbound tags exist.
- [ ] Required ports are documented.
- [ ] Listener binding reviewed.
- [ ] DNS behavior reviewed.
- [ ] FakeDNS recovery docs are current.
- [ ] CA lifecycle docs are current.
- [ ] Platform matrix updated.
- [ ] Known issues updated.
- [ ] Checksums generated.
- [ ] Validation report attached.
- [ ] Git commit, branch, and dirty-tree state recorded.
- [ ] Xray version and config-test result recorded when available.
- [ ] Final verdict written.

## `validation-report.json` fields

```json
{
  "release": "vXX",
  "date_utc": "YYYY-MM-DDTHH:MM:SSZ",
  "config": {
    "path": "Xray-config/MITM-DomainFronting.json",
    "sha256": "...",
    "remarks": "MITM-DomainFronting_vXX"
  },
  "checks": {
    "json_parse": "pass",
    "route_references": "pass",
    "rule_tags": "warn",
    "loopback_bindings": "warn",
    "xray_run_test": "pass|fail|not_run"
  },
  "repository": {
    "commit": "...",
    "branch": "main",
    "is_dirty": false
  },
  "xray": {
    "version": {"status": "pass"},
    "config_test": {"status": "pass|fail|not_run"}
  },
  "tested_with": {
    "xray": "...",
    "v2rayN": "...",
    "v2rayNG": "...",
    "geosite_sha256": "...",
    "geoip_sha256": "..."
  },
  "known_issues": []
}
```

## Final verdict per release

Use `docs/final-verdict-template.md` for every release. The verdict must state:

- what changed;
- what was tested;
- what was not tested;
- known regressions;
- rollback instruction;
- whether the release is recommended for normal users.
