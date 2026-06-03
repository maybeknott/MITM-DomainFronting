# Release Engineering

## Purpose

Define the minimum release process, required artifacts, validation commands, and
checklist fields so maintainers can ship reproducible releases with documented evidence.

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
8. Update `docs/reference/03-issues-risks-validation.md` §1 if user-visible issues changed.
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
docs/reference/03-issues-risks-validation.md
CHANGELOG.md
```

## Validation command sequence

For a standard local validation gate before release evidence, run:

```bash
python main.py release-check
```

On Windows, use `py -3 main.py release-check` if `python` is not on `PATH`.

Use the expanded sequence below when preparing release evidence or when a specific check needs its own output:

```bash
python scripts/validate_config.py Xray-config/MITM-DomainFronting.json
python scripts/preflight.py --config Xray-config/MITM-DomainFronting.json --no-dns --skip-cert --skip-runtime
python scripts/geodata_pin.py --verify
python scripts/route_intent_sync.py Xray-config/MITM-DomainFronting.json
python scripts/config_src_validate.py --run-steps
python scripts/build_config.py --check-runtime-sync --generate-profiles --check-profile-sync
python tests/python/health_policy_tests.py
python scripts/lab_evidence_run.py --json-out lab-evidence.bundle.json
python scripts/lab_evidence_validate.py lab-evidence.bundle.json
python main.py release-check
python scripts/build_release_manifest.py --root . --out validation-report.json --checksums checksums.txt --skip-xray-test
```

For a packaged Windows ZIP, verify artifact shape before publishing:

```bash
python scripts/verify_release_artifact.py dist/MITM-DomainFronting-Control-Center-vX.Y.Z-windows-x64.zip --checksum dist/MITM-DomainFronting-Control-Center-vX.Y.Z-windows-x64.zip.sha256
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

If Xray is available, generate disposable runtime-local CA material first. Xray resolves the
relative `mycert.crt` and `mycert.key` paths from the runtime resource directory in this
validation layout, so the test must not depend on user-private certificate files.

```bash
python scripts/install_xray.py --out-dir xray --force
xray/xray tls cert -ca -file=xray/mycert
xray/xray run -test -config Xray-config/MITM-DomainFronting.json
python scripts/build_release_manifest.py --root . --out validation-report.json --checksums checksums.txt --xray-bin xray/xray
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
- [ ] Issue registry in `docs/reference/03-issues-risks-validation.md` updated if needed.
- [ ] Checksums generated.
- [ ] Validation report attached.
- [ ] Lab evidence bundle attached when DNS/captive/NAT64 behavior changed.
- [ ] Route intent sync and config-src validation recorded in validation report.
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
