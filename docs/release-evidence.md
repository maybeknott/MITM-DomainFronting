# Release Evidence Checklist

## Purpose

List the commands, fields, and pass criteria that must accompany each release so
maintainers can prove the shipped config was validated without exposing secrets.

Every release should include evidence that the single shipped config was checked.

## Required Commands

For a quick validation gate before collecting artifacts:

```sh
python main.py release-check
```

On Windows, use `py -3 main.py release-check` if `python` is not on `PATH`.

For release evidence, collect the individual command output:

```sh
python scripts/validate_config.py Xray-config/MITM-DomainFronting.json
python scripts/preflight.py --config Xray-config/MITM-DomainFronting.json --no-dns --skip-cert --skip-runtime
python tests/python/repository_structure_tests.py
python scripts/provider_dossier_validate.py
python scripts/route_intent_sync.py Xray-config/MITM-DomainFronting.json
python scripts/config_src_validate.py --run-steps
python scripts/transport_experiment_validate.py
python scripts/geodata_pin.py --verify
python scripts/lab_evidence_run.py --json-out lab-evidence.bundle.json
python main.py release-check
python scripts/build_release_manifest.py --root . --out validation-report.json --checksums checksums.txt --skip-xray-test
```

For GUI release assets, also attach the ZIP verifier result:

```sh
python scripts/verify_release_artifact.py dist/MITM-DomainFronting-Control-Center-vX.Y.Z-windows-x64.zip --checksum dist/MITM-DomainFronting-Control-Center-vX.Y.Z-windows-x64.zip.sha256 --json
```

## Related documents

| Topic | Document |
|---|---|
| Lab scenarios | [lab-evidence-checklist.md](lab-evidence-checklist.md) |
| Final verdict | [final-verdict-template.md](final-verdict-template.md) |
| Release process | [release-engineering.md](release-engineering.md) |
| Issue registry | [reference/03-issues-risks-validation.md](reference/03-issues-risks-validation.md) |

For local release verification with generated CA files:

```sh
python scripts/preflight.py --config Xray-config/MITM-DomainFronting.json --cert Xray-config/mycert.crt --key Xray-config/mycert.key --no-dns
```

If Xray is available:

```sh
python scripts/preflight.py --config Xray-config/MITM-DomainFronting.json --xray-bin xray --no-dns
python scripts/build_release_manifest.py --root . --out validation-report.json --checksums checksums.txt --xray-bin xray
```

## Evidence Fields

- Git commit and branch.
- Dirty working tree state.
- Config SHA-256.
- Xray version and `xray run -test` result when available.
- Geosite/geoip hashes if available from the runtime package.
- Windows and Android client versions tested.
- DNS fallback result.
- FakeDNS recovery result.
- Metadata validation result.
- Route policy test result.
- Secret scan result.
- Known provider failures.
- Final verdict.

## Evidence That Must Not Be Included

- `mycert.key`
- private browsing URLs
- cookies or authorization headers
- request or response bodies
- screenshots with accounts, tokens, chats, or QR codes
- raw decrypted logs
- generated local CA files

## Minimum Pass Criteria

For a normal release:

- `validate_config.py` exits successfully.
- Static preflight with `--skip-cert --skip-runtime` exits successfully.
- `build_release_manifest.py` exits successfully.
- Private-key scan in CI passes.
- Metadata validation and route policy tests pass.
- Route intent sync and config-src validation pass.
- Transport experiment manifest validation passes.
- Issue registry and support matrix reviewed ([03-issues-risks-validation.md](reference/03-issues-risks-validation.md), [SUPPORT_MATRIX.md](../SUPPORT_MATRIX.md)).
- Final verdict is written.

For a stronger release:

- `xray run -test` is recorded as pass.
- Local CA preflight is recorded on at least one maintainer machine.
- Windows browser path is tested.
- Android browser path is tested if Android support is claimed.
- DNS fallback is tested by temporarily making the primary resolver unavailable in a lab.
- FakeDNS recovery is tested after stopping the client.
- Lab evidence bundle (`lab-evidence.bundle.json`) is collected on at least one target platform when DNS/captive claims change.

## Interpreting Dirty Tree State

The manifest records whether the repository was dirty when evidence was generated. Draft evidence may be dirty during review, but release evidence should be generated from a clean commit so checksums and source state are reproducible.

## Final Verdict

Use [final-verdict-template.md](final-verdict-template.md). A release can ship with documented limitations; they must be explicit in the issue registry.
