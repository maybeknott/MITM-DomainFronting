# config-src

This directory is the build-time source boundary for the repository config. It does
not change the current user import workflow.

## Current Behavior

- Users and v2rayN still import `Xray-config/MITM-DomainFronting.json` directly.
- `config-src/base.json` is the source JSON that must rebuild the runtime import target exactly.
- `routes.yml`, `dns.yml`, `profiles.yml`, `providers.yml`, and `static-cidrs.yml` hold source metadata used by maintainers and validators.
- `config-src/manifest.json` declares the source files, runtime target, compiled output, and optional fragment list.
- `scripts/config_src_validate.py` checks manifest integrity and required validation steps.
- `scripts/build_config.py --check-runtime-sync --generate-profiles --check-profile-sync` validates, merges fragments when listed, writes `build/config/MITM-DomainFronting.json` plus generated profiles (gitignored), and fails if the compiled results differ from `Xray-config/MITM-DomainFronting*.json`.

## Fragment Merge

When fragments are listed in `manifest.json` -> `fragments`, `scripts/config_src_merge.py` deep-merges each overlay JSON object onto the primary config:

- **Objects**: recursive merge
- **Arrays**: concatenated, for example additional `routing.rules`
- **Scalars**: overlay replaces base

See `config-src/fragments/README.md` for authoring guidance. With an empty `fragments` array, the compiled artifact remains a validated copy of `config-src/base.json`.

## Commands

```bash
python scripts/config_src_validate.py --run-steps
python scripts/build_config.py --check-runtime-sync --generate-profiles --check-profile-sync
python scripts/config_src_merge_test.py
```
