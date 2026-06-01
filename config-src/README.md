# config-src (phase 1)

This directory introduces a **build-time config boundary** without changing the current user import workflow.

## Current behavior

- Users and v2rayN still import `Xray-config/MITM-DomainFronting.json` directly.
- `config-src/manifest.json` declares the primary source file and future fragment list.
- `scripts/config_src_validate.py` checks manifest integrity and required validation steps.
- `scripts/config_src_build.py` validates the primary config and writes a compiled copy to `build/config/MITM-DomainFronting.json` (gitignored).

## Phase 2 (future)

When fragments are added under `config-src/fragments/`, the build script will merge them into the compiled output. Until then, the compiled artifact is a validated copy of the primary source.

## Commands

```bash
python scripts/config_src_validate.py
python scripts/config_src_build.py
```
