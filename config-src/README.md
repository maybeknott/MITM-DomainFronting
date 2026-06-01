# config-src (phase 1 + phase 2 merge)

This directory introduces a **build-time config boundary** without changing the current user import workflow.

## Current behavior

- Users and v2rayN still import `Xray-config/MITM-DomainFronting.json` directly.
- `config-src/manifest.json` declares the primary source file and optional fragment list.
- `scripts/config_src_validate.py` checks manifest integrity and required validation steps.
- `scripts/config_src_build.py` validates, merges fragments (when listed), and writes a compiled copy to `build/config/MITM-DomainFronting.json` (gitignored).

## Fragment merge (phase 2)

When fragments are listed in `manifest.json` → `fragments`, `scripts/config_src_merge.py` deep-merges each partial JSON object onto the primary config:

- **Objects** — recursive merge
- **Arrays** — concatenated (e.g. additional `routing.rules`)
- **Scalars** — overlay replaces base

See `config-src/fragments/README.md` for authoring guidance. With an empty `fragments` array, the compiled artifact remains a validated copy of the primary source.

## Commands

```bash
python scripts/config_src_validate.py --run-steps
python scripts/config_src_build.py
python scripts/config_src_merge_test.py
```
