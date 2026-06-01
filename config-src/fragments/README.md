# config-src fragments

Each file here is an overlay Xray JSON object merged onto the primary config during `scripts/build_config.py`.

## Merge rules

- **Objects** — deep merge; overlay keys win at leaves.
- **Arrays** — concatenated (`base + overlay`), e.g. extra `routing.rules` or `outbounds`.
- **Scalars** — overlay replaces base.

## Example

`example-overlay.json` (reference only; not listed in `manifest.json` until needed):

```json
{
  "remarks": "MITM-DomainFronting_build_overlay",
  "routing": {
    "rules": [
      {
        "type": "field",
        "ruleTag": "r900_direct_global_catchall",
        "network": "tcp,udp",
        "outboundTag": "direct"
      }
    ]
  }
}
```

Add fragment paths to `config-src/manifest.json` → `fragments` in merge order, then run:

```bash
python scripts/config_src_validate.py --run-steps
python scripts/build_config.py --check-runtime-sync --generate-profiles --check-profile-sync
```

The compiled output is written to `build/config/MITM-DomainFronting.json` (gitignored). Users still import `Xray-config/MITM-DomainFronting.json`; CI verifies that source output and tracked runtime output stay synchronized.
