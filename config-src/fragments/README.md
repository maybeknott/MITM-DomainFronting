# config-src fragments

## Purpose

Optional overlay JSON objects merged onto the primary config during `scripts/build_config.py`. Use fragments for incremental route or outbound changes without editing the full base JSON by hand.

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

## Related documents

| Document | Topic |
|---|---|
| [`../README.md`](../README.md) | Config source overview |
| [`../../docs/routing-correctness.md`](../../docs/routing-correctness.md) | Route intent and validation |
| [`../../docs/reference/generated-files.md`](../../docs/reference/generated-files.md) | Build outputs |
| [`../../config-src/manifest.json`](../manifest.json) | Fragment list and merge order |
