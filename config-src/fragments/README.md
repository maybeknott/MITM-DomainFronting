# config-src fragments

## Purpose

Optional overlay JSON objects merged onto the primary config during `scripts/build_config.py`. Use fragments for incremental route or outbound changes without editing the full base JSON by hand.

Reference-only lab fragments (`reality-outbound-stub.json`, `tls-fragment-overlay.json`, `tun-inbound-stub.json`, `fakedns-19818-trap.json`) are **not** listed in `manifest.json` until an operator explicitly opts in. Generate optional lab profiles with:

```bash
py -3 scripts/generate_evasion_profiles.py
```

## Merge rules

Control keys (see `scripts/config_src_merge.explain_merge_controls()`):

| Key | Effect |
|---|---|
| `__replace__: true` | Replace the entire subtree at this node |
| `__merge_strategy__` | Per-child list strategy map |

List strategies:

| Strategy | Behavior |
|---|---|
| `append` | Default — concatenate arrays |
| `replace` | Overlay list replaces base list |
| `append_unique` | Append items deduped by stable JSON key |
| `append_unique_by_tag` | Replace tagged dict entries by `tag` / `ruleTag` / `id` / `name`, append untagged uniquely |

Object merge: deep merge; overlay leaf keys win.

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
py -3 scripts/config_src_validate.py --run-steps
py -3 scripts/build_config.py --check-runtime-sync --generate-profiles --check-profile-sync
```

The compiled output is written to `build/config/MITM-DomainFronting.json` (gitignored). Users still import `Xray-config/MITM-DomainFronting.json`; CI verifies that source output and tracked runtime output stay synchronized.

## Related documents

| Document | Topic |
|---|---|
| [`../README.md`](../README.md) | Config source overview |
| [`../../docs/routing-correctness.md`](../../docs/routing-correctness.md) | Route intent and validation |
| [`../../docs/reference/generated-files.md`](../../docs/reference/generated-files.md) | Build outputs |
| [`../../config-src/manifest.json`](../manifest.json) | Fragment list and merge order |
