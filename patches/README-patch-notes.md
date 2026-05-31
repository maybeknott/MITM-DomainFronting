# Patch Notes

`minimal-loopback-and-gitignore.patch` is intentionally small.

It only does two things:

1. Adds `.gitignore` entries for local certs, keys, logs, temp files, and geodata.
2. Adds explicit `listen: 127.0.0.1` to the three expected local inbounds.

It does not:

- add multiple config profiles;
- remove easy certificate generation;
- change service/provider route behavior;
- add relays;
- add payload logging;
- change performance-sensitive transport settings.

Apply only after reviewing against the current config:

```bash
git apply patches/minimal-loopback-and-gitignore.patch
python scripts/validate_config.py Xray-config/MITM-DomainFronting.json
```
