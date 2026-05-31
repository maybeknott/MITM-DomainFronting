# Preflight and Diagnostics

## Objective

Catch common setup problems before users open issues. The preflight script is local-only and does not inspect request bodies. It checks files, ports, config structure, DNS reachability, and listener binding expectations.

## Preflight command

```bash
python scripts/preflight.py \
  --config Xray-config/MITM-DomainFronting.json \
  --cert Xray-config/mycert.crt \
  --key Xray-config/mycert.key
```

Optional Xray config test:

```bash
python scripts/preflight.py --config Xray-config/MITM-DomainFronting.json --xray-bin xray --no-dns
```

Static-only CI check without user-local CA files:

```bash
python scripts/preflight.py --config Xray-config/MITM-DomainFronting.json --no-dns --skip-cert --skip-runtime
```

Optional DNS check:

```bash
python scripts/check_dns.py --domain example.com --resolver 1.1.1.1 --resolver 8.8.8.8
```

## Checks

| Check | Why it matters | Pass condition |
|---|---|---|
| Config exists | User imported correct file | File readable |
| JSON parses | Xray can parse config | Valid JSON |
| Required inbound tags | Local graph exists | `mixed-in`, `tls-decrypt-h11`, `tls-decrypt-h211` present |
| Required ports | Expected local ports exist in config | 10808, 11666, 11777 present |
| Loopback binding | Avoid LAN exposure | Inbounds use `listen: 127.0.0.1` or equivalent |
| Cert exists | Local CA exists | `mycert.crt` found |
| Key exists | Issuing key exists | `mycert.key` found |
| Key permissions | Avoid local overexposure | Not world-readable on POSIX |
| Static CI mode | Avoid requiring user-local CA in CI | `--skip-cert` is explicit |
| Static runtime mode | Avoid depending on the CI runner's live ports | `--skip-runtime` is explicit |
| Route tags | Debug route intent | Every rule has `ruleTag` |
| Route references | No broken target tags | All outbounds/inbounds exist |
| DNS health | Resolver path likely works | Resolver returns response or times out clearly |
| Geodata presence | Route lists available | `geoip.dat` and `geosite.dat` present where expected |
| UDP/443 policy | HTTP/3/QUIC claims stay honest | Explicit rule exists or output documents limited/test-required behavior |
| Documentation coverage | Support reports can be routed | Required operational docs are present |
| Xray config test | Runtime parser accepts config | `xray run -test` passes when `--xray-bin` is provided |

## Diagnostic output

The script writes simple JSON with statuses:

```json
{
  "overall": "warn",
  "checks": [
    {"id": "config_json", "status": "pass", "detail": "valid JSON"},
    {"id": "port_10808", "status": "pass", "detail": "present in config"},
    {"id": "loopback_tls_decrypt_h11", "status": "warn", "detail": "missing explicit listen field; add listen: 127.0.0.1"}
  ]
}
```

## What diagnostics must not include

Do not include:

- `mycert.key` content;
- cookies;
- Authorization headers;
- request bodies;
- full URLs with tokens;
- screenshots showing tokens;
- private chat/session IDs;
- personal browsing history.

## Support-safe issue report

Users can paste:

- OS version;
- client version;
- Xray version;
- browser version;
- config version/remarks;
- preflight JSON after reviewing it;
- DNS check summary;
- route tag if available;
- whether the issue is browser-only or app-specific.
