# Preflight and Diagnostics

## Purpose

Catch common setup problems before users open issues. The preflight script is local-only, does not inspect request bodies, and checks files, ports, config structure, DNS reachability, and listener binding expectations.

## Preflight command

```bash
python scripts/preflight.py \
  --config Xray-config/Xray-Cooperative-Overlay.json \
  --cert Xray-config/mycert.crt \
  --key Xray-config/mycert.key
```

Optional Xray config test:

```bash
python scripts/preflight.py --config Xray-config/Xray-Cooperative-Overlay.json --xray-bin xray --no-dns
```

Static-only CI check without user-local CA files:

```bash
python scripts/preflight.py --config Xray-config/Xray-Cooperative-Overlay.json --no-dns --skip-cert --skip-runtime
```

When DNS checks are enabled, preflight also runs a best-effort captive portal warning probe. Skip it with `--skip-captive-portal` or together with `--no-dns`.

Optional DNS check:

```bash
python scripts/check_dns.py --domain example.com --resolver 1.1.1.1 --resolver 8.8.8.8
```

Platform/browser capability and ECH warning probe:

```bash
python scripts/platform_capability_check.py
```

Best-effort trust-store matching:

```bash
python scripts/trust_store_check.py --cert Xray-config/mycert.crt
python scripts/trust_assistant.py --cert Xray-config/mycert.crt
```

`trust_store_check.py` reports whether the local CA appears trusted. `trust_assistant.py` prints platform-specific command blocks for users to run themselves; it does not elevate privileges or modify trust stores.

Local health summary:

```bash
python scripts/health_probe.py --config Xray-config/Xray-Cooperative-Overlay.json --cert Xray-config/mycert.crt --key Xray-config/mycert.key --providers-dir providers
```

The health probe includes a read-only `policy_recommendation` object (`auto_switch` is always false). It suggests a profile and local actions but never changes runtime config.

Intelligent advisor (profiles, evasion lab, eBPF — local only):

```bash
python main.py advise --text
python main.py probe --json   # includes an "intelligent" object
python main.py lab-prepare --allow-warn
```

See [`intelligent-automation.md`](intelligent-automation.md).

Query-type-aware DNS check:

```bash
python scripts/check_dns.py --domain example.com --resolver 1.1.1.1 --resolver 8.8.8.8 --all-types
```

Support-safe decision report:

```bash
python scripts/decision_report.py --config Xray-config/Xray-Cooperative-Overlay.json --profile balanced
```

The decision report includes captive portal warnings and the same read-only `policy_recommendation` block as the health probe. For repeatable lab scenarios, see [`lab-evidence-checklist.md`](lab-evidence-checklist.md) and `python scripts/lab_evidence_run.py`.

## Checks

| Check | Why it matters | Pass condition |
|---|---|---|
| Config exists | User imported correct file | File readable |
| JSON parses | Xray can parse config | Valid JSON |
| Required inbound tags | Local graph exists | `mixed-in` plus isolated Google/Fastly/Meta decrypt inbounds present |
| Required ports | Expected local ports exist in config | 10808, 11666, 11777, 11888, 11999 present |
| Loopback binding | Avoid LAN exposure | Inbounds use `listen: 127.0.0.1` or equivalent |
| Cert exists | Local CA exists | `mycert.crt` found |
| Key exists | Issuing key exists | `mycert.key` found |
| Key permissions | Avoid local overexposure | Not world-readable on POSIX |
| Cert/key pair | Avoid wrong-pair trust failures | `mitm_trust.py check-pair` passes |
| Cert expiry | Avoid sudden browser privacy errors | `mitm_trust.py status --json` reports enough days remaining |
| Static CI mode | Avoid requiring user-local CA in CI | `--skip-cert` is explicit |
| Static runtime mode | Avoid depending on the CI runner's live ports | `--skip-runtime` is explicit |
| Proxy environment | Avoid proxy-chain loops | Standard proxy environment variables are absent or reviewed |
| System proxy | Avoid routing into an existing OS proxy unexpectedly | OS proxy state is disabled or explicitly understood |
| VPN/TUN interfaces | Avoid capture, DNS, and route conflicts | No common VPN/TUN interface keywords are active, or conflict is reviewed |
| Route tags | Debug route intent | Every rule has `ruleTag` |
| Route references | No broken target tags | All outbounds/inbounds exist |
| DNS health | Resolver path likely works | Resolver returns response or times out clearly |
| Geodata presence | Route lists available | `geoip.dat` and `geosite.dat` present where expected |
| UDP/443 policy | HTTP/3/QUIC claims stay honest | Explicit rule exists or output documents limited/test-required behavior |
| Documentation coverage | Support reports can be routed | Required operational docs are present |
| Xray config test | Runtime parser accepts config | `xray run -test` passes when `--xray-bin` is provided |
| Decision report | Support-safe summary | Redacted JSON contains route/profile/DNS/cert/port states only |
| Platform capability report | ECH and browser behavior can change route assumptions | Browser/platform details and ECH warning are explicit |
| Trust-store check | Cert may exist locally but not be trusted where needed | `pass/missing/mismatch/unknown/not_supported` status is explicit |
| Health probe | Unified local health view before escalation | Port/cert/trust/dns/provider/geodata status is emitted in redacted JSON |

## Diagnostic output

The script writes simple JSON with statuses:

```json
{
  "overall": "warn",
  "checks": [
    {"id": "config_json", "status": "pass", "detail": "valid JSON"},
    {"id": "port_10808", "status": "pass", "detail": "present in config"},
    {"id": "loopback_tls_decrypt_google_h11", "status": "warn", "detail": "missing explicit listen field; add listen: 127.0.0.1"}
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
- proxy/VPN/TUN warnings if present;
- route tag if available;
- whether the issue is browser-only or app-specific.

## Related documents

| Document | Topic |
|---|---|
| [`decision-engine.md`](decision-engine.md) | Redacted decision report |
| [`listener-binding.md`](listener-binding.md) | Loopback port expectations |
| [`dns-resilience.md`](dns-resilience.md) | DNS edge cases and tests |
| [`lab-evidence-checklist.md`](lab-evidence-checklist.md) | Scenario-driven lab evidence |
