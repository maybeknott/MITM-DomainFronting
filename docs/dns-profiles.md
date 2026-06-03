# DNS Profiles

## Purpose

Describe named DNS policy profiles and how they map to runtime resolver tags so
support and release validation can reason about fallback behavior without a separate
generator.

The primary config keeps one DNS block, but support and release validation should reason about named DNS policies. The profiles in [dns-profiles.yml](../configs/dns-profiles.yml) define expected fallback behavior without requiring a separate runtime generator.

## Profiles

| Profile | Purpose | Resolver order | Local DNS policy | Silent local fallback |
|---|---|---|---|---|
| `dns-strict` | Privacy or strict verification mode | Cloudflare, then Google, then fail | Private/regional only | No |
| `dns-balanced` | Normal reliability | Cloudflare, Google, documented local fallback | Private/regional/captive/enterprise | No |
| `dns-local-first` | Captive or enterprise troubleshooting | Local, then external | Preferred for setup/private flows | Warning required |
| `dns-debug` | Diagnostics | Report each attempt | User selected | No |

## Current Runtime Mapping

| Runtime tag | Role |
|---|---|
| `no-filter-dns-cloudflare` | Primary external resolver path |
| `no-filter-dns-google` | Secondary external resolver path |
| `tls-repack-dns-cloudflare` | Primary DNS repack outbound |
| `tls-repack-dns-google` | Secondary DNS repack outbound |
| `localhost` resolver | Private, regional, captive, or enterprise fallback |

## Validation

Minimum validation:

```bash
python scripts/validate_config.py Xray-config/MITM-DomainFronting.json
python scripts/check_dns.py --domain example.com --resolver 1.1.1.1 --resolver 8.8.8.8
```

Stronger validation:

- simulate primary resolver timeout;
- query A and AAAA separately;
- query HTTPS/SVCB for an HTTP/3-capable domain;
- test private LAN suffixes;
- test captive portal behavior by disabling the method until login completes;
- verify FakeDNS recovery after stopping the client.

## Privacy Rule

Do not silently fall back to local DNS for targeted public domains in strict or balanced support claims. If local DNS is used for captive or enterprise troubleshooting, the issue or release note must say so explicitly.

## Related documents

| Document | Topic |
|---|---|
| [`dns-resilience.md`](dns-resilience.md) | Edge cases, harness, and recovery |
| [`decision-engine.md`](decision-engine.md) | DNS fields in decision report |
| [`fakedns-recovery.md`](fakedns-recovery.md) | FakeDNS stale cache recovery |
| [`configs/dns-profiles.yml`](../configs/dns-profiles.yml) | Profile definitions (source) |
