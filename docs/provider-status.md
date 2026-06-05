# Provider status and drift register

## Purpose

CDN and resolver behavior changes without a repository commit. This register records
**support level**, **drift risk**, and **evidence required** before claiming a provider
path works in release notes or support channels.

**When to update:** route tag changes, `geosite.dat` / `geoip.dat` updates, DNS profile
changes, or new failure reports from the field.

---

## Current providers

| Provider / group | Config reference | Status | Drift risk | Evidence before support claims |
|---|---|---|---|---|
| Google / YouTube | `geosite:google`, `domain:googlevideo.com` | experimental | ALPN, QUIC, regional routing | Browser TCP/443, media playback, DNS fallback |
| Fastly / Reddit / CNN / BuzzFeed | `geosite:fastly`, `geoip:fastly`, related domains | experimental | CDN policy and IP range drift | Domain route and IP route validation |
| Meta / WhatsApp / Instagram | `geosite:meta` | experimental | App trust, QUIC, regional routing | Browser test and Android trust notes |
| DNS resolvers | `no-filter-dns-cloudflare`, `no-filter-dns-google` | supported/test-required | Resolver blocking or timeout | Primary timeout and fallback test |

**Wire reminder:** the logical destination travels in HTTP routing inside Xray after
local MITM. The outer TLS Server Name Indication (SNI) is the **front domain** from
`providers/*.yml` — validated by `scripts/core/sni_camouflage.py`, not Rust
`tls_orchestrator.rs`.

---

## Drift triage procedure

When a provider stops working, **do not** add domains blindly. Collect:

| Step | Action |
|---|---|
| 1 | Route tag that should have matched — check `providers/*.yml` → `ruleTag` |
| 2 | Outbound `tls-repack-*` tag and camouflage `serverName`: `py -3 scripts/core/sni_camouflage.py Xray-config/Xray-Cooperative-Overlay.json` |
| 3 | Client and Xray version; platform and browser/app |
| 4 | Failure class: DNS, certificate, connection, HTTP status, media-only, or app-only |
| 5 | TCP/443 with QUIC disabled vs enabled |
| 6 | Same target on another network (ISP/region control) |
| 7 | Whether `geosite.dat` and `geoip.dat` changed since last known-good release |
| 8 | PCAP (optional): `tshark -r capture.pcap -Y "tls.handshake.extensions_server_name"` — SNI on wire vs logical Host |

If the issue is user-visible and reproducible, add a row to
[reference/03-issues-risks-validation.md](reference/03-issues-risks-validation.md) §1
(PROV-* category).

---

## Evidence levels

| Level | Meaning | Required evidence |
|---|---|---|
| `documented` | Described limitation, not necessarily supported | Docs state expected failure mode |
| `experimental` | Route exists; may work for some users | At least one successful manual test + known limits |
| `supported/test-required` | Intended support; release must verify | Validation report + platform test notes |
| `unsupported` | Do not troubleshoot as product bug | Known app/provider policy blocks support |

---

## Maintainer update rules

| Change type | Update |
|---|---|
| Provider route logic | [routing-correctness.md](routing-correctness.md) |
| Support matrix claims | `SUPPORT_MATRIX.md` (repository root) |
| User-visible failure | [reference/03-issues-risks-validation.md](reference/03-issues-risks-validation.md) §1 |
| Provider metadata | Matching file under `providers/` |
| Geosite/geoip dependency | Release evidence hash in [release-evidence.md](release-evidence.md) |

**Invariants:**

- Every route in `providers/*.yml` must match a real `ruleTag` in the primary config.
- New domains or IP ranges need a documented reason and rollback path.
- Provider dossiers must include `supported_profiles`, `tested_with`, `failure_policy`,
  `rollback`, and `evidence_required`.

**Validate dossiers before release:**

```bash
python scripts/provider_dossier_validate.py
```

---

## New provider entry template

```yaml
provider_id: example
routes_added: []
domains_added: []
ips_added: []
tested_on:
  os: []
  client: []
  xray_version: ""
protocols:
  tcp_443: untested
  udp_443: untested
  dns: untested
known_failure_modes: []
rollback: "remove added routes"
```

---

## Related documents

| Topic | Document |
|---|---|
| Routing invariants | [routing-correctness.md](routing-correctness.md) |
| SNI camouflage format | [sni-camouflage.md](sni-camouflage.md) |
| Protocol limits (QUIC, WebRTC) | [protocol-coverage.md](protocol-coverage.md) |
