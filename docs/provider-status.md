# Provider Status and Drift Register

Provider and CDN behavior can change without repository changes. Keep this register current when routes, geosite data, DNS behavior, or support claims change.

| Provider / group | Config reference | Status | Drift risk | Evidence required before support claims |
|---|---|---|---|---|
| Google / YouTube | `geosite:google`, `domain:googlevideo.com` | experimental | ALPN, QUIC, regional routing | Browser TCP/443, media playback, DNS fallback |
| Fastly / Reddit / CNN / BuzzFeed | `geosite:fastly`, `geoip:fastly`, related domains | experimental | CDN policy and IP range drift | Domain route and IP route validation |
| Meta / WhatsApp / Instagram | `geosite:meta` | experimental | app trust, QUIC, regional routing | Browser test and Android trust notes |
| DNS resolvers | `no-filter-dns-cloudflare`, `no-filter-dns-google` | supported/test-required | resolver blocking or timeout | Primary timeout and fallback test |

## Drift Triage

When a provider stops working, do not start by adding domains blindly. First collect:

- route tag that should have matched;
- client and Xray version;
- platform and browser/app;
- whether failure is DNS, certificate, connection, HTTP status, media-only, or app-only;
- whether TCP/443 works with QUIC disabled;
- whether the same target works on another network;
- whether `geosite.dat` and `geoip.dat` changed since the last known-good release.

## Evidence Levels

| Level | Meaning | Required evidence |
|---|---|---|
| `documented` | Behavior is described, not necessarily supported | Docs mention limitation and expected failure mode |
| `experimental` | Route exists and may work for some users | At least one successful manual test and known limitations |
| `supported/test-required` | Intended support, but release must verify | Validation report plus platform-specific test notes |
| `unsupported` | Do not troubleshoot as a bug | Known limitation or app/provider policy prevents support |

## Update Rules

- If a provider route changes, update `docs/routing-correctness.md`.
- If support claims change, update `SUPPORT_MATRIX.md`.
- If failure is user-visible, update `KNOWN_ISSUES.md`.
- If provider metadata changes, update the matching file in `providers/`.
- Every route listed in `providers/*.yml` must match a real `ruleTag` in the primary config.
- If domains or IP ranges are added, record the reason and rollback path.
- If behavior depends on geosite/geoip data, record the data source and hash in release evidence.
- Provider dossiers must include `supported_profiles`, `tested_with` (`os`, `client`, `xray_min`), `failure_policy`, `rollback`, and `evidence_required`.
- Validate dossier files before release:

```bash
python scripts/provider_dossier_validate.py
```

## New Provider Entry

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
