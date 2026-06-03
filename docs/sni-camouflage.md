# SNI Camouflage ("SNI Spoofing")

## Purpose

Distinguish legitimate camouflage SNI in Xray config from rejected raw packet injection. Document how front SNIs are set, inspected, and validated without conflating the two techniques.

## Two meanings — read this first

People use "SNI spoofing" for two unrelated techniques. Only one belongs in this repository.

| Meaning | What it is | Where it lives | Status here |
|---|---|---|---|
| **Camouflage SNI (legitimate)** | TLS ClientHello carries a **front** `serverName` that differs from the logical destination (domain fronting, REALITY camouflage). Expressed as Xray config fields. No raw sockets. | `streamSettings.tlsSettings.serverName`, `streamSettings.realitySettings.serverName` | **In scope** — already used in shipped config; validated by `scripts/core/sni_camouflage.py` |
| **ClientHello split for DPI** | Split TLS records so naive middleboxes miss SNI on first segment | Xray `fragment` settings in profiles | **Accepted** — preferred over raw TCP split in Rust |
| **Raw segment injection (rejected variant)** | Hand-built TCP/IP frames, out-of-window segments in the **Rust validation crate** as default egress | Blueprint modules (`sni_spoof.rs`, `xray_bridge.rs`, …) | **Rejected** — wrong implementation site; use Xray-native evasion instead |

Confusing the two is why packet-injection blueprints keep resurfacing. This document and the evasion engineering handbook keep the distinction explicit.

## Camouflage SNI in Xray (data plane)

When an outbound uses TLS or REALITY, the wire SNI is whatever you set in config:

```json
"streamSettings": {
  "security": "tls",
  "tlsSettings": {
    "serverName": "www.microsoft.com",
    "fingerprint": "chrome",
    "alpn": ["h2", "http/1.1"]
  }
}
```

REALITY uses the same idea on `realitySettings.serverName` (required for REALITY outbounds).

The primary import config (`Xray-config/MITM-DomainFronting.json`) already fronts repack outbounds with camouflage SNIs such as `www.microsoft.com`, `www.google.com`, and `github.githubassets.com`. That **is** anti-censorship SNI control done correctly.

## Inspection helper (strategy layer)

`scripts/core/sni_camouflage.py` is a **read-only** inspector:

- Parses Xray JSON and lists camouflage-SNI bindings per outbound.
- Flags REALITY outbounds missing `serverName` (error).
- Flags `tls-repack*` outbounds missing `serverName` (warning).
- Warns on implausible hostnames.

```bash
py -3 scripts/core/sni_camouflage.py
py -3 scripts/core/sni_camouflage.py Xray-config/MITM-DomainFronting.json --json
```

Tests: `py -3 tests/python/sni_camouflage_tests.py`

Future work: named front selection in profiles, REALITY profiles with documented keys, and strategy-engine scoring of which front works on the user's path — still config + evidence, never raw injection.

## Honesty and safety rules

- Camouflage SNI changes what the **TLS ClientHello advertises**, not what the GUI claims was measured unless a probe actually observed it.
- Supported use remains user-controlled testing on networks the user may configure (`THREAT_MODEL.md`). Do not use front SNIs to impersonate third parties on networks you do not control.
- No silent privilege elevation to install packet engines.

## Related documents

| Document | Topic |
|---|---|
| [`reference/02-decisions-evasion-engineering.md`](reference/02-decisions-evasion-engineering.md) | Accepted vs rejected evasion techniques |
| [`reference/01-architecture-runtime-delivery.md`](reference/01-architecture-runtime-delivery.md) | Xray-native evasion delivery |
| [`transport-profiles.md`](transport-profiles.md) | Transport expectations |
| [`THREAT_MODEL.md`](../THREAT_MODEL.md) | Supported use boundaries |
