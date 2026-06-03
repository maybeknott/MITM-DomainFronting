# SNI Camouflage ("SNI Spoofing")

## Two meanings — read this first

People use "SNI spoofing" for two unrelated techniques. Only one belongs in this
repository.

| Meaning | What it is | Where it lives | Status here |
|---|---|---|---|
| **Camouflage SNI (legitimate)** | TLS ClientHello carries a **front** `serverName` that differs from the logical destination (domain fronting, REALITY camouflage). Expressed as Xray config fields. No raw sockets. | `streamSettings.tlsSettings.serverName`, `streamSettings.realitySettings.serverName` | **In scope** — already used in shipped config; validated by `scripts/core/sni_camouflage.py` |
| **Raw segment injection (rejected)** | Hand-built TCP/IP frames, out-of-window segments, decoy SNI to desync DPI, `cap_net_raw`, eBPF/XDP, inline Rust byte bridge | Blueprint modules (`sni_spoof.rs`, `xray_bridge.rs`, …) | **Out of scope** — ADR-0008 |

Confusing the two is why packet-injection blueprints keep resurfacing. This document
and ADR-0008/0009 exist to keep the distinction explicit.

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

REALITY uses the same idea on `realitySettings.serverName` (required for REALITY
outbounds).

The primary import config (`Xray-config/MITM-DomainFronting.json`) already fronts
repack outbounds with camouflage SNIs such as `www.microsoft.com`, `www.google.com`,
and `github.githubassets.com`. That **is** anti-censorship SNI control done correctly.

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

Future work (ROADMAP Track A/B): named front selection in profiles, REALITY
profile with documented keys, and strategy-engine scoring of which front works on
the user's path — still config + evidence, never raw injection.

## Honesty and safety rules

- Camouflage SNI changes what the **TLS ClientHello advertises**, not what this GUI
  claims was measured unless a probe actually observed it (ADR-0004).
- Supported use remains user-controlled testing on networks the user may configure
  (`THREAT_MODEL.md`). Do not use front SNIs to impersonate third parties on
  networks you do not control.
- No silent privilege elevation to install packet engines (ADR-0002, ADR-0006).

## References

- ADR-0008 — rejects raw-packet "SNI spoofing" in the Rust core.
- ADR-0009 — anti-censorship mission; evasion via data plane + strategy layer.
- ADR-0004 — JA3 oracle honesty.
- `docs/transport-profiles.md`, `ROADMAP.md` (Tracks A/B/C).
