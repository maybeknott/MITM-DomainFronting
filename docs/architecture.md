# Architecture

## Purpose

This document explains the current simple architecture without requiring a redesign.

## Runtime graph

```text
Browser / local app using proxy or TUN
  (diagnostics: stock Chromium; stealth default: CloakBrowser — see docs/chromium-integration.md)
        |
        v
mixed-in :10808
        |
        +--> direct/block/DNS rules
        |
        +--> redirect-out-h11  --> 127.0.0.1:11666 --> tls-decrypt-h11  --> tls-repack-* --> remote provider/service
        |
        +--> redirect-out-h211 --> 127.0.0.1:11777 --> tls-decrypt-h211 --> tls-repack-* --> remote provider/service
```

## Components

| Component | Purpose | Risk if broken | Validation |
|---|---|---|---|
| `mixed-in` | Main local proxy/TUN ingress | Client cannot enter config | Required inbound/port check |
| `tls-decrypt-h11` | Local HTTP/1.1 TLS handling path | h11-targeted flows fail | Port/listener/cert check |
| `tls-decrypt-h211` | Local HTTP/2 + HTTP/1.1 TLS handling path | h2-targeted flows fail | Port/listener/cert check |
| `mycert.crt` | Trusted local CA certificate | Browser trust errors if missing/wrong | Fingerprint verification |
| `mycert.key` | Local CA private key | Critical if exposed; broken if missing | Existence and permission check |
| DNS block | Domain resolution and FakeDNS behavior | Routing failures and stale cache | DNS resilience checks |
| Outbounds | Direct, block, DNS, redirect, repack paths | Wrong route or silent failure | Tag/reference validation |
| Routing rules | Ordered decision table | Shadowing, wrong fallback | Static validation + route tags |

## Design principle

Keep the normal user path simple:

```text
generate cert -> install cert -> import config -> run client -> use browser
```

Add maintainability around that path through docs and scripts, not through a complex runtime architecture.
