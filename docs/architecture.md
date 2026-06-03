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
        +--> redirect-out-google-h11 --> 127.0.0.1:11666 --> tls-decrypt-google-h11 --> tls-repack-google
        |
        +--> redirect-out-google-h2  --> 127.0.0.1:11777 --> tls-decrypt-google-h2  --> tls-repack-google
        |
        +--> redirect-out-fastly-h2  --> 127.0.0.1:11888 --> tls-decrypt-fastly-h2  --> tls-repack-fastly
        |
        +--> redirect-out-meta-h2    --> 127.0.0.1:11999 --> tls-decrypt-meta-h2    --> tls-repack-meta
```

## Components

| Component | Purpose | Risk if broken | Validation |
|---|---|---|---|
| `mixed-in` | Main local proxy/TUN ingress | Client cannot enter config | Required inbound/port check |
| `tls-decrypt-google-h11` | Local HTTP/1.1 TLS handling path for googlevideo | h11-targeted media flows fail | Port/listener/cert check |
| `tls-decrypt-google-h2` | Isolated Google-family HTTP/2 + HTTP/1.1 TLS handling path | Google-family h2 flows fail | Port/listener/cert check |
| `tls-decrypt-fastly-h2` | Isolated Fastly-family HTTP/2 + HTTP/1.1 TLS handling path | Fastly-family h2 flows fail | Port/listener/cert check |
| `tls-decrypt-meta-h2` | Isolated Meta-family HTTP/2 + HTTP/1.1 TLS handling path | Meta-family h2 flows fail | Port/listener/cert check |
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

## Rust core (`src/`): validation library, not a data plane

The `src/*.rs` tree is named like a proxy engine (ingress traits, a
`handle_client` loop, a TLS orchestrator, a scheduler), but it is **not** on the
live traffic path. It parses ClientHellos, models ALPN/JA3/routing policy, and
runs a self-audit/regression harness. It does not forward bytes to the internet
and does not hand traffic to Xray over SOCKS5.

```text
Xray  = data plane (proxy, routing, MITM, domain-fronting, uTLS, REALITY,
        fragmentation) — where evasion executes — see ADR-0001
Rust  = parse / classify / model / score / self-audit around Xray's config and
        behavior (no upstream dialing, no raw-packet manipulation, no eBPF on egress)
```

Integration between the two is **config + evidence**, never an in-band byte
handoff. See `docs/adr/0007-rust-core-is-validation-not-data-plane.md` for the
full boundary, and `docs/adr/0008-no-raw-packet-injection-data-plane.md` for why
the specific TCP-sequence-injection / SNI-spoofing / eBPF-XDP / inline-SOCKS5
"Rust as egress engine" blueprint is rejected. Process lifetime (running the Rust
self-audit alongside Xray) is handled by `scripts/core/process_supervisor.py`,
which already provides atomic kill-on-close containment without changing the byte
path.

## Anti-censorship strategy layer

Defeating censorship is a first-class goal (ADR-0009), pursued **without** turning
the Rust crate into a packet engine. Evasion strength lives in the Xray data plane
(REALITY, uTLS, TLS record fragmentation, padding/mux, domain fronting, FakeDNS);
the repo's job is to make that data plane *adaptive and self-healing*:

```text
probe user's own path  ->  classify blocking method  ->  score candidate
(path_scorer.py)           (failure_classifier.py)       strategies
        |                                                     |
        +------------------> select + apply Xray config <-----+
                             (strategy engine, roadmap)  -> auto-failover + evidence
```

The Rust core may model and regression-test the selection logic; Python probes and
orchestrates; Xray executes the chosen strategy. See ADR-0009 and the
anti-censorship capability roadmap in `ROADMAP.md` (Tracks A/B/C).

## Diagnostic and governance layer

Local validation sits beside the runtime graph. Nothing in this layer uploads telemetry or changes runtime config automatically. The GUI may write local-only operational telemetry under `.local-state/` for status history, command durations, and redacted troubleshooting evidence.

```text
Xray-config/MITM-DomainFronting.json
  -> validate_config / preflight / route_intent_sync
  -> config-src source build (base.json + metadata + optional fragment merge)
  -> health_probe / decision_report (read-only policy_recommendation)
  -> dns_lab_harness / lab_evidence_run (redacted lab scenarios)
  -> transport_experiment_validate (extension governance guardrails)
```

| Layer | Scripts | Docs |
|---|---|---|
| Preflight | `preflight.py`, `validate_config.py` | `preflight-and-diagnostics.md` |
| Route intent | `route_intent_sync.py` | `routing-correctness.md`, `configs/route-intent.json` |
| Config build boundary | `config_src_validate.py`, `build_config.py`, `config_src_build.py` | `config-src/README.md` |
| Health / decisions | `health_probe.py`, `decision_report.py` | `decision-engine.md`, `configs/health-checks.yml` |
| DNS lab evidence | `dns_lab_harness.py`, `lab_evidence_run.py` | `dns-resilience.md`, `lab-evidence-checklist.md` |
| Transport governance | `transport_experiment_validate.py` | `transport-extension-governance.md` |
| Release evidence | `build_release_manifest.py`, `geodata_pin.py` | `release-engineering.md`, `release-evidence.md` |
