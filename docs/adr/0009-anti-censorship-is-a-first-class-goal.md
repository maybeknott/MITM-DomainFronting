# ADR 0009: Anti-Censorship Is A First-Class Goal

## Status

Accepted.

## Context

This project exists to help users operate MITM domain-fronting and related TLS
transports on **networks they control or own**, including environments where
censorship or middleboxes degrade or block those paths. That mission must be
visible in architecture and roadmap, not treated as a side effect of diagnostics.

At the same time, ADR-0001, ADR-0007, and ADR-0008 define **how** strength is
delivered: one Xray data plane, a validation/strategy layer in Python and Rust,
and no raw-packet Rust egress engine. Safety and honesty constraints (ADR-0002,
ADR-0004, ADR-0005, ADR-0006) remain binding; they protect users, not censors.

## Decision

Defeating censorship and restoring usable access on the user's own path is a
**first-class product goal**, on equal footing with safety, honesty, and
maintainability.

We pursue it in two complementary halves, both first-class:

1. **Strong data plane (Xray-core, ADR-0001).** All on-the-wire evasion is
   expressed here: REALITY, uTLS fingerprint mimicry, TLS record fragmentation,
   padding/mux, domain fronting, FakeDNS, flexible routing. New transports belong
   in config profiles and, when upstream lacks them, in Xray-core (Go).

2. **Intelligent strategy layer (this repo).** Probe how the user's network is
   failing, classify the blocking method, score candidate strategies, auto-select
   and fail over, and prove success with redacted evidence (`verified-session`,
   JA3 oracle honesty per ADR-0004). Rust models and regression-tests; Python
   orchestrates; Xray executes.

ADR-0008 explicitly rejects raw injection and inline Rust byte bridges **not**
because evasion is unwanted, but because that approach is weaker, more brittle,
and more privileged than config + strategy.

## Consequences

- `ROADMAP.md` includes an anti-censorship capability roadmap (Tracks A/B/C):
  evasion profiles, adaptive strategy engine, and consent-gated public UX.
- **Camouflage SNI** (legitimate "SNI spoofing"): front `serverName` in Xray TLS/REALITY
  settings is documented in `docs/sni-camouflage.md` and inspected by
  `scripts/core/sni_camouflage.py` — the safe, data-plane counterpart to raw injection
  (ADR-0008). The shipped config already uses `tlsSettings.serverName` on repack
  outbounds; Track A adds REALITY/fragmentation profiles; Track B surfaces front
  selection in the strategy engine.
- Proposals that only add packet injection in Rust without a new ADR and threat
  model remain out of scope (ADR-0008).
- GUI and CLI should evolve toward plain-language resilience ("finding a way
  through", named strategy) with technical detail behind progressive disclosure
  (ADR-0006).
- Documentation (`docs/architecture.md`) names the strategy layer beside the
  runtime graph.

## References

- ADR-0001 — Xray as runtime.
- ADR-0006 — Target user and progressive disclosure.
- ADR-0007 — Rust validation boundary.
- ADR-0008 — No raw-packet injection data plane in Rust.
- `ROADMAP.md` — Tracks A/B/C.
