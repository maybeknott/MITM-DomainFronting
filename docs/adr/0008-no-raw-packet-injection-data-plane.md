# ADR 0008: No TCP-Sequence-Injection / SNI-Spoofing Data Plane In The Rust Core

## Status

Accepted.

## Context

Repeated proposals describe a second egress path inside this repository:

- Raw-socket TCP sequence-number injection and out-of-window segments to defeat DPI.
- SNI or decoy-frame spoofing at the packet layer ("right before the connection leaves
  the device").
- eBPF/XDP programs loaded from `ingress_xdp_gateway.rs` to rewrite live frames.
- Rust modules such as `sni_spoof.rs`, `xray_bridge.rs`, or C helpers like
  `xdp_sni_spoof.c`.
- Inline SOCKS5 byte handoff (`dial_xray_socks_outbound`, `execute_bidirectional_splice`)
  that makes the Rust binary carry live traffic between client and Xray.

Verification against the current tree shows none of that exists and must not be
added here without revisiting foundational ADRs:

- **ADR-0001** — Xray is the single runtime data plane.
- **ADR-0007** — The Rust crate parses, models, scores, and self-audits; it does not
  forward bytes, dial upstream, or load kernel packet engines on the egress path.
- **ADR-0002 / ADR-0006** — Trust and privilege are consent-based; standing
  `CAP_NET_RAW` / Administrator daemons conflict with silent elevation.
- **THREAT_MODEL.md** — Supported use is user-controlled, user-owned testing on
  networks the user may configure; intercepting third-party traffic without
  authorization is unsupported.

Some blueprint snippets also misstate existing code (for example claiming
`PolicyAwareTlsBackend` performs SOCKS5 dialing, or citing fabricated Xray fields
such as `packetPhysics`). The only `TcpStream::connect` in `src/` is a unit-test
client in `ingress_loopback.rs`. `ingress_xdp_gateway.rs` is a model/fixture, not a
loaded XDP driver.

ADR-0009 affirms that anti-censorship is a first-class product goal. This ADR does
**not** reject evasion; it rejects the **weak, brittle, privileged** implementation
path (raw packet surgery and a parallel Rust byte plane) in favor of evasion
expressed in Xray config and an adaptive strategy layer (see ADR-0009 and
`ROADMAP.md` Tracks A/B/C).

## Decision

The Rust core will **not** implement:

- Raw-socket egress, TCP sequence injection, out-of-window segment tricks, or
  checksum/segment builders for live traffic.
- SNI spoofing, decoy TLS records, or any "apply spoofing at packet level before
  egress" engine in Rust or bundled C/eBPF shims controlled from this crate.
- Loading eBPF/XDP from this repository to rewrite packets on the wire.
- A privileged standing daemon (`cap_net_raw`, Windows admin service) as the
  default egress path for this project.
- An inline SOCKS5 or splice bridge that makes `mitm_stream_core` the hop that
  carries user bytes between client and Xray.

Evasion techniques that operate on the wire belong in **Xray-core (Go)** and in
**named config profiles** validated by this repo's toolchain. The Rust core may
**model** TLS/ALPN/JA3/routing behavior and regression-test policy; Python may
**probe, classify, score, and select** strategies; Xray **executes** them.

Revisit this boundary only via a **new ADR** that:

1. Revisits ADR-0001 (why move egress out of Xray),
2. Includes an updated threat model for raw injection and standing privileges, and
3. Specifies explicit, consent-based privilege-grant UX (no silent elevation).

## Consequences

- Blueprints proposing `src/sni_spoof.rs`, `src/xray_bridge.rs`, shared-memory
  SeqLock telemetry for a raw daemon, or rewriting `path_scorer.py` /
  `failure_classifier.py` into injection-sweep engines are **declined** as-is.
- ALPN inference and fail-open bypass already live in `tls_orchestrator_backend.rs`
  and `main.rs` (`MITM_STREAM_UPSTREAM_ALPN`, `MITM_STREAM_ALLOW_POLICY_INFERENCE`);
  no duplicate "xray_bridge" module is needed for that behavior.
- Future packet-level primitives, if ever justified, should be designed in
  Xray-core and adopted through config + tests here, not smuggled into the
  validation library.
- `ROADMAP.md` tracks the **strong** evasion path: REALITY/fragmentation profiles,
  adaptive strategy engine, and consent-gated one-button connect (ADR-0009).

## References

- ADR-0001 — Xray as runtime data plane.
- ADR-0007 — Rust core is validation, not data plane.
- ADR-0009 — Anti-censorship is a first-class goal; evasion via data plane + strategy.
- THREAT_MODEL.md — Supported vs. unsupported use cases.
