# ADR 0007: The Rust Core Is A Validation Library, Not A Data Plane

## Status

Accepted.

## Context

The `src/*.rs` tree looks, at a glance, like a live proxy engine: it has an
ingress trait (`ingress.rs`, `ingress_loopback.rs`, `ingress_android_tun.rs`,
`ingress_xdp_gateway.rs`), a `handle_client` accept loop in `main.rs`, a TLS
orchestrator (`tls_orchestrator.rs`), a ClientHello parser (`parser.rs`), JA3
logic (`ja3.rs`), and a scheduler. This naming repeatedly invites proposals to:

- modify `handle_client` to dial upstream over a SOCKS5 handshake to Xray;
- add raw-socket TCP sequence-number injection / SNI-spoofing inside the
  orchestrator;
- load eBPF/XDP programs from `ingress_xdp_gateway.rs` to rewrite live packets;
- treat the Rust binary as the egress data plane with Xray as a sidecar.

These proposals assume the Rust core forwards bytes to the internet. **It does
not.** Establishing the actual boundary as an accepted decision stops this
confusion from recurring and prevents accidental scope creep into a second,
competing runtime (which ADR-0001 already rules out, but only briefly).

What the Rust core actually does today (verified against the source):

- `PolicyAwareTlsBackend` (`tls_orchestrator_backend.rs`) implements ALPN
  negotiation/lock policy and bypass decisions. It contains **no socket dialing**
  and never connects upstream.
- `main.rs` `handle_client` reads a ClientHello off a loopback socket, parses it,
  runs ALPN orchestration *modeling* and an optional JA3 self-audit
  (`MITM_STREAM_EXPECTED_JA3`), and reports. It does **not** forward traffic to a
  destination or to Xray.
- The only `TcpStream::connect` in `src/` is the client side of a unit test in
  `ingress_loopback.rs`.
- `ingress_xdp_gateway.rs`, `ingress_android_tun.rs`, `cooperative_overlay.rs`,
  `h2_coalescing.rs`, and `scheduler.rs` are modeled abstractions and regression
  fixtures, not loaded kernel programs or a live scheduler on the egress path.

## Decision

The Rust core is a **validation, parsing, and policy-modeling library plus a
self-audit harness**. It is explicitly *not* the runtime data plane and must not
be wired into the live traffic path. Xray is the data plane (ADR-0001).

Concretely:

- The Rust core may parse, classify, score, model, and self-audit (e.g. confirm
  that a configured uTLS fingerprint produces the expected JA3). Its outputs are
  evidence and regression signals, not forwarded bytes.
- The Rust core must not open upstream connections, perform SOCKS5 client
  handshakes to Xray, manipulate raw packets, inject TCP segments, or load
  eBPF/XDP. Those belong to Xray (or, if ever justified, to a future Go/Xray-core
  contribution per ADR-0001).
- Integration with Xray is **config-and-evidence**, not in-band byte handoff:
  the toolchain generates and validates Xray config, runs Xray as the runtime,
  and the Rust core validates/observes around it.

## Consequences

- Proposals to add packet injection / SNI-spoofing / sequence-number tricks, or
  to make the Rust binary the egress engine, are out of scope here. They would
  require: (a) a new ADR revisiting ADR-0001, (b) a real threat-model review, and
  (c) the privilege/safety story (`CAP_NET_RAW`, Administrator) that ADR-0002 and
  ADR-0006 deliberately keep consent-based.
- `process_supervisor.py` already provides atomic, kill-on-close lifecycle
  containment (Windows Job Object, POSIX process group). A "run Rust + Xray as
  one machine" conductor can be built on it *without* changing the byte path —
  the Rust process stays a self-audit/observer alongside Xray, not an inline hop.
- If a Rust capability is ever promoted to the data plane, it should be
  implemented where the data plane lives (Xray-core in Go), not by turning the
  validation library into a parallel proxy.
- Module names that imply a live data plane (e.g. `ingress_xdp_gateway`) should
  carry doc comments clarifying they are models/fixtures, to reduce future
  confusion.
