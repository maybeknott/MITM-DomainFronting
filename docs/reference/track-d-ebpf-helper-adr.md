# ADR: Optional eBPF helper (Track D — not live)

## Status

Proposed — lab/CI only. **Not** promoted to the live Xray data plane.

## Context

`src/ingress_xdp_gateway.rs` and related Rust fixtures validate parsing and scheduling offline. Track D references an optional host-side eBPF helper for leak detection and ingress telemetry in controlled lab environments.

## Decision

1. Keep eBPF/XDP code in the Rust crate as **offline fixtures** (`mitm_stream_core` tests / lab harness).
2. Do **not** ship a live BPF loader from the GUI or `main.py` ProcessSupervisor path.
3. If a helper is needed later, it must be a separate signed artifact with explicit operator consent, distinct from `xray/xray.exe`.

## Consequences

- Live egress remains Xray-only (ADR-0007 alignment).
- Lab operators use `protocol_smoke.py`, firewall checklists (`docs/tun-operational-notes.md`), and Rust unit tests for regression signal.
- Future helper work requires: verifier CI, capability drop, and documented rollback.

## Related

- `docs/reference/03-issues-risks-validation.md` §4
- `src/ingress_xdp_gateway.rs`
- `docs/rust-stream-core-baseline.md`
