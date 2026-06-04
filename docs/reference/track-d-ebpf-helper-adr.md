# ADR: eBPF/XDP production loader (Track D)

## Status

Accepted — production loader shipped with explicit consent gate. Xray remains the sole TLS/data plane.

## Context

`src/ingress_xdp_gateway.rs` models batch ingress shapes for regression tests. Operators need optional kernel-side ingress telemetry under active lab or gateway deployments without promoting Rust to live egress.

## Decision

1. Ship `scripts/ebpf_xdp_loader.py` with **telemetry** and **containment** programs (`tools/ebpf/*.bpf.c`).
2. Require `MITM_EBPF_CONSENT=1` before any kernel attach; record state in `.local-state/ebpf-xdp-loader.json`.
3. Containment sets `supervisor_alive=0` on ProcessSupervisor stop → TCP `XDP_DROP` (fail-closed). Optional `MITM_EBPF_CONTAINMENT=1` on start.
4. Rust enables the XDP gateway backend when loader state reports `attached` or `MITM_EBPF_ATTACHED=1` (coordination only).
5. Do **not** auto-load containment from GUI Start Core unless operator sets consent + containment env vars.

## Consequences

- Live egress remains Xray-only (ADR-0007).
- CI uses `--simulate` for structure probes (`protocol_smoke.py --scenario ebpf-xdp-loader`).
- Operators build BPF objects on Linux (`make -C tools/ebpf`) before live attach.

## Related

- `docs/reference/03-issues-risks-validation.md` §4
- `src/ingress_xdp_gateway.rs`
- `tools/ebpf/README.md`
