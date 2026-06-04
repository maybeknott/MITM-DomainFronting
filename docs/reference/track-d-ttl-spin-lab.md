# Track D — TTL spin / ghost segments (lab only)

## Status

Reference lab technique — **not** implemented in the live Rust validation binary or GUI data plane.

## Intent

Stateful middleboxes (censors, some DPI) track TCP flows. TTL-limited decoy segments can exhaust tracker table entries while genuine segments (normal TTL) reach the origin/CDN.

## Owner (when implemented)

1. **Xray-core** `sockopt` / outbound tuning where supported.
2. Optional consented **eBPF/XDP helper** per [track-d-ebpf-helper-adr.md](track-d-ebpf-helper-adr.md).

## Lab validation (current)

- TLS record fragmentation reference: `config-src/fragments/tls-fragment-overlay.json`
- Structure probe: `py -3 scripts/protocol_smoke.py --scenario ttl-spin-policy`
- Wire proof requires controlled lab capture (pcap + TTL field inspection) — not CI by default.

## Rejected

- Emitting decoy segments from `mitm_stream_core` mock send path as default egress.
- Silent kernel module install from the GUI.

## Related

- [02-decisions-evasion-engineering.md](02-decisions-evasion-engineering.md) §4.2
- [01-architecture-runtime-delivery.md](01-architecture-runtime-delivery.md) Track D matrix
