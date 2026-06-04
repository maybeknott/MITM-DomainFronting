# Track D eBPF/XDP ingress telemetry

Production loader: `py -3 scripts/ebpf_xdp_loader.py` with `MITM_EBPF_CONSENT=1`.

Programs:

| Program | Purpose |
|---|---|
| `telemetry` | Pass-through RX counter |
| `containment` | `XDP_DROP` on TCP when `supervisor_alive=0` after supervisor exit |

## Build (Linux)

```bash
make -C tools/ebpf
```

## Attach

```bash
export MITM_EBPF_CONSENT=1
export MITM_STREAM_XDP_IFACE=eth0
py -3 scripts/ebpf_xdp_loader.py --interface "$MITM_STREAM_XDP_IFACE" --program containment
export MITM_EBPF_CONTAINMENT=1
```

Detach: `py -3 scripts/ebpf_xdp_loader.py --detach --interface eth0`

State file: `.local-state/ebpf-xdp-loader.json`

Xray remains the live TLS/data plane; this program is ingress telemetry only.
