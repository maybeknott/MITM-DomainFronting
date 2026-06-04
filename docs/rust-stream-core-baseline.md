# Rust stream-core (`mitm_stream_core`) baseline

## Purpose

This document describes the **Rust validation crate** at the repository root: what it
implements, what it deliberately does **not** do, and how to run tests.

**Critical boundary:** `mitm_stream_core` is **not** the production data plane.
**Xray-core** (`xray/xray.exe`) is the sole component that forwards live traffic to
the internet. Python spawns Xray only via `ProcessSupervisor` — not this Rust binary
at GUI init.

---

## Crate layout

| Path | Role |
|---|---|
| `Cargo.toml` | Empty `[dependencies]` — validation library, not a TLS stack |
| `src/main.rs` | Optional loopback harness (lab); prints policy outcome |
| `src/parser.rs` | Bounded TLS ClientHello parser |
| `src/ja3.rs` | Parse ClientHello → JA3 string/hash; offline JA3 regression check |
| `src/regression_harness.rs` | JA3/ALPN/H2/extension-order regression gates |
| `src/cert_cache.rs` | In-memory cert cache **model** (not live MITM) |
| `src/tls_orchestrator*.rs` | ALPN policy **model** (no socket I/O) |
| `src/h2_coalescing.rs` | HTTP/2 coalescing **model** |
| `src/ingress_*.rs` | Ingress **fixtures** (loopback, Android TUN model, XDP mock) |
| `src/cooperative_overlay.rs` | Session/auth **model** for regression |
| `src/backend_runtime.rs` | Selects ingress fixture for harness |
| `src/scheduler.rs` | Adaptive path scheduler baseline (tests) |

`ingress_xdp_gateway.rs` is explicitly a **validation fixture** — not a loaded eBPF
program on the live egress path.

---

## Milestone capabilities (validation scope)

1. **Stream-core baseline** — loopback listener (`MITM_STREAM_LISTEN`, default
   `127.0.0.1:10808`); bounded ClientHello parser with pre-allocation DoS hardening;
   fragment-aware collection; handshake timeout; accept-loop backoff; env var warnings;
   JA3 regression check via `MITM_STREAM_EXPECTED_JA3`.

2. **Cert cache model** — bounded positive/negative cache with TTL.

3. **TLS regression harness** — JA3/JA4/ALPN/H2 SETTINGS order and id:value checks;
   extension order; GREASE handling; `observation_from_client_hello` bridge.

4. **Scheduler baseline** — circuit avoidance, probe selection, request lifecycle.

5. **Ingress traits** — stream vs packet backends; loopback implements stream trait.

6. **Cooperative overlay model** — session auth, sequence strictness, replay rejection.

7. **ALPN policy lock** — client-offered ∩ provider-allowed; forced modes; reject mismatch.

8. **H2 coalescing guard** — single provider family per session; authority normalization.

9. **TLS orchestration model** — upstream vs local ALPN commit split; explicit fallback policy.

10. **Backend runtime fallback** — `auto` / `loopback` / `android_tun` / `gateway_xdp`
    with capability gating and visible fallback notes.

---

## Explicit limits (do not assume more)

| Capability | Status |
|---|---|
| Production TLS MITM on wire | **No** — Xray + `mycert.*` |
| Handcrafted ServerHello forging | **No** |
| Live eBPF loader | **Yes** — `scripts/ebpf_xdp_loader.py` + `tools/ebpf/` (consent-gated; Xray still data plane) |
| uTLS / rustls wire emission from `ja3.rs` | **No** |
| Runtime auto-switching to Rust forwarder | **No** |
| Android TUN / XDP on production path | **Harness models only** |

---

## Production boundary

This crate validates models and regression gates. **Xray** owns live TLS MITM, routing,
and outbound repack on the wire.

| Capability | This crate | Live owner |
|---|---|---|
| `ingress_xdp_gateway.rs` loads libbpf | Mock `BatchPacketBuffer`; enables when loader state / `MITM_EBPF_ATTACHED=1` | Xray + `ebpf_xdp_loader.py` on NIC |
| `ja3.rs` drives live uTLS | Parses → JA3 hash | Xray `tlsSettings.fingerprint` |
| `tls_orchestrator.rs` mutates wire | ALPN policy model | Xray repack outbounds |
| `cert_cache.rs` OpenSSL on disk | In-memory model | Xray + `mycert.crt` / `.key` |
| Python spawns Rust + Xray at init | Harness optional | **Xray only** |

Rust module verification checklists: [reference/02-decisions-evasion-engineering.md](reference/02-decisions-evasion-engineering.md) (ADR-0007).

---

## Validation commands

```bash
python tests/python/rust_core_tests.py
cargo test --locked
cargo clippy --all-targets -- -D warnings
```

Optional harness env vars: `MITM_STREAM_BACKEND`, `MITM_STREAM_EXPECTED_JA3`,
`MITM_STREAM_HANDSHAKE_TIMEOUT_MS` — see `src/main.rs` and module docs.

---

## Related documents

| Topic | Document |
|---|---|
| Production runtime graph | [reference/01-architecture-runtime-delivery.md](reference/01-architecture-runtime-delivery.md) §2 |
| ADR-0007 validation boundary | [reference/02-decisions-evasion-engineering.md](reference/02-decisions-evasion-engineering.md) (ADR-0007) |
