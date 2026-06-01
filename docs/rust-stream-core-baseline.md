# Rust Stream-Core Baseline (Milestones 4-8)

This repository now includes a tested Rust stream-core baseline at the repo root:

- `Cargo.toml`
- `src/main.rs`
- `src/alpn_policy.rs`
- `src/h2_coalescing.rs`
- `src/ingress.rs`
- `src/parser.rs`
- `src/cert_cache.rs`
- `src/regression_harness.rs`
- `src/scheduler.rs`

Current scope:

1. **Milestone 4: stream-core baseline**
   - Loopback listener (`MITM_STREAM_LISTEN`, default `127.0.0.1:10808`)
   - Safe, bounded TLS `ClientHello` parser
   - Fragment-aware collection across TLS handshake records

2. **Milestone 5: bounded cert cache**
   - Bounded positive cache with per-provider and global caps
   - TTL handling
   - Negative cache (`mark_denied` / `denied_reason`)

3. **Milestone 6: TLS regression harness baseline**
   - JA3 / JA4 / ALPN / H2-settings / GREASE checks
   - Explicit mismatch reporting

4. **Milestone 7: adaptive path scheduler baseline**
   - Foreground selection avoids open circuits
   - Background half-open probe selection
   - Request lifecycle tracking (`begin_request` / `finish_request`)
   - Failure phase carried in samples

5. **Milestone 8: ingress boundary baseline**
   - Separate stream and packet ingress traits
   - Packet references reject empty packets
   - Flow metadata supports unknown original destination

6. **ALPN policy lock baseline**
   - Local ALPN can only be selected from client-offered and provider-allowed values
   - Forced modes fail when the upstream result conflicts
   - Missing upstream selection is reported as a policy error

7. **HTTP/2 coalescing guard baseline**
   - Sessions bind to one provider family
   - `:authority` values are normalized before tracking
   - Cross-provider reuse fails closed

Important limits:

- This is **not** a production TLS MITM engine yet.
- No handcrafted TLS `ServerHello` forging is implemented.
- Android TUN and AF_XDP are represented as backend boundaries, not enabled runtime backends.
- No runtime auto-switching is introduced by this Rust baseline.

Validation:

- Run Rust tests: `python scripts/rust_core_tests.py`
- Or directly: `cargo test`
- Lint strictly: `cargo clippy --all-targets -- -D warnings`
