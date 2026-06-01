# Rust Stream-Core Prototype (Milestones 4-6)

This repository now includes a **prototype** Rust core at the repo root:

- `Cargo.toml`
- `src/main.rs`
- `src/parser.rs`
- `src/cert_cache.rs`
- `src/regression_harness.rs`

Current scope:

1. **Milestone 4: stream-core prototype**
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

Important limits:

- This is **not** a production TLS MITM engine yet.
- No handcrafted TLS `ServerHello` forging is implemented.
- No Android TUN or AF_XDP runtime integration is in this milestone set.
- No runtime auto-switching is introduced by this Rust prototype.

Validation:

- Run Rust tests: `python scripts/rust_core_tests.py`
- Or directly: `cargo test`
