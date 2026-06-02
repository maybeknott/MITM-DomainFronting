# Rust Stream-Core Baseline (Milestones 4-9)

This repository now includes a tested Rust stream-core baseline at the repo root:

- `Cargo.toml`
- `src/main.rs`
- `src/alpn_policy.rs`
- `src/backend_runtime.rs`
- `src/h2_coalescing.rs`
- `src/ingress.rs`
- `src/ingress_android_tun.rs`
- `src/ingress_loopback.rs`
- `src/ingress_xdp_gateway.rs`
- `src/parser.rs`
- `src/cert_cache.rs`
- `src/cooperative_overlay.rs`
- `src/regression_harness.rs`
- `src/scheduler.rs`
- `src/tls_orchestrator.rs`
- `src/tls_orchestrator_backend.rs`

Current scope:

1. **Milestone 4: stream-core baseline**
   - Loopback listener (`MITM_STREAM_LISTEN`, default `127.0.0.1:10808`)
   - Safe, bounded TLS `ClientHello` parser. Per-record payload lengths are
     validated against the RFC 8446 §5.1 ceiling (2^14 bytes) and the overall
     ClientHello budget *before* any buffer is allocated, so a peer cannot make
     the parser reserve a large buffer for bytes it never (or only slowly)
     sends (pre-allocation DoS hardening)
   - Fragment-aware collection across TLS handshake records
   - Bounded handshake read timeout (`MITM_STREAM_HANDSHAKE_TIMEOUT_MS`,
     default `10000`, `0` disables) so a slow/idle peer cannot pin a worker
     thread indefinitely (slow-loris hardening)
   - Accept-loop backoff after `accept_flow` errors, preventing a hot
     busy-loop when accept fails persistently (e.g. file-descriptor
     exhaustion)
   - Misconfiguration is now visible on stderr instead of silently ignored:
     unrecognized `MITM_STREAM_BACKEND` values, non-integer millisecond env
     vars (`MITM_STREAM_HANDSHAKE_TIMEOUT_MS`, `MITM_STREAM_TIMEOUT_MS`), and
     unrecognized boolean values (`MITM_STREAM_ALLOW_POLICY_INFERENCE`) emit a
     warning and fall back to the documented default
   - Packet backend MTU budget is configurable via `MITM_STREAM_MAX_PACKET_SIZE`
     (default `2048`); invalid values warn and fall back to the default
   - The observed JA3 fingerprint (string + MD5 hash, GREASE-stripped per
     RFC 8701) is computed from each `ClientHello` and logged. Setting
     `MITM_STREAM_EXPECTED_JA3` to the JA3 MD5 hash a genuine client of the
     impersonated browser would present enables a runtime self-audit: a match
     is logged, and any divergence warns loudly on stderr so a drifting
     presented fingerprint is surfaced rather than silently tolerated

2. **Milestone 5: bounded cert cache**
   - Bounded positive cache with per-provider and global caps
   - TTL handling
   - Negative cache (`mark_denied` / `denied_reason`)

3. **Milestone 6: TLS regression harness baseline**
   - JA3 / JA4 / ALPN / H2-settings (ordered id *and* id:value) / TLS
     extension-order / GREASE checks
   - Explicit mismatch reporting
   - `observation_from_client_hello` bridges a parsed `ClientHello` into a
     `TlsObservation` (computing JA3 via the dependency-free `ja3` module), so
     the same harness used in tests can self-audit the live runtime fingerprint

4. **Milestone 7: adaptive path scheduler baseline**
   - Foreground selection avoids open circuits
   - Background half-open probe selection
   - Request lifecycle tracking (`begin_request` / `finish_request`)
   - Failure phase carried in samples

5. **Milestone 8: ingress boundary baseline**
   - Separate stream and packet ingress traits
   - Desktop loopback ingress backend implementing the stream trait
   - Packet references reject empty packets
   - Flow metadata supports unknown original destination

6. **Milestone 9: cooperative overlay baseline**
   - Session open/authentication boundary via `OverlayAuthenticator`
   - Strict sequence handling with replay/out-of-order rejection
   - Explicit UDP-to-TCP fallback state toggles
   - Idle session pruning and bounded session capacity

7. **ALPN policy lock baseline**
   - Local ALPN can only be selected from client-offered and provider-allowed values
   - Forced modes (`force_http11`, `force_h2`) fail when the upstream result conflicts
   - `reject_mismatch` mode clones the upstream selection but fails closed when it
     diverges from the client's most-preferred (first-offered) protocol, so the
     MITM never silently downgrades the client's top ALPN preference
   - Missing upstream selection is reported as a policy error

8. **HTTP/2 coalescing guard baseline**
   - Sessions bind to one provider family
   - `:authority` values are normalized before tracking
   - Cross-provider reuse fails closed

9. **TLS orchestration baseline**
   - Upstream ALPN negotiation and local ALPN commit are split behind explicit traits
   - Fallback policy is explicit (`FailClosed`, `ForceHttp11IfPossible`, `BypassWithoutMitm`)
   - Upstream negotiation errors can degrade to bypass mode when policy allows

10. **Backend runtime fallback baseline**
    - Runtime backend selection supports `auto`, `loopback`, `android_tun`, `gateway_xdp`
    - Android TUN and XDP packet backends are capability-gated and bounded
    - Unsupported or misconfigured packet backends automatically fall back to loopback with visible runtime notes

Important limits:

- This is **not** a production TLS MITM engine yet.
- No handcrafted TLS `ServerHello` forging is implemented.
- Android TUN and AF_XDP paths are bounded packet backends with explicit fallback to loopback.
- No runtime auto-switching is introduced by this Rust baseline.

Validation:

- Run Rust tests: `python scripts/rust_core_tests.py`
- Or directly: `cargo test`
- Lint strictly: `cargo clippy --all-targets -- -D warnings`
