# Transport Compatibility Notes

## Purpose

This file documents transport capability without requiring multiple runtime profiles.

## Current simple approach

- Keep one user-facing config.
- Document protocol behavior in `docs/protocol-coverage.md`.
- Add validation for TCP/UDP/DNS/IPv6 edge cases.
- Do not add relays by default.
- Do not add unauthenticated admin/API endpoints.

## Transport handling table

| Transport | Simple status | Notes |
|---|---|---|
| TCP | primary | Main route path for HTTPS |
| UDP | explicit testing required | QUIC/WebRTC/DNS edge cases |
| HTTP/1.1 | supported/tested | h11 local tunnel path |
| HTTP/2 | supported/tested | h2/h1 local tunnel path |
| HTTP/3/QUIC | profile-defined | Strict/debug block UDP/443; balanced/compatibility direct-route with warning |
| WebSocket | test-required | Depends on HTTP/1.1 upgrade handling |
| gRPC | test-required | Depends on HTTP/2 stream behavior |
| Xray transports like XHTTP/gRPC/WS/Hysteria | not added by default | Would change architecture; document separately if ever added |

## Rule

Transport expansion should be tested and documented before claiming support. Unsupported transports must stay explicitly labeled rather than silently assumed.
