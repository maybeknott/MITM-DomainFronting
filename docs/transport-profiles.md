# Transport Compatibility Notes

## Purpose

This file documents transport capability without requiring multiple runtime profiles.

## Current simple approach

- Keep one user-facing config.
- Document protocol behavior in `docs/protocol-coverage.md`.
- Add validation for TCP/UDP/DNS/IPv6 edge cases.
- Do not add relays by default.
- Do not add unauthenticated admin/API endpoints.
- Keep transport profile policy in [`configs/transport-profiles.yml`](../configs/transport-profiles.yml), validated by `scripts/transport_profile_validate.py`.

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
| Xray transports like XHTTP/gRPC/WS/Hysteria | external-engine review | Default-disabled in `configs/transport-profiles.yml`; requires upstream or architecture review |

## Rule

Transport expansion should be tested and documented before claiming support. Unsupported transports must stay explicitly labeled rather than silently assumed.

## Evidence Commands

```bash
python scripts/transport_profile_validate.py
python scripts/protocol_smoke.py --scenario udp443-policy
python scripts/protocol_smoke.py --scenario http2-alpn --host example.com
python scripts/protocol_smoke.py --scenario grpc-alpn --host example.com
```

## Related documents

| Document | Topic |
|---|---|
| [`protocol-coverage.md`](protocol-coverage.md) | Full protocol matrix |
| [`transport-extension-governance.md`](transport-extension-governance.md) | Transport change governance |
| [`sni-camouflage.md`](sni-camouflage.md) | Camouflage SNI in outbounds |
| [`configs/transport-profiles.yml`](../configs/transport-profiles.yml) | Transport profile policy |
