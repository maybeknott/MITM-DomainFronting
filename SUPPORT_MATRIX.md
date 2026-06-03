# Support Matrix

## Purpose

Summarize documented platform and protocol support levels. Do not claim app or protocol support without validation evidence attached to a release.

## Summary

| Area | Status | Notes |
|---|---|---|
| Windows + v2rayN | supported | Primary documented desktop path |
| Android + v2rayNG + Chromium browser | supported/browser-oriented | App support varies |
| Android independent apps | limited/unknown | User CA, pinning, custom trust, QUIC may break |
| macOS | test-required | Add release evidence before claiming full support |
| Linux | test-required | Distro trust store differs |
| HTTP/1.1 | supported/test-required | WebSocket needs explicit test |
| HTTP/2 | supported/test-required | gRPC needs explicit test |
| HTTP/3/QUIC | limited/unknown | UDP/443 behavior must be documented |
| DNS/FakeDNS | supported but sensitive | Recovery docs required |
| WebRTC/STUN/TURN | degraded/unknown | UDP-heavy and app/browser-specific |

## Version table

| Release | Xray | v2rayN | v2rayNG | Windows | Android | macOS | Linux | Notes |
|---|---|---|---|---|---|---|---|---|
| current main | min 26.2.6 per config | test before release | test before release | supported path documented | browser-oriented path documented | needs release evidence | needs release evidence | Do not claim app/protocol support without validation evidence |

## Related documents

| Document | Topic |
|---|---|
| [`docs/platform-compatibility.md`](docs/platform-compatibility.md) | Detailed compatibility matrix |
| [`docs/protocol-coverage.md`](docs/protocol-coverage.md) | Protocol expectations |
| [`docs/release-evidence.md`](docs/release-evidence.md) | Release validation |
| [`docs/final-verdict-template.md`](docs/final-verdict-template.md) | Release recommendation template |
