# Reviewer Checklist

## Purpose

Pre-merge checklist for config, DNS, certificate, documentation, and release changes. Complete relevant sections before merging behavior-affecting work.

Use this checklist before merging config, DNS, certificate, documentation, or release changes.

## Config review

- [ ] JSON parses.
- [ ] `remarks` version updated if behavior changed.
- [ ] Required inbounds exist: `mixed-in`, `tls-decrypt-google-h11`, `tls-decrypt-google-h2`, `tls-decrypt-fastly-h2`, `tls-decrypt-meta-h2`.
- [ ] Required ports are present: 10808, 11666, 11777, 11888, 11999.
- [ ] Local inbounds explicitly bind to loopback or the absence is documented as a warning.
- [ ] Required outbounds exist.
- [ ] Every route `outboundTag` points to an existing outbound.
- [ ] Every route `inboundTag` points to an existing inbound.
- [ ] Every rule has `ruleTag` or missing tags are documented before release.
- [ ] Rule order was reviewed for shadowing.
- [ ] Final catch-all behavior is understood.
- [ ] Static CIDRs have rationale.
- [ ] No private keys or local certs are committed.

## DNS review

- [ ] Resolver timeout behavior is documented.
- [ ] Local/private DNS behavior is documented.
- [ ] FakeDNS behavior is documented.
- [ ] FakeDNS recovery guide is current.
- [ ] DNS route tags are present.
- [ ] DNS loop risk reviewed.
- [ ] Captive portal limitation documented.
- [ ] DNS64/NAT64 status documented.

## Protocol review

- [ ] HTTP/1.1 expected behavior documented.
- [ ] HTTP/2 expected behavior documented.
- [ ] HTTP/3/QUIC behavior documented.
- [ ] WebSocket behavior documented or marked unknown.
- [ ] gRPC behavior documented or marked unknown.
- [ ] WebRTC/STUN/TURN behavior documented or marked degraded/unsupported.
- [ ] IPv6 behavior documented.
- [ ] Android app limitations documented.
- [ ] No handcrafted TLS `ServerHello`/`Finished` byte-forging is introduced without transcript-level tests.
- [ ] ALPN local/upstream lock behavior is explicit and fail-closed on mismatch.
- [ ] HTTP/2 provider coalescing isolation is preserved (`:authority` normalization + provider-family pinning).
- [ ] No async mutex is held across `.await` in stream/overlay paths.

## Certificate review

- [ ] Easy certificate generation still works.
- [ ] Certificate status script works.
- [ ] Install guide is current.
- [ ] Verify guide is current.
- [ ] Rotate guide is current.
- [ ] Remove guide is current.
- [ ] Emergency compromise guide is current.
- [ ] Expired certificate recovery is current.
- [ ] Wrong-certificate recovery is current.

## Release review

- [ ] `validate_config.py` passed.
- [ ] `preflight.py` passed or warnings are documented.
- [ ] Xray test passed or not-run reason documented.
- [ ] Checksums generated.
- [ ] Validation report generated.
- [ ] Support matrix updated.
- [ ] Risk register reviewed in engineering handbook.
- [ ] Final verdict written.
- [ ] Any new dependency is reflected in requirements/CI and validated on clean checkout.
- [ ] Existing script CLI contracts remain stable, or breaking changes are versioned and documented.
- [ ] `auto_switch_safe` remains false unless explicit governance approval exists.

## Related documents

| Document | Topic |
|---|---|
| [`routing-correctness.md`](routing-correctness.md) | Route invariants |
| [`certificate-lifecycle.md`](certificate-lifecycle.md) | CA lifecycle docs |
| [`release-evidence.md`](release-evidence.md) | Release validation |
| [`final-verdict-template.md`](final-verdict-template.md) | Release verdict template |
