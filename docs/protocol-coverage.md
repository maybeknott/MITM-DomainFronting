# Protocol Coverage

## Objective

Document what the current method is expected to handle, what is expected to pass through directly, what may partially work, and what is not supported. This reduces vague bug reports such as "site broken" by turning them into protocol-specific reports.

## Protocol matrix

| Protocol / technology | Current expected state | Main edge cases | Test requirement |
|---|---|---|---|
| TCP/443 HTTPS | Core supported path for targeted browser flows | Certificate trust, ALPN, SNI/ECH, provider drift | Browser test plus route-tag check |
| HTTP/1.1 over TLS | Supported through h11 local tunnel | WebSocket upgrades, keepalive, redirects | Test normal page + WebSocket endpoint |
| HTTP/2 over TLS | Supported through h2/h1 local tunnel | gRPC, stream resets, multiplexing | Test HTTP/2 page + gRPC-like h2 endpoint |
| HTTP/3 / QUIC / UDP/443 | Not fully modeled in the base config | May bypass TCP path, fail, or downgrade | Test UDP/443 behavior explicitly |
| DNS UDP/TCP/53 | Routed through DNS handling | Resolver timeout, hijack, private domains | Resolver tests |
| DoH | Depends on configured resolver route | Resolver reachability, TLS behavior | DNS check script |
| DoT | Not explicitly modeled unless user adds it | Port 853 behavior | Document unsupported unless tested |
| DoQ | Not explicitly modeled | UDP/QUIC-based DNS | Document unsupported unless tested |
| WebSocket | May work when HTTP/1.1 path works | Upgrade headers and proxy behavior | Add a WebSocket smoke test |
| gRPC | May work when HTTP/2 path works | h2 stream handling | Add h2/gRPC smoke test |
| WebRTC/STUN/TURN | App/browser-dependent, UDP-heavy | UDP route, IP leak risk, app pinning | Mark as degraded/experimental |
| IPv6 | Catch-all may direct-route IPv6 | IPv6-only/NAT64 differences | IPv6 route test |
| NAT64/DNS64 | Not guaranteed | IPv4-only assumptions | IPv6-only lab test |
| Captive portal HTTP | Environment-specific | DNS/HTTP hijack | Captive portal procedure |
| Private LAN | Should remain direct | Printers, router UI, local domains | LAN direct-route test |
| Enterprise TLS inspection | Competing MITM | CA conflicts | Document conflict behavior |
| Antivirus HTTPS scanning | Competing local TLS interception | Broken trust chain | Detection note |

## Simple classification labels

Use these labels in issues and compatibility files:

```text
supported       Expected to work in current config.
degraded        May work partially or require browser/app setting.
pass_through    Not handled by method; direct behavior expected.
unsupported     Known not to work reliably.
unknown         Not tested yet.
```

## Protocol test checklist

- [ ] TCP/443 HTTPS targeted domain loads.
- [ ] HTTP/1.1-only endpoint loads.
- [ ] HTTP/2 endpoint loads.
- [ ] WebSocket endpoint connects or failure is documented.
- [ ] gRPC/h2 endpoint connects or failure is documented.
- [ ] UDP/443 behavior is known.
- [ ] DNS UDP/TCP works.
- [ ] DoH resolver path works.
- [ ] IPv6 behavior is known.
- [ ] Private LAN destination remains reachable.
- [ ] Captive portal behavior is documented.
- [ ] Android browser behavior is documented separately from Android app behavior.

## Issue triage mapping

| User symptom | Likely protocol issue | What to ask for |
|---|---|---|
| Page loads but video fails | QUIC, media domain, provider route, or DNS | Browser, domain category, route tag, DNS result |
| Login page loops | cookies, third-party domains, ad-block false positive, pinned endpoint | route tag, ad-block rule, browser console category only |
| Works in Chrome but not Firefox | browser trust store or HTTP/2 behavior | CA install scope and browser version |
| Works on desktop but not Android app | Android user CA / pinning / app trust | app name, browser vs app, Android version |
| Works on Wi-Fi but not mobile | DNS64/NAT64, IPv6, provider region | network type, IPv6 status, resolver status |
| Fails after disabling tool | FakeDNS stale cache | run FakeDNS recovery steps |
