# Known Issues

## Certificate and trust

| ID | Symptom | Likely cause | Workaround |
|---|---|---|---|
| CERT-001 | Browser privacy error | CA not installed or wrong CA installed | Verify fingerprint and reinstall |
| CERT-002 | Worked before, then failed | Certificate expired or rotated | Rotate/reinstall CA |
| CERT-003 | Browser works but app fails | App ignores user CA or pins cert | Use browser or mark app unsupported |

## DNS

| ID | Symptom | Likely cause | Workaround |
|---|---|---|---|
| DNS-001 | Site lookup times out | Resolver timeout | Check resolver fallback |
| DNS-002 | Normal internet broken after stopping | FakeDNS stale cache | Follow FakeDNS recovery guide |
| DNS-003 | Internal LAN names fail | Enterprise/private DNS mismatch | Use local resolver for private domains |

## Protocols

| ID | Symptom | Likely cause | Workaround |
|---|---|---|---|
| PROTO-001 | Page loads but media fails | QUIC/UDP/media domain route | Test UDP/443 and media route |
| PROTO-002 | Works in Chrome but not Firefox | Browser trust store or settings | Verify CA in Firefox |
| PROTO-003 | Mobile network differs from Wi-Fi | IPv6/NAT64/provider region | Add network details to issue |

## Providers

| ID | Symptom | Likely cause | Workaround |
|---|---|---|---|
| PROV-001 | Specific provider stops working suddenly | Provider policy or domain/IP drift | Update provider status and routes |
| PROV-002 | Only one ISP affected | Regional CDN or DNS difference | Add ISP/region/network details |
