# Evidence Map

This document maps repository evidence to engineering conclusions.

| Evidence | Conclusion | Required action |
|---|---|---|
| Config defines `mixed-in` plus isolated Google/Fastly/Meta decrypt inbounds | Local ingress/decrypt graph exists | Validate local ports and listener binding |
| Config uses certificate `usage: issue` with `mycert.crt` and `mycert.key` | Local certificate lifecycle is central | Add lifecycle docs and status script |
| Config uses DNS, FakeDNS, resolver aliases, localhost fallback, `serveStale`, and explicit Xray query strategy | DNS is a major runtime dependency | Add DNS resilience docs and tests |
| Config uses service/provider routing groups | Route drift and provider drift are core risks | Add route tags, provider status, release validation |
| `.gitignore` only ignoring IDE files is insufficient | Generated keys can be accidentally committed | Add cert/key/log/geodata ignore rules |
| PR proposing DNS fallback and cert-generation improvements exists | Some hardening needs are already recognized | Preserve easy cert generation while improving reliability |
| Xray routing is ordered | Route order matters | Add route validation and shadowing review |
| Xray supports multiple transports | Protocol taxonomy is feasible | Document protocol support, but keep one config |
| FakeDNS can create stale mappings | Recovery docs are required | Add FakeDNS recovery guide |
| Android trust behavior varies by app | Browser success does not imply app success | Add platform compatibility matrix |
| Provider policies can change | External drift can break routes | Add provider status and known issues |
