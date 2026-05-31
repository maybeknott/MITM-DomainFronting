# Assumptions and Unknowns

## Assumptions

| Assumption | Confidence | Validation |
|---|---|---|
| The config is intended for local user-controlled operation | High | README and local port design |
| `mycert.crt` and `mycert.key` are user-specific | High | Certificate lifecycle docs |
| The main user workflow should remain one config | High | Project simplicity requirement |
| Browser support is more reliable than arbitrary app support | High | Platform trust behavior |
| Provider/CDN behavior can change externally | High | Provider status review |
| DNS behavior is environment-dependent | High | DNS test matrix |
| Android non-root app support is limited | High | Android trust model |

## Unknowns

| Unknown | Why it matters | How to reduce uncertainty |
|---|---|---|
| Exact client version behavior | UI/import behavior can change | Record v2rayN/v2rayNG versions per release |
| Exact Xray binding defaults | Listener exposure depends on defaults | Add explicit `listen` and preflight checks |
| Geosite/GeoIP version on user device | Routing can drift | Publish hashes and tested versions |
| Provider success rates by ISP/region | Provider routes can be region-specific | Add provider status and issue template |
| HTTP/3/QUIC behavior per browser | UDP path may differ | Protocol tests |
| ECH behavior per browser/OS | SNI assumptions may change | Compatibility matrix |
| App-specific CA/pinning behavior | App support varies | App compatibility labels |
| Captive portal behavior | Network login can interfere | Captive portal test note |
| FakeDNS stale cache frequency | Recovery need varies | Add recovery validation reports |

## Maintenance rule

Every release should update this file if a previously unknown item becomes known through testing.
