# TUN Operational Notes

TUN mode can capture more traffic than browser proxy mode. Treat it as platform-specific and test it independently from browser-only setup.

## Required Checks

- Confirm TUN mode is enabled only when intended.
- Confirm DNS behavior under TUN.
- Confirm private LAN access still works.
- Confirm IPv6 behavior.
- Confirm VPN conflict behavior.
- Confirm browser CA trust still works.

## Browser Proxy vs TUN

The structured profile definitions live in [tun-profiles.yml](../configs/tun-profiles.yml). They are policy metadata, not additional runtime configs.

| Mode | Scope | Main risk | Support note |
|---|---|---|---|
| Browser/system proxy | Usually browser-oriented | Apps may bypass proxy | Preferred first troubleshooting path |
| TUN/VPN mode | Broader device traffic | Captures apps that may not trust user CAs | Requires separate app-by-app validation |

If a site works in browser proxy mode but fails in TUN mode, collect DNS behavior, route tag, and whether the failing traffic is browser, app, UDP, or private LAN traffic.

## Android Notes

Android non-root operation usually depends on a VPN-service based client. Browser traffic may work while independent apps fail because of app trust rules, certificate pinning, or custom network stacks.

Android checks:

- HEV TUN setting matches the setup guide.
- User CA is installed and visible in Android security settings.
- Chromium-based browser trusts the user CA.
- Firefox has third-party CA support enabled if Firefox is used.
- Independent app failures are classified separately from browser failures.

## Failure Classes

| Symptom | Likely cause | Next check |
|---|---|---|
| Browser works, app fails | app CA trust or certificate pinning | Mark app-specific; do not claim config regression yet |
| LAN resource breaks | TUN route or DNS capture too broad | Check private IP/domain direct rules |
| Captive portal does not open | portal DNS/HTTP interception | Disable method until portal login completes |
| Media fails but page loads | QUIC/UDP or media domain route | Test with QUIC disabled and inspect route tag |
| IPv6 network differs | NAT64/DNS64 or CDN IPv6 drift | Record IPv6 state and resolver answers |

## Support Boundary

Do not mark an app as supported only because a browser works on the same device. App support needs its own evidence.

## Profile Policy

| Profile | Scope | Default | DNS policy | Failure policy |
|---|---|---|---|---|
| `browser-proxy-first` | Browser or explicit system proxy | Yes | `dns-balanced` | Warn on app-specific failures |
| `android-browser-safe` | External VPN-service client feeding browser-oriented traffic | No | `dns-balanced` | Do not infer independent app support |
| `desktop-full-system-strict` | Full-system capture | No | `dns-strict` | Stop on VPN, proxy, or DNS conflict |
| `desktop-split-tunnel` | Selected routes | No | `dns-local-first` | Keep private LAN direct and review DNS capture |
