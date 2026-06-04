# TUN Operational Notes

## Purpose

Document TUN/VPN-mode checks that differ from browser-only proxy setup. TUN can capture broader traffic; validate DNS, private LAN reachability, and app trust separately from browser success.

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

## Fail-closed firewall checklist (High Stealth / TUN lab)

Run these **after** TUN is enabled and **before** claiming leak protection. Adjust interface names and app paths for your host.

### Windows (WFP)

1. Confirm only the intended TUN/VPN interface carries default-route traffic (`Get-NetRoute -DestinationPrefix 0.0.0.0/0`).
2. Block browser WebRTC STUN on UDP/3478 when testing proxy-only paths:

```powershell
New-NetFirewallRule -DisplayName "MITM-lab-block-stun-udp3478" -Direction Outbound -Action Block -Protocol UDP -RemotePort 3478
```

3. Optional: block QUIC/UDP443 egress during strict lab runs (restore after test):

```powershell
New-NetFirewallRule -DisplayName "MITM-lab-block-udp443" -Direction Outbound -Action Block -Protocol UDP -RemotePort 443
```

4. Remove lab rules when finished:

```powershell
Remove-NetFirewallRule -DisplayName "MITM-lab-block-stun-udp3478"
Remove-NetFirewallRule -DisplayName "MITM-lab-block-udp443"
```

### Linux (nftables)

```bash
# Block STUN during lab
sudo nft add rule inet filter output udp dport 3478 counter drop
# Optional QUIC block
sudo nft add rule inet filter output udp dport 443 counter drop
# List and delete by handle after the run
sudo nft -a list chain inet filter output
```

Validate with browser leak tests plus `tcpdump udp port 3478` on the egress interface. Do not treat firewall rules as a substitute for route/DNS correctness — they are a lab gate only.

## Related documents

| Document | Topic |
|---|---|
| [`android-guide.md`](android-guide.md) | v2rayNG TUN setup |
| [`android-trust-model.md`](android-trust-model.md) | App vs browser trust |
| [`operating-profiles.md`](operating-profiles.md) | Profile failure policies |
| [`protocol-coverage.md`](protocol-coverage.md) | QUIC and UDP expectations |
