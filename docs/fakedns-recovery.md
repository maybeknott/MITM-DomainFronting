# FakeDNS recovery

## Purpose

FakeDNS maps unresolved hostnames to **virtual IP addresses** in the **`198.18.0.0/15`**
range (RFC 2544 benchmark space) so applications resolve names inside Xray or a TUN
tunnel instead of leaking queries to the ISP resolver on UDP port 53.

**Problem this solves:** after FakeDNS stops, stale mappings can remain in OS or browser
DNS caches and make normal internet access look broken until caches are cleared.

**Leak class:** without FakeDNS (or equivalent), browsers may prefetch DNS via the system
resolver before proxy routing applies — exposing destination intent on raw UDP/53.
High Stealth profiles route DNS through Xray FakeDNS; optional kernel traps are Track D.

---

## Safe disable sequence

1. Stop browser tabs using the method.
2. Stop v2rayN / v2rayNG / Xray.
3. Disable system proxy or TUN/VPN mode.
4. Flush OS DNS cache (commands below).
5. Restart browser completely.
6. If still broken, reboot network interface or device.

---

## Platform commands

### Windows

```powershell
ipconfig /flushdns
```

Restart browser. Disable system proxy in Windows settings or the client UI if it was enabled.

### macOS

```bash
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder
```

Restart browser.

### Linux (systemd-resolved)

```bash
resolvectl flush-caches
```

NetworkManager alternative:

```bash
sudo systemctl restart NetworkManager
```

Restart browser.

### Android

1. Stop the VPN/TUN client.
2. Toggle airplane mode on and off.
3. Clear browser DNS/cache if needed.
4. Reboot if stale mapping persists.

---

## Browser-level flush

Chromium-based browsers may retain host cache. Restart the browser completely. Use the
browser's internal DNS/host cache page for your version if problems persist.

---

## Verification

After flushing:

```bash
python scripts/check_dns.py --domain example.com
python scripts/fakedns_recovery_check.py --domain example.com
```

Open a normal site **without** the method enabled to confirm recovery.

Automated flush where supported:

```bash
python scripts/fakedns_recovery_check.py --domain example.com --yes
```

The script prints redacted JSON evidence only — no browsing payloads or credentials.

---

## Related issues

| Symptom | Known issue ID |
|---|---|
| Internet broken after stopping Xray | DNS-002 in [reference/03-issues-risks-validation.md](reference/03-issues-risks-validation.md) §1 |
| App connects by raw IP, bypasses proxy | DNS-004 (FakeDNS / High Stealth) |

TUN and firewall checklist: [tun-operational-notes.md](tun-operational-notes.md).
