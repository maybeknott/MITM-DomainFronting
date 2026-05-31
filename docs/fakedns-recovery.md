# FakeDNS Recovery

## Problem

FakeDNS can leave stale fake IP mappings in OS or browser DNS caches after the client stops. This can make normal internet access look broken until caches are cleared.

## Safe disable sequence

1. Stop browser tabs using the method.
2. Stop v2rayN/v2rayNG/Xray.
3. Disable system proxy or TUN/VPN mode.
4. Flush OS DNS cache.
5. Restart browser.
6. If still broken, reboot network interface or device.

## Windows

```powershell
ipconfig /flushdns
```

Restart browser. If system proxy was enabled, disable it in Windows proxy settings or the client UI.

## macOS

Common command:

```bash
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder
```

Restart browser.

## Linux

Systemd-resolved:

```bash
resolvectl flush-caches
```

If using NetworkManager:

```bash
sudo systemctl restart NetworkManager
```

Restart browser.

## Android

1. Stop the VPN/TUN client.
2. Toggle airplane mode on and off.
3. Clear browser DNS/cache if needed.
4. Reboot if stale mapping persists.

## Browser-level flush

Chromium-based browsers may also keep host cache. Restart the browser completely. If needed, use the browser's internal DNS/host cache page for your version.

## Verification

After flushing, run:

```bash
python scripts/check_dns.py --domain example.com
```

Then open a normal non-target site without the method enabled.
