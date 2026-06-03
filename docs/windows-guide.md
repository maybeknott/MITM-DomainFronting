# Windows Guide

## Purpose

Run the documented Windows path with v2rayN and Xray: generate or install the local CA, import the primary config, run preflight, and validate browser integration through diagnostics or stealth launchers.

## Steps

1. Download/extract v2rayN with Xray core.
2. Place `certificate_generator.bat` in the folder where `xray.exe` is available.
3. Run `certificate_generator.bat`.
4. Confirm `mycert.crt` and `mycert.key` exist.
5. Install `mycert.crt` in the intended trust store.
6. Import `MITM-DomainFronting.json` into v2rayN.
7. Ensure core type is Xray.
8. Ensure local proxy port behavior matches the config.
9. Run preflight:

```powershell
python scripts\preflight.py --config Xray-config\MITM-DomainFronting.json --cert Xray-config\mycert.crt --key Xray-config\mycert.key
```

## Browser integration (two paths)

| Path | When to use | Command |
|------|-------------|---------|
| **Diagnostics** | Proxy, CA, and page load checks | `python scripts\browser_diagnostics.py --url https://example.com` |
| **Stealth (default)** | Anti-bot / fingerprint / CAPTCHA flows | `pip install -r requirements-browser-stealth.txt` then `python scripts\browser_stealth.py --url …` |

Stealth uses [CloakBrowser](https://github.com/CloakHQ/CloakBrowser) by default; diagnostics uses stock Chrome/Playwright. Both send traffic to `socks5://127.0.0.1:10808`. See [`chromium-integration.md`](chromium-integration.md).

```powershell
.\scripts\launch_browser_mitm.ps1 -Mode Diagnostics -Url https://example.com
.\scripts\launch_browser_mitm.ps1 -Mode Stealth -Url https://example.com
```

## Common failures

| Symptom | Cause | Fix |
|---|---|---|
| `xray.exe not found` | generator not in correct folder | Put script next to xray or add xray to PATH |
| Browser privacy error | CA not installed or wrong CA | Verify fingerprint and reinstall |
| Port conflict | another app uses 10808/11666/11777 | Stop other app or adjust config carefully |
| Works in Chrome but not Firefox | browser trust mismatch | Import CA into Firefox or configure OS trust usage |
| LAN can reach port | listener not loopback/firewall issue | Add explicit `listen: 127.0.0.1` and check firewall |

## Related documents

| Document | Topic |
|---|---|
| [`ca-install-guide.md`](ca-install-guide.md) | Windows CA install |
| [`chromium-integration.md`](chromium-integration.md) | Browser diagnostics and stealth |
| [`preflight-and-diagnostics.md`](preflight-and-diagnostics.md) | Preflight checks |
| [`listener-binding.md`](listener-binding.md) | Loopback port verification |
