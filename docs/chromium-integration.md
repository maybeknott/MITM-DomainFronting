# Chromium integration (two-part model)

MITM-DomainFronting exposes a normal local proxy on `127.0.0.1:10808` (`mixed-in`). Any Chromium-based client only needs that endpoint; it does not need to understand Xray routing, loopback decrypt ports (`11666` / `11777`), or domain-fronting outbounds.

This repository separates **two browser roles**:

| Path | Purpose | Default engine | Script |
|------|---------|----------------|--------|
| **Diagnostics** | Verify proxy wiring, CA trust, DNS/routing, page load | Stock Chromium via Playwright (optional system Chrome/Edge) | `scripts/browser_diagnostics.py` |
| **Stealth** | Application-layer fingerprint and anti-bot / CAPTCHA evasion | [CloakBrowser](https://github.com/CloakHQ/CloakBrowser) | `scripts/browser_stealth.py` |

Do **not** use the diagnostics browser to judge anti-bot success. Do **not** expect CloakBrowser to fix broken Xray routes, missing CA trust, or QUIC leakage by itself.

Settings live in `configs/browser-integration.json`.

## Runtime graph

```text
+------------------------------------------------------------------+
|  APPLICATION LAYER                                               |
|  Diagnostics: stock Chrome / Playwright                          |
|  Stealth:     CloakBrowser (default) — canvas, WebGL, webdriver… |
+------------------------------------------------------------------+
                              |
                              |  HTTP CONNECT / SOCKS5
                              v
+------------------------------------------------------------------+
|  TRANSPORT LAYER — MITM-DomainFronting (Xray)                    |
|  mixed-in :10808 → routing → 11666/11777 decrypt → tls-repack     |
+------------------------------------------------------------------+
                              |
                              v
                     Remote CDN / service
```

See also [`architecture.md`](architecture.md) and [`listener-binding.md`](listener-binding.md).

## Prerequisites

1. Xray (or v2rayN) running with `MITM-DomainFronting.json` imported.
2. Local CA generated (`certificate_generator.bat` / `.sh`) and trusted where needed — see [`ca-install-guide.md`](ca-install-guide.md).
3. Preflight passes:

```powershell
python scripts\preflight.py --config Xray-config\MITM-DomainFronting.json --cert Xray-config\mycert.crt --key Xray-config\mycert.key
```

## Path 1 — Diagnostics (stock Chromium)

**Use when:** confirming `mixed-in`, certificate trust, and that a target URL loads through the tunnel.

**Install:**

```powershell
pip install -r requirements-browser-diagnostics.txt
playwright install chromium
```

On Linux, if system libraries are missing, also run `playwright install-deps chromium`.

**Run:**

```powershell
python scripts\browser_diagnostics.py --url https://example.com
```

Optional system Chrome instead of bundled Chromium:

```powershell
python scripts\browser_diagnostics.py --url https://example.com --executable "C:\Program Files\Google\Chrome\Application\chrome.exe"
```

**Manual launch (PowerShell):**

```powershell
.\scripts\launch_browser_mitm.ps1 -Mode Diagnostics -Url https://example.com
```

Diagnostics enables `ignore_https_errors` for automation when the MITM CA is not in the OS store. Prefer installing `mycert.crt` for realistic trust behavior (`scripts\mitm_trust.py status`).

## Path 2 — Stealth (CloakBrowser, default)

**Use when:** exercising sites with bot detection, Turnstile, reCAPTCHA v3 scoring, or fingerprint checks — **after** diagnostics passes.

**Install:**

```powershell
pip install -r requirements-browser-stealth.txt
python -m cloakbrowser install
```

Upstream project: **https://github.com/CloakHQ/CloakBrowser**

**Run:**

```powershell
python scripts\browser_stealth.py --url https://example.com
```

Recommended flags for protected sites (still route through local MITM proxy):

```powershell
python scripts\browser_stealth.py --url https://target.example --geoip --fingerprint-seed 42069
```

Proxy default: `socks5://127.0.0.1:10808` (matches `mixed-in`). HTTP proxy `http://127.0.0.1:10808` also works.

**Manual launch helper:**

```powershell
.\scripts\launch_browser_mitm.ps1 -Mode Stealth -Url https://example.com
```

CloakBrowser applies source-level Chromium patches; MITM-DomainFronting still owns TLS interception and domain fronting. Configure evasion in CloakBrowser **before** relying on the Xray path.

## Transport hardening (both paths)

Chromium may bypass a TCP proxy via QUIC/UDP. Both integration scripts pass:

- `--disable-quic`
- `--disable-udp-proxies`

Align with [`configs/protocols.yml`](../configs/protocols.yml) and strict Xray profiles that block UDP/443 when needed.

## Telemetry JSON

Scripts print a single JSON object (stdout) with `mode`, `runtime_environment`, `network_telemetry`, `fingerprint_validation`, and `execution_state`. Use diagnostics output to debug proxy/CA; use stealth output only after diagnostics is green.

## Loopback routing deadlock

Traffic leaving `tls-decrypt-h11` / `tls-decrypt-h211` must not be routed back into `mixed-in`. Shipped configs use `inboundTag`-scoped repack rules and `redirect-out-h*` → loopback ports — see [`routing-correctness.md`](routing-correctness.md).

## Profile directories

| Path | Role |
|------|------|
| `browser-profiles/diagnostics-playwright` | Diagnostics sessions |
| `browser-profiles/stealth-cloakbrowser` | CloakBrowser persistent profile |

Both are gitignored. Delete them to reset HSTS, cookies, and Alt-Svc state.

## What each layer must not do

| Hazard | Wrong approach |
|--------|----------------|
| Broken MITM / wrong SNI | Rely on CloakBrowser only |
| Bot block on target site | Use diagnostics Chrome only |
| QUIC leak outside proxy | Omit `--disable-quic` / UDP policy |
| Infinite Xray loop | Route decrypt inbound traffic back to `mixed-in` |
