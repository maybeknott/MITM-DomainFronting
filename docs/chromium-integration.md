# Chromium and browser integration

## Purpose

This guide covers how Chromium-based clients connect to MITM-DomainFronting, how to
run **diagnostics** vs **stealth** browser paths, and how **profile-scoped trust**
reduces machine-wide Certificate Authority (CA) footprint.

**Scope:** browser launch, proxy wiring, certificate trust, QUIC hardening, and
telemetry JSON from integration scripts. It does not document Xray routing rules —
see [routing-correctness.md](routing-correctness.md) for loopback deadlock avoidance.

**Out of scope:** CloakBrowser upstream patches (see project README on CloakBrowser).

---

## How traffic flows

MITM-DomainFronting exposes a local proxy at **`127.0.0.1:10808`** (`mixed-in`).
Browsers do not need to know about decrypt ports (`11666` / `11777`) or domain-fronting
outbounds — only the proxy endpoint.

```text
+------------------------------------------------------------------+
|  APPLICATION LAYER                                               |
|  Diagnostics: stock Chromium (Playwright)                        |
|  Stealth:     CloakBrowser — canvas, WebGL, webdriver evasion     |
+------------------------------------------------------------------+
                              |  SOCKS5 / HTTP CONNECT
                              v
+------------------------------------------------------------------+
|  TRANSPORT — Xray (sole live data plane)                         |
|  mixed-in :10808 → routing → tls-decrypt-* → tls-repack-*        |
+------------------------------------------------------------------+
                              v
                     Remote CDN / service
```

| Layer | Owner | Live bytes? |
|---|---|---|
| Browser fingerprint / bot evasion | CloakBrowser (stealth path only) | Browser → proxy |
| TLS MITM, SNI camouflage, fronting | **Xray** | Yes |

---

## Two browser paths

| Path | When to use | Engine | Script |
|---|---|---|---|
| **Diagnostics** | Verify proxy, CA trust, DNS, page load | Stock Chromium (Playwright) | `scripts/browser_diagnostics.py` |
| **Stealth** | Anti-bot, CAPTCHA, fingerprint checks **after** diagnostics pass | [CloakBrowser](https://github.com/CloakHQ/CloakBrowser) | `scripts/browser_stealth.py` |

Settings: `configs/browser-integration.json`.

**Rules:**

- Do not use diagnostics Chrome to judge anti-bot success.
- Do not expect CloakBrowser to fix broken Xray routes, missing CA trust, or QUIC leaks.

---

## Certificate trust (ADR-0002 summary)

**Policy:** never install a MITM root CA silently. System-wide install requires explicit
operator action via `scripts/mitm_trust.py`.

| Mode | Forensic footprint | Status |
|---|---|---|
| **OS-wide CA** | Windows CryptoAPI / macOS Keychain entry | Shipped — opt-in with guides |
| **Profile-scoped** | Trust only in isolated browser profile | Shipped — CDP assist + manual import |
| **Covert hooking** | `LD_PRELOAD`, DLL injection, mmap `cert9.db` | **Rejected** — EDR-visible |

### Profile-scoped trust (shipped)

Launch Chromium in an isolated profile and apply trust **inside that profile only**
(via Chrome DevTools Protocol (CDP) broker or documented manual import):

```powershell
chrome.exe --remote-debugging-port=9222 `
  --user-data-dir=$env:LOCALAPPDATA\MITM-DF\ephemeral-profile `
  --disable-background-networking `
  --proxy-server=socks5://127.0.0.1:10808
```

**CDP workflow** (owner: `scripts/core/trust_broker.py` + `scripts/core/cdp_client.py`):

1. Read WebSocket URL from `http://127.0.0.1:9222/json/version`.
2. CDP assist opens `chrome://settings/security` in the isolated profile (GUI **Launch isolated Chromium** or `mitm_trust cdp-assist`).
3. Operator imports `mycert.crt` manually for that profile only.
4. On session end: close browser; optionally delete the ephemeral profile directory.

**Verify system store stays clean** (profile-scoped mode):

```powershell
Get-ChildItem Cert:\LocalMachine\Root\ | Where-Object { $_.Subject -match "MITM" }
# Expect: zero matches
py -3 scripts\mitm_trust.py status --json
```

**Firefox:** dedicated profile with user-guided import into `cert9.db` — not covert
SQLite patching.

Full policy: [reference/02-decisions-evasion-engineering.md](reference/02-decisions-evasion-engineering.md) (ADR-0002).

---

## Prerequisites

1. Xray running with `Xray-config/MITM-DomainFronting.json` imported.
2. Local CA generated (`certificate_generator.bat` / `.sh`) and trusted as needed —
   [ca-install-guide.md](ca-install-guide.md).
3. Preflight passes:

```powershell
python scripts\preflight.py --config Xray-config\MITM-DomainFronting.json --cert Xray-config\mycert.crt --key Xray-config\mycert.key
```

Listener details: [listener-binding.md](listener-binding.md).

---

## Path 1 — Diagnostics (stock Chromium)

**Use when:** confirming `mixed-in`, certificate trust, and that a target URL loads.

**Install:**

```powershell
pip install -r requirements-browser-diagnostics.txt
playwright install chromium
```

On Linux, if libraries are missing: `playwright install-deps chromium`.

**Run:**

```powershell
python scripts\browser_diagnostics.py --url https://example.com
```

Optional system Chrome:

```powershell
python scripts\browser_diagnostics.py --url https://example.com --executable "C:\Program Files\Google\Chrome\Application\chrome.exe"
```

**Helper script:**

```powershell
.\scripts\launch_browser_mitm.ps1 -Mode Diagnostics -Url https://example.com
```

Diagnostics may use `ignore_https_errors` when the MITM CA is not in the OS store.
For realistic trust behavior, install `mycert.crt` or use profile-scoped trust.

---

## Path 2 — Stealth (CloakBrowser)

**Use when:** bot detection, Turnstile, reCAPTCHA v3, or fingerprint checks — **after**
diagnostics is green.

**Install:**

```powershell
pip install -r requirements-browser-stealth.txt
python -m cloakbrowser install
```

**Run:**

```powershell
python scripts\browser_stealth.py --url https://example.com
```

Recommended flags for protected sites:

```powershell
python scripts\browser_stealth.py --url https://target.example --geoip --fingerprint-seed 42069
```

**Measure TLS fingerprint** (optional — requires a trusted JA3 oracle):

```powershell
python scripts\browser_stealth.py --url https://target.example `
  --ja3-oracle-url https://tls.peet.ws/api/all --expected-ja3 <known-ja3-or-md5>
```

Without `--ja3-oracle-url`, `tls_fingerprint_ja3_matches_browser` stays `null` with
`verification_method: "not_measured"` — the probe never fabricates a green TLS match.

Default proxy: `socks5://127.0.0.1:10808`. HTTP proxy on the same port also works.

```powershell
.\scripts\launch_browser_mitm.ps1 -Mode Stealth -Url https://example.com
```

CloakBrowser owns application-layer evasion; MITM-DomainFronting owns TLS interception
and domain fronting on the Xray path.

---

## Transport hardening (both paths)

Chromium may bypass a TCP proxy via QUIC/UDP. Both scripts pass:

- `--disable-quic`
- `--disable-udp-proxies`

Align with [configs/protocols.yml](../configs/protocols.yml) and strict Xray profiles
that block UDP/443 when needed. WebRTC Session Traversal Utilities for NAT (STUN)
leaks are a separate class — see [protocol-coverage.md](protocol-coverage.md) and
High Stealth TUN notes in [tun-operational-notes.md](tun-operational-notes.md).

---

## Script telemetry JSON

Scripts print one JSON object to stdout with:

- `mode`, `runtime_environment`, `network_telemetry`
- `engine_capabilities` — what stealth is **configured** to do
- `fingerprint_validation` — what was **measured** against an external oracle
- `execution_state`

Use diagnostics output for proxy/CA issues; use stealth output only after diagnostics passes.

---

## Loopback routing deadlock

Traffic from `tls-decrypt-google-h11`, `tls-decrypt-google-h2`, `tls-decrypt-fastly-h2`,
or `tls-decrypt-meta-h2` must **not** route back into `mixed-in`. Shipped configs use
`inboundTag`-scoped repack rules and isolated `redirect-out-*` loopback ports —
[routing-correctness.md](routing-correctness.md).

---

## Profile directories

| Path | Role |
|---|---|
| `browser-profiles/diagnostics-playwright` | Diagnostics sessions |
| `browser-profiles/stealth-cloakbrowser` | CloakBrowser persistent profile |

Both are gitignored. Delete to reset HSTS, cookies, and Alt-Svc state.

---

## Common mistakes

| Hazard | Wrong approach |
|---|---|
| Broken MITM / wrong SNI | Rely on CloakBrowser only |
| Bot block on target site | Use diagnostics Chrome only |
| QUIC leak outside proxy | Omit `--disable-quic` / UDP policy |
| Infinite Xray loop | Route decrypt inbound traffic back to `mixed-in` |
| Machine-wide CA IoC | Silent or undocumented system trust install |

---

## Related documents

| Topic | Document |
|---|---|
| CA install / remove | [ca-install-guide.md](ca-install-guide.md), [ca-remove-guide.md](ca-remove-guide.md) |
| Runtime architecture | [reference/01-architecture-runtime-delivery.md](reference/01-architecture-runtime-delivery.md) §2 |
| Known browser issues | [reference/03-issues-risks-validation.md](reference/03-issues-risks-validation.md) §1 |
