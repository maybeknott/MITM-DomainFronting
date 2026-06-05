# Getting started (Xray-Cooperative-Overlay)

English walkthrough for first-time users. For a full doc map see [README.md](README.md). Farsi: [fa/quick-start.md](fa/quick-start.md).

## What this project does

You run a **local proxy** (Xray) on your machine. A browser you configure uses `127.0.0.1:10808`. HTTPS to that browser is decrypted with **your own** certificate (`mycert.crt` / `mycert.key`). Nothing is uploaded to a cloud service by default.

This is **not** a guarantee that every site or app will work. It is a lab-style setup for specific paths and networks.

## Glossary (30 seconds)

| Term | Meaning |
|------|---------|
| **Core** | Xray process serving the local inbound (often via v2rayN on Windows) |
| **Local CA** | Your `mycert.crt` / `mycert.key` pair for MITM in the browser |
| **Profile** | Generated JSON variant: `strict`, `balanced`, `compatibility`, `debug` |
| **Readiness** | Shared health model used by GUI and `main.py probe` |
| **Advisor** | Local recommendations from decision report + readiness (no upload) |
| **Evasion lab** | Optional `evasion-*` profiles for controlled DPI/lab work only |

## Fastest path (Windows)

1. Open the Control Center:

   ```powershell
   py -3 main.py gui
   ```

2. On **Dashboard**, read **New here?** or open **Getting Started** in the sidebar.

3. **Check Setup** — runs the same checks the CLI uses for readiness.

4. **Generate Local CA** — creates cert files only; you still install trust manually ([ca-install-guide.md](ca-install-guide.md)).

5. **Start Core** (or keep v2rayN/Xray already listening on the local port).

6. **Run Page Check** — confirms the browser can load a page through the proxy.

7. If something fails: **Logs & Health** → **Health Probe**, then **Copy Issue Summary**. Or open **Smart Tips** for ranked next steps.

### One-shot CLI onboarding

Runs validate → static preflight → probe → advisor without the GUI:

```powershell
py -3 main.py onboard --dry-run   # list steps only
py -3 main.py onboard             # execute newcomer playbook
```

Maintainers: `py -3 main.py onboard --persona maintainer`

## Typical workflow (after first success)

```text
Check Setup → Generate CA → install trust manually → Start Core → Page Check
     ↓ fail
Smart Tips / main.py advise --text → fix listener or CA → retry
     ↓ lab work only
lab-prepare + evasion profiles (see intelligent-automation.md)
```

## CLI map

| Goal | Command |
|------|---------|
| Guided sweep | `py -3 main.py onboard` |
| Static checks | `py -3 main.py audit` |
| Full offline suite | `py -3 main.py test` |
| What to do next | `py -3 main.py advise --text` |
| Readiness JSON | `py -3 main.py probe --json` |
| Lab artifacts | `py -3 main.py lab-prepare --allow-warn` |
| Release gate | `py -3 main.py release-check` |

The `probe` JSON includes an `intelligent` block (persona, recommendations, playbook). Plans are also saved to `.local-state/advisor-plan.latest.json` for GUI **Smart Tips**.

## Choosing an operating profile

| Profile | When to use |
|---------|-------------|
| `strict` | Maximum policy; may break more sites |
| `balanced` | Default daily use |
| `compatibility` | More permissive routing/DNS |
| `debug` | Diagnostics and verbose behavior |

Details: [operating-profiles.md](operating-profiles.md). After a successful run in the GUI, **Apply Recommended** can remember the winner in `.local-state/strategy-winner.json`.

## Safety rules (read once)

- Never share `mycert.key` or use someone else's certificate.
- The app does **not** silently install trust or change system proxy settings.
- Evasion lab profiles (`evasion-*`) are for **controlled lab** use only.
- Do not paste raw health JSON or PCAP into public tickets without redaction.

## Troubleshooting

Symptom → fix table: [troubleshooting.md](troubleshooting.md).

## Where to go next

| Topic | Document |
|-------|----------|
| Full doc index | [README.md](README.md) |
| GUI tour | [gui.md](gui.md) |
| Certificates | [ca-install-guide.md](ca-install-guide.md) |
| Browser setup | [chromium-integration.md](chromium-integration.md) |
| Profiles | [operating-profiles.md](operating-profiles.md) |
| Smart automation | [intelligent-automation.md](intelligent-automation.md) |
| Engineering index | [reference/00-engineering-handbook.md](reference/00-engineering-handbook.md) |
