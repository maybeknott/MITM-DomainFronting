# Troubleshooting guide

## Purpose

Symptom-oriented fixes for local MITM-DomainFronting setup. All steps are **on your machine**; nothing here uploads data or changes trust/proxy settings silently.

For automated triage first:

```powershell
py -3 main.py advise --text
py -3 main.py probe --json
```

See also [preflight-and-diagnostics.md](preflight-and-diagnostics.md) and [intelligent-automation.md](intelligent-automation.md).

## Quick decision tree

```text
Page won't load?
  ├─ No listener on proxy port → Start Core or open v2rayN
  ├─ Certificate warning in browser → Generate CA + manual trust install
  ├─ Proxy unreachable → Check 127.0.0.1:10808 and browser proxy setting
  └─ Still failing → Health Probe + Copy Issue Summary (GUI)

CI / maintainer failures?
  ├─ Profile drift → generate_profiles.py + commit JSON
  ├─ config-src → config_src_validate.py --run-steps
  └─ release-check → main.py release-check

Lab / DPI labels in decision report?
  └─ lab-prepare + evasion profiles (controlled lab only)
```

## Symptom table

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| Browser shows certificate error | CA not in trust store | [ca-install-guide.md](ca-install-guide.md); GUI **Generate Local CA** then install trust manually |
| `NET::ERR_PROXY_CONNECTION_FAILED` | Nothing listening on proxy port | **Start Core** or start v2rayN; confirm port in [listener-binding.md](listener-binding.md) |
| Page Check fails immediately | Playwright missing | Install via GUI Repair or `requirements-browser-diagnostics.txt` |
| GUI shows **Unsafe listener exposed** | External core bound to `0.0.0.0` | Rebind v2rayN/Xray inbound to `127.0.0.1` only |
| `cert/key mismatch` | Wrong pair of files | Regenerate CA; do not mix others' `.crt`/`.key` |
| Strict sites still break | ECH, pinning, or non-browser app | Expected limit — see [protocol-coverage.md](protocol-coverage.md) |
| QUIC-only site behaves oddly | UDP/443 policy | Try **debug** profile or document QUIC limitation |
| DNS works but wrong IP | Resolver drift or hijack | [dns-resilience.md](dns-resilience.md); DNS check in GUI |
| `generated profiles out of sync` (CI) | JSON not regenerated after base config change | `py -3 scripts/generate_profiles.py --base Xray-config/MITM-DomainFronting.json` |
| Advisor suggests evasion profile | Failure labels in decision report | Lab-only — see [operating-profiles.md](operating-profiles.md) optional lab section |
| eBPF loader fails on Windows | Linux-only feature | Normal; smoke uses simulate mode on non-Linux |

## CLI diagnostics (copy-paste)

```powershell
# Minimal newcomer sweep
py -3 main.py onboard --dry-run
py -3 main.py onboard

# Deep static check (no live DNS)
py -3 scripts/preflight.py --config Xray-config/MITM-DomainFronting.json --no-dns --skip-cert --skip-runtime

# Unified health JSON
py -3 scripts/health_probe.py --config Xray-config/MITM-DomainFronting.json --cert Xray-config/mycert.crt --key Xray-config/mycert.key --providers-dir providers

# Redacted support bundle
py -3 scripts/decision_report.py --config Xray-config/MITM-DomainFronting.json --profile balanced
```

## What to attach when asking for help

Include only **redacted** artifacts:

- OS and Python version
- Xray version (from GUI or `xray version`)
- Config `remarks` field (not full secrets)
- Output of `main.py probe --json` after removing paths you do not want to share
- Preflight or health probe JSON (review first)
- Whether issue is browser-only or system-wide

Do **not** attach: `mycert.key`, cookies, Authorization headers, full browsing history, or raw PCAP with credentials.

## Related documents

| Document | Topic |
|----------|--------|
| [getting-started.md](getting-started.md) | First-time setup |
| [gui.md](gui.md) | Control Center workflow |
| [decision-engine.md](decision-engine.md) | Decision report format |
| [lab-evidence-checklist.md](lab-evidence-checklist.md) | Lab scenarios |
