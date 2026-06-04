# Local activity history (GUI telemetry)

## Purpose

The Control Center records **local-only** activity history so operators can explain
what happened during setup and troubleshooting. This is **not** remote telemetry —
nothing is uploaded automatically (ADR-0005).

**Forensic note:** persistent disk history can be an operational security (OPSEC)
concern on hostile hosts. Users may **Clear Activity** or delete the jsonl file;
Track D will add optional retention caps and clear-on-exit for High Stealth mode.

---

## Scope

### Recorded (local disk under `.local-state/`)

- GUI startup and status changes
- Command labels, exit codes, and durations
- Whether `127.0.0.1:10808` accepts connections
- File-presence booleans for config, certificate, key, profiles, and local tools
- Redacted status snapshots

### Never recorded

- Private keys or certificate key material
- Request or response bodies
- Cookies, tokens, account identifiers, or credentials
- Decrypted payloads
- Automatic uploads or remote reporting

---

## Files

```text
.local-state/gui-telemetry.jsonl          # append-only during GUI use (gitignored)
.local-state/gui-telemetry-export.diagnostic.json   # created only on Export Activity
```

Clearing activity history does **not** change configs, certificates, trust stores, or
running Xray processes.

---

## GUI controls

**Dashboard — Live Telemetry rail**

| Control | Meaning |
|---|---|
| Downlink / Uplink | Local OS network rates with sparklines |
| Connections | GUI/core activity stream count |
| Requests | Local GUI event count |
| Blocked | Failed/blocked/error events |
| Local & Private | Reminder that data stays on device |

**Actions** (command palette and related tools)

| Action | Effect |
|---|---|
| Run Full Status | Redacted snapshot in local output pane |
| Show Activity | Recent GUI events |
| Export Activity | Writes diagnostic JSON for manual review before sharing |
| Clear Activity | Removes `gui-telemetry.jsonl` |

---

## OPSEC modes

| Setting | Standard default | High Stealth OPSEC (shipped) |
|---|---|---|
| Retention | Append until user clears | RAM-only — no jsonl append when enabled |
| On exit | File persists | Optional clear-on-exit preference |
| Export | User-initiated only | Same — never silent upload |
| Labels | `source: local-gui` on every record | Unchanged |

Toggle in GUI Settings: **OPSEC mode (RAM-only telemetry)**. Implementation:
`scripts/gui.py` + `scripts/core/gui_preferences.py`.

---

## What writes disk

| Module | Writes telemetry to disk? | Notes |
|---|---|---|
| `scripts/core/failure_classifier.py` | **No** | In-memory `ProbeResult` only |
| `scripts/decision_report.py` | **Opt-in** | Only with `--json-out <path>` |
| `scripts/gui.py` | **Yes** | Appends to `.local-state/gui-telemetry.jsonl` |
| `scripts/build_config.py` | **Yes** | Writes `Xray-config/*.json` — expected build artifact |

---

## Forensic validation procedure

1. Delete `.local-state/gui-telemetry.jsonl` if present.
2. Run a GUI session: Start Core → browse one HTTPS site → Stop Core.
3. Inspect new files:

```powershell
Get-ChildItem -Recurse .local-state\
```

4. Confirm no unexpected probe log files appeared.
5. Before handing device to an inspector: **Clear Activity** or delete the jsonl file.

---

## Related documents

| Topic | Document |
|---|---|
| ADR-0005 policy detail | [reference/02-decisions-evasion-engineering.md](reference/02-decisions-evasion-engineering.md) (ADR-0005) |
| Known OPSEC issues | [reference/03-issues-risks-validation.md](reference/03-issues-risks-validation.md) §1 (OPSEC-*) |
| Threat model | [../THREAT_MODEL.md](../THREAT_MODEL.md) |
