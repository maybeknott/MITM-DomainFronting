# Local Activity History

The Control Center records local activity history to help users explain what happened during setup and troubleshooting.

## Scope

Activity history is local-only and written under `.local-state/`, which is ignored by git.

It may include:

- GUI startup and status changes;
- command labels, exit codes, and durations;
- local listener state such as whether `127.0.0.1:10808` accepts connections;
- file-presence booleans for config, certificate, key, profiles, and local tools;
- redacted status snapshots.

It must not include:

- private keys or certificate key material;
- request or response bodies;
- cookies, tokens, account identifiers, or credentials;
- decrypted payloads;
- automatic uploads or remote reporting.

## Files

```text
.local-state/gui-telemetry.jsonl
.local-state/gui-telemetry-export.diagnostic.json
```

The JSONL file is append-only during normal GUI use. The export file is created only when the user clicks **Export Activity**.

## GUI Controls

The **Dashboard** screen shows a right-side **Live Telemetry** rail:

- **Downlink** and **Uplink**: local OS network rates with compact sparklines;
- **Connections**: GUI/core activity stream count;
- **Requests**: local GUI activity event count;
- **Blocked**: failed/blocked/error activity events;
- **Local & Private**: a visible reminder that telemetry stays on the device;
- **Quick Actions**: opens logs, finds actions, resets statistics, or refreshes status.

The detailed activity actions are still available from the command palette and related tools:

- **Run Full Status**: records a redacted status snapshot and prints it in the local output pane;
- **Show Activity**: prints the most recent local GUI events;
- **Export Activity**: writes a local diagnostic JSON file for review before sharing;
- **Clear Activity**: removes the local GUI activity file.

Clearing activity history does not change configs, certificates, trust stores, or running Xray processes.
