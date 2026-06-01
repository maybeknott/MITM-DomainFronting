# Local Status and Telemetry

The Control Center records local operational telemetry to help users explain what happened during setup and troubleshooting.

## Scope

Telemetry is local-only and written under `.local-state/`, which is ignored by git.

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

The JSONL file is append-only during normal GUI use. The export file is created only when the user clicks **Export Telemetry**.

## GUI Controls

The Dashboard includes:

- **Run Full Status**: records a redacted status snapshot and prints it in the local output pane;
- **Show Telemetry**: prints the most recent local GUI events;
- **Export Telemetry**: writes a local diagnostic JSON file for review before sharing;
- **Clear Telemetry**: removes the local GUI telemetry file.

Clearing telemetry does not change configs, certificates, trust stores, or running Xray processes.
