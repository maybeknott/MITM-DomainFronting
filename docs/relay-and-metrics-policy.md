# Relay and Metrics Policy

The current project is local-first. Relay and metrics support are not enabled by default and must stay constrained if added later.

## Relay Policy

Relay profiles must satisfy all of these requirements:

- disabled by default;
- owned or explicitly authorized infrastructure only;
- no public open relay defaults;
- authentication required;
- owner metadata required;
- no payload logging;
- clear allowed-use statement;
- rollback instructions.

The schema lives in [relay-profiles.yml](../configs/relay-profiles.yml). CI validates the guardrails before any relay profile can be added.

## Metrics Policy

Metrics/debug profiles must be local-only and redacted.

Allowed examples:

- route tag;
- check ID;
- status;
- elapsed milliseconds;
- resolver tag;
- selected profile.

Forbidden examples:

- private keys;
- cookies;
- authorization headers;
- request or response bodies;
- full URLs with tokens;
- decrypted payloads.

The schema lives in [metrics-profiles.yml](../configs/metrics-profiles.yml). Debug data should help explain behavior without collecting user traffic.
