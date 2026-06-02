# ADR 0003: Browser Proxy First

## Status

Accepted.

## Context

The project supports browser diagnostics and optional fingerprint checks. OS-wide proxy or TUN changes are higher-risk and harder to reason about for newcomers.

## Decision

The default diagnostic path is an explicit browser proxy against the local Xray listener. TUN and OS proxy state are detected or documented, not silently changed.

## Consequences

- Page Check should run before advanced fingerprint checks.
- CloakBrowser is an app-layer fingerprint path, not a routing engine.
- System proxy and TUN states are warnings/context unless the user intentionally configures them.
