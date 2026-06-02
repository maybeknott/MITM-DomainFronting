# ADR 0005: Local Source-Labeled Telemetry

## Status

Accepted.

## Context

The GUI shows network and activity telemetry. Some telemetry is system-wide while future telemetry may be app- or process-specific.

## Decision

Telemetry must stay local and must label its source, scope, and confidence. System counter telemetry must not be presented as per-Xray telemetry.

## Consequences

- The right rail can show rates, totals, and running time, but labels must clarify measurement scope.
- Future per-process or Xray-log telemetry should be shown as a distinct source.
- No automatic upload of telemetry is allowed.
