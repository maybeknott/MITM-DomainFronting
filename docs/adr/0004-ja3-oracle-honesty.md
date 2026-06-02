# ADR 0004: JA3 Oracle Required For Measured Fingerprint Claims

## Status

Accepted.

## Context

Xray can be configured with `tlsSettings.fingerprint: "chrome"`, but that is not the same as externally measured JA3 proof.

## Decision

The app may say a TLS fingerprint is configured when the Xray config sets it. It may only claim a measured JA3 match when an external JA3 oracle returns matching evidence.

## Consequences

- Without an oracle URL and expected value, JA3 status remains `not measured`.
- GUI/docs must distinguish configured uTLS behavior from measured TLS fingerprint evidence.
- Browser fingerprint checks and TLS fingerprint checks remain separate concepts.
