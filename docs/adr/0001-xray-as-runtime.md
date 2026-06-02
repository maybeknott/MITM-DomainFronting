# ADR 0001: Xray Is The Runtime Source Of Truth

## Status

Accepted.

## Context

The project contains Python diagnostics, GUI orchestration, generated profiles, and Rust validation experiments. Without a clear boundary, these pieces can look like competing runtimes.

## Decision

Xray remains the actual runtime for proxying, routing, MITM, domain-fronting, and uTLS fingerprint behavior. Python, GUI, config-src, tests, and Rust validate, generate, observe, or assist around Xray.

## Consequences

- Runtime behavior must be proven against generated Xray configs.
- Rust code is validation/experimental unless explicitly promoted later.
- Native Xray-core integration is deferred until a feature is stable enough to justify a Go/Xray-core implementation.
