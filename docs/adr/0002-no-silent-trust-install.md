# ADR 0002: No Silent Trust-Store Installation

## Status

Accepted.

## Context

The project creates local CA material for browser MITM diagnostics. Installing trust silently would be risky and surprising.

## Decision

The app may generate local certificate files and show instructions, but it must not silently install a CA into Windows, browser, or machine trust stores.

## Consequences

- Trust setup remains explicit and user-controlled.
- GUI and CLI should report trust state and recommended next action.
- Any future trust-changing action must require clear confirmation and must explain system impact.
