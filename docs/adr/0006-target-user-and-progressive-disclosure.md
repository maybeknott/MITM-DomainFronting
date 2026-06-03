# ADR 0006: Target User And Progressive Disclosure

## Status

Accepted.

## Context

Recurring product feedback asks the project to "reduce end-user complexity" and
repeatedly poses the same unanswered question:

> Are we optimizing for completely non-technical users who just want an On/Off
> switch, or intermediate users who still need control over routing profiles?

That question must be answered explicitly, because it constrains every UX and
distribution decision (preset toggles, auto-setup, error messages, packaging).
Leaving it implicit causes proposals to swing between "hide everything behind one
switch" and "expose every knob", which are contradictory.

The repository already encodes three relevant guardrails:

- ADR-0001: Xray is the runtime source of truth.
- ADR-0002: No silent trust-store installation; the private key stays local.
- ADR-0003: Browser-proxy-first; OS proxy/TUN state is detected, not changed.

A "make it a single On/Off switch that silently trusts a CA and auto-elevates to
admin" direction would violate ADR-0002 and the project's honesty posture, even
though it would feel simpler.

## Decision

The primary user is the **motivated intermediate user**: someone comfortable
running a desktop app and following a short guided flow, who needs the tool to be
safe and legible but does **not** want to hand-edit Xray JSON or memorize CLI
flags.

We optimize for this user via **progressive disclosure**, not via a single
opaque switch:

1. **One dominant next action.** The dashboard always shows the single best next
   step derived from `ProjectState.next_action`. This is the "simple path".
2. **Named intents over raw files.** Operating profiles are surfaced as
   Standard (balanced) / High Stealth (strict) / Legacy Network (compatibility),
   bound to `ProjectState.active_profile` — never as a file picker.
3. **Guided, consent-based setup.** Auto-setup may generate the local CA, run
   preflight, and offer fixes, but trust installation and privilege elevation
   remain explicit, user-approved steps (ADR-0002). "Zero-touch" means
   "zero-guesswork", not "silent system changes".
4. **Plain-language status, evidence on demand.** Failures are shown through the
   failure classifier's friendly summaries; the raw evidence, check IDs, and the
   `verified-session` bundle are available behind an "advanced/details" affordance
   for the operator and maintainer tiers.

We explicitly **defer** the "pure On/Off appliance for fully non-technical users"
product. It would require silent trust handling we have ruled out, and a
different threat-model conversation. It is out of scope unless a future ADR
revisits ADR-0002.

## Consequences

- Preset toggle work (proposal idea #1) targets `active_profile`, with a short
  inline description per intent rather than a configuration dialog.
- Auto-setup work (proposal idea #2) is allowed to *prepare and recommend* but
  must route trust install / admin elevation through an explicit confirmation,
  reusing the existing `RepairAction.requires_admin` / `confirmation_required`
  flags.
- The failure classifier (idea #3) and single-binary distribution (idea #4) are
  already aligned with this user and need no demographic change.
- "Advanced" surfaces (full check list, JA3 oracle fields, evidence bundles,
  release tooling) stay available but are not the default view.
- Large supercomposition rewrites (PyO3 embedding, Cap'n Proto IPC, Tauri/Slint,
  io_uring/eBPF, embedding Rust into Xray) remain out of scope: they raise, not
  lower, complexity and risk for the intermediate user, and conflict with
  ADR-0001/0003.
