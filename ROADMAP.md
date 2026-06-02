# Roadmap And Gap Tracker

This file tracks product coherence work that should remain visible between releases.

## Completed

- Shared `ProjectState`, `CheckResult`, and `RepairAction` readiness layer.
- `main.py probe` emits shared readiness state.
- GUI dashboard consumes readiness state for next action, safety banner, and status cards.
- Unsafe external listener detection is visible in CLI and GUI.
- Python regression tests moved to `tests/python/`.
- Release ZIP verifier added and wired into the GUI release workflow.
- Maintainer map and ADRs added.

## Next

- Extract more of `scripts/gui.py` into focused GUI modules.
- Add a guided trust checklist panel backed by shared readiness fields.
- Add explicit JA3 oracle fields and measured-vs-configured UI.
- Add `verified-session` evidence bundle command.
- Add release artifact verifier output to release notes.
- Consolidate CA docs into a single certificate reference.
- Consolidate DNS/profile/protocol docs into a single network-model reference.
- Add JSON schemas for `configs/`, `providers/`, and `config-src/`.

## Open Gaps

| Gap | Desired Outcome | Current Status |
|---|---|---|
| Per-process telemetry | Show app-owned Xray counters separately from system counters | System counters are labeled; per-process telemetry not implemented |
| JA3 oracle workflow | User enters oracle URL and expected hash; app records measured result | Readiness model supports fields; GUI flow not complete |
| Verified runtime session | One command saves redacted runtime evidence | Planned |
| Docs consolidation | Fewer first-contact docs, stronger reference docs | Started with Farsi quick start, ADRs, maintainer map |
| GUI modularization | `scripts/gui.py` becomes a small entrypoint | Started with `scripts/core/gui_readiness.py` |
