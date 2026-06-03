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
- JA3 echo-oracle measurement wired into the stock-Chromium diagnostics probe
  (`--ja3-oracle` / `--expected-ja3`); result lands honestly in
  `fingerprint_validation` and stays `not_measured` without an oracle.
- `verified-session` evidence bundle command added
  (`py -3 main.py verified-session`) that composes the shared readiness state,
  an optional page check, and an optional JA3 oracle into one redacted
  `runtime-evidence.json` (config/profile hashes, listener/trust/cert evidence,
  PID dropped, root redacted).

## Next

- Extract more of `scripts/gui.py` into focused GUI modules.
- Add a guided trust checklist panel backed by shared readiness fields.
- Surface JA3 oracle fields and `verified-session` in the GUI (CLI path done).
- Add `verified-session` evidence output to release notes.
- Consolidate CA docs into a single certificate reference.
- Consolidate DNS/profile/protocol docs into a single network-model reference.
- Add JSON schemas for `configs/`, `providers/`, and `config-src/`.

## Open Gaps

| Gap | Desired Outcome | Current Status |
|---|---|---|
| Per-process telemetry | Show app-owned Xray counters separately from system counters | System counters are labeled; per-process telemetry not implemented |
| JA3 oracle workflow | User enters oracle URL and expected hash; app records measured result | CLI + probe wiring done (`--ja3-oracle`); GUI flow still pending |
| Verified runtime session | One command saves redacted runtime evidence | Done via `py -3 main.py verified-session` |
| Docs consolidation | Fewer first-contact docs, stronger reference docs | Started with Farsi quick start, ADRs, maintainer map |
| GUI modularization | `scripts/gui.py` becomes a small entrypoint | Started with `scripts/core/gui_readiness.py` |
