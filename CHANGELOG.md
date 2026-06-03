# Changelog

## Unreleased

### Added

- Repository structure documentation.
- Routing correctness documentation.
- DNS resilience documentation.
- Protocol coverage matrix.
- Platform compatibility matrix.
- Certificate lifecycle guides.
- Preflight and validation scripts.
- Release validation workflow.
- Shared readiness model for CLI/GUI orchestration with `ProjectState`, `CheckResult`, and `RepairAction` contracts.
- `main.py probe` now emits the shared readiness state instead of running a separate health-probe path.
- Python regression tests now live under `tests/python/`; `scripts/` is kept for operator commands, diagnostics, builders, and app entrypoints.
- `main.py release-check` gates release readiness and ZIP artifact verification, including checksum and forbidden local certificate/key checks.
- Release readiness checks and ZIP artifact verification.
- Farsi quick start, maintainer map, generated-files policy, roadmap, and architecture decision records.
- ADR-0008 (no raw-packet injection / inline Rust egress) and ADR-0009 (anti-censorship as a first-class goal).
- ROADMAP anti-censorship Tracks A/B/C and structural guardrails (GUI stays under `scripts/`, doc-merge requires structure-test updates).
- SNI camouflage doc and read-only inspector (`docs/sni-camouflage.md`, `scripts/core/sni_camouflage.py`) distinguishing legitimate front-`serverName` evasion from raw-packet injection (ADR-0008).

### Changed

- Control Center GUI visual refresh (design tokens, status pills, circular workflow stepper, card elevation).
- Control Center Dashboard now consumes the shared readiness state for its next action, safety banner, status chips, readiness cards, and proxy-mode panels.
- GUI readiness cache and dashboard action mapping were extracted into `scripts/core/gui_readiness.py` with bridge tests.
- Dashboard stat-card values wrap to their rendered width so long status strings (e.g. "Needs Attention") are not clipped in the tight grid.
- Telemetry rail shows Running Time at the top and inline sparklines beside each live metric value.
- JA3 runtime self-audit comparison extracted to testable `ja3::self_audit` (env: `MITM_STREAM_EXPECTED_JA3`).
- JA3 MD5 hex encoding writes directly into a pre-sized buffer instead of allocating per byte.
- `docs/architecture.md` documents the anti-censorship strategy layer (probe → classify → score → apply Xray config).
- No change to default runtime behavior unless maintainers apply optional patches.
- Removed obsolete historical patch files now superseded by committed loopback and ignore rules.

### Notes

- Easy certificate generation remains supported.
- Single-config workflow remains supported.
