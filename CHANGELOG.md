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

### Changed

- Control Center GUI visual refresh (design tokens, status pills, circular workflow stepper, card elevation).
- Control Center Dashboard now consumes the shared readiness state for its next action, safety banner, status chips, readiness cards, and proxy-mode panels.
- GUI readiness cache and dashboard action mapping were extracted into `scripts/core/gui_readiness.py` with bridge tests.
- Dashboard stat-card values wrap to their rendered width so long status strings (e.g. "Needs Attention") are not clipped in the tight grid.
- Telemetry rail shows Running Time at the top and inline sparklines beside each live metric value.
- JA3 runtime self-audit comparison extracted to testable `ja3::self_audit` (env: `MITM_STREAM_EXPECTED_JA3`).
- JA3 MD5 hex encoding writes directly into a pre-sized buffer instead of allocating per byte.
- No change to default runtime behavior unless maintainers apply optional patches.

### Notes

- Easy certificate generation remains supported.
- Single-config workflow remains supported.
