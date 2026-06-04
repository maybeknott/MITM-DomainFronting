# Changelog

## Unreleased

### Added

- Preflight connect gate (`preflight_gate.py`) with GUI toggle to block Start Core on gate failure.
- Windows DPAPI private-key wrap/unwrap (`mitm_trust wrap-key` / `unwrap-key`) and connect-time key restore.
- CDP trust assist for isolated Chromium (`cdp_client.py`, `mitm_trust cdp-assist`) — opens certificate settings; no silent CA install.
- GUI **Run JA3 Oracle** (Health tab) with opt-in oracle URL and `.local-state/ja3-evidence.json` persistence (ADR-0004).
- TUN lab fragment (`tun-inbound-stub.json`), WFP/nftables firewall checklist, and Track D ADRs (eBPF helper, TTL spin lab).
- Lab evidence bundle now includes protocol structure probes (UDP/443, fragment, REALITY stub, FakeDNS, TUN, TTL spin, firewall checklist, evasion lab merge).
- T-03 build artifact hygiene section in `docs/reference/generated-files.md`.

### Changed

- Strategy profile **Apply Recommended** and optional auto-apply after non-healthy decision reports.
- `lab_evidence_run.py` aggregates DNS harness + protocol smoke scenarios into one bundle.

### Added (prior unreleased baseline)

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
- Farsi quick start, maintainer map, generated-files policy, and architecture decision records (now in `docs/reference/`).
- ADR-0008 (no raw-packet injection / inline Rust egress) and ADR-0009 (anti-censorship as a first-class goal).
- Anti-censorship Tracks A/B/C documented in `01-architecture-runtime-delivery.md` and structural guardrails (GUI stays under `scripts/`, doc changes require structure-test updates).
- SNI camouflage doc and read-only inspector (`docs/sni-camouflage.md`, `scripts/core/sni_camouflage.py`) distinguishing legitimate front-`serverName` evasion from raw-packet injection (ADR-0008).
- ADR-0010 adoption routing and evasion technique map (now `02-decisions-evasion-engineering.md`).
- Track D (profile trust, High Stealth TUN, OPSEC telemetry, key hardening, kernel packet shaping).
- ADR-0002–0005 amended with offensive-defensive review refinements (CDP-first trust, 198.18 FakeDNS, init-time JA3 pools, XDP-before-stack).
- Issue registry and verification gates consolidated into `03-issues-risks-validation.md`.
- High-survivability engineering spec consolidated into `02-decisions-evasion-engineering.md`.
- `docs/reference/00-engineering-handbook.md` through `03-issues-risks-validation.md` — engineering handbook (architecture, ADRs, issues, validation).

### Changed

- `docs/reference/` — engineering handbook (four Markdown files; edit in place, no doc generator)

- Control Center GUI visual refresh (design tokens, status pills, circular workflow stepper, card elevation).
- Control Center Dashboard now consumes the shared readiness state for its next action, safety banner, status chips, readiness cards, and proxy-mode panels.
- GUI readiness cache and dashboard action mapping were extracted into `scripts/core/gui_readiness.py` with bridge tests.
- Dashboard stat-card values wrap to their rendered width so long status strings (e.g. "Needs Attention") are not clipped in the tight grid.
- Telemetry rail shows Running Time at the top and inline sparklines beside each live metric value.
- JA3 runtime regression comparison gated by `MITM_STREAM_EXPECTED_JA3` in the Rust validation crate.
- JA3 MD5 hex encoding writes directly into a pre-sized buffer instead of allocating per byte.
- `docs/reference/01-architecture-runtime-delivery.md` documents the anti-censorship strategy layer (probe → classify → score → apply Xray config).
- ADR-0008 reframed: packet-level evasion accepted in Xray profiles and Track D, not in Rust validation as live egress.
- ADR-0010 rewritten as adoption routing; ADR-0002–0005 amended with accepted evasion evolutions (profile trust, bounded mimicry, High Stealth TUN, OPSEC telemetry).
- ADR-0002–0005 cross-linked to ADR-0010; `THREAT_MODEL.md` and `docs/local-telemetry.md` clarify evasion vs OPSEC boundaries.
- No change to default runtime behavior unless maintainers apply optional patches.
- Removed obsolete historical patch files now superseded by committed loopback and ignore rules.

### Notes

- Easy certificate generation remains supported.
- Single-config workflow remains supported.
