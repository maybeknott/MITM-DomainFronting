# Changelog

## Unreleased

### Added

- Preflight connect gate (`preflight_gate.py`) with GUI toggle to block Start Core on gate failure.
- Windows DPAPI private-key wrap/unwrap (`mitm_trust wrap-key` / `unwrap-key`) and connect-time key restore.
- CDP trust assist for isolated Chromium (`cdp_client.py`, `mitm_trust cdp-assist`) — opens certificate settings; no silent CA install.
- GUI **Run JA3 Oracle** (Health tab) with opt-in oracle URL and `.local-state/ja3-evidence.json` persistence (ADR-0004).
- TUN lab fragment (`tun-inbound-stub.json`), WFP/nftables firewall checklist, and Track D ADRs (eBPF helper, TTL spin lab).
- Lab evidence bundle now includes DNS harness + protocol structure probes (UDP/443, fragment, REALITY stub, FakeDNS, TUN, TTL spin, firewall checklist, evasion lab merge).
- Engineering handbook (`docs/reference/00`–`03`), SNI camouflage inspector, anti-censorship Tracks A–D, ADR-0002–0010, and issue/validation registry.
- Shared readiness model (`ProjectState`, `CheckResult`, `RepairAction`) for CLI/GUI orchestration.
- `main.py release-check`, repository structure tests, provider dossiers, and release validation workflow.

### Changed

- Strategy profile **Apply Recommended** and optional auto-apply after non-healthy decision reports.
- `lab_evidence_run.py` aggregates DNS harness + protocol smoke scenarios into one bundle.
- Reference docs finalized: all Track A/B/C/D baseline items marked **Shipped**; future research isolated to `03` §4.1.
- Control Center GUI visual refresh and shared readiness dashboard integration.
- ADR-0008 reframed: packet-level evasion in Xray profiles and Track D docs, not Rust live egress.

### Notes

- Easy certificate generation and single-config workflow remain supported.
- Live eBPF loader and Suricata wire proof are documented as future research (not partial baseline work).
- Default runtime behavior unchanged unless maintainers apply optional lab profiles or High Stealth settings.
