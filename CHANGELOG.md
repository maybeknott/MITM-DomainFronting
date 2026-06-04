# Changelog

## Unreleased

### Added

- Preflight connect gate (`preflight_gate.py`) with GUI toggle to block Start Core on gate failure.
- Windows DPAPI private-key wrap/unwrap (`mitm_trust wrap-key` / `unwrap-key`) and connect-time key restore.
- CDP trust assist for isolated Chromium (`cdp_client.py`, `mitm_trust cdp-assist`) — opens certificate settings; no silent CA install.
- GUI **Run JA3 Oracle** (Health tab) with opt-in oracle URL and `.local-state/ja3-evidence.json` persistence (ADR-0004).
- TUN lab fragment (`tun-inbound-stub.json`), WFP/nftables firewall checklist, and Track D ADRs (eBPF helper, TTL spin lab).
- Live eBPF/XDP production loader (`scripts/ebpf_xdp_loader.py`, `tools/ebpf/`) with `MITM_EBPF_CONSENT=1` gate.
- Suricata/PCAP wire-proof harness (`scripts/wire_proof_suricata.py`, `config-src/lab/`).
- Automatic JA3 `pool_id` attach on every generated operating profile (`ja3_pool_attach.py`, `ja3-profile-pools.yml`).
- eBPF fail-secure containment (`containment_xdp.bpf.c`, `ebpf_containment.py`, ProcessSupervisor lifecycle).
- Evasion lab profiles: `evasion-fakedns`, `evasion-high-stealth` + JA3 attach on lab configs.
- Persistent strategy `remember_winner()` cache (`strategy_winner.py`).
- Intelligent advisor (`intelligent_advisor.py`, `main.py advise`, `probe` JSON `intelligent` field).
- One-shot lab pipeline (`main.py lab-prepare`, `config_src_build` evasion regen on `--generate-profiles`).
- `apply_strategy_profile.py --remember` to persist successful profile selection.
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
- Regenerate Xray operating profiles after pull: `py -3 scripts/build_config.py --generate-profiles --check-profile-sync`.
- Default runtime behavior unchanged unless maintainers apply optional lab profiles or High Stealth settings.
