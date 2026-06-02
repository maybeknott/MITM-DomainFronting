# Maintainer Map

This map shows where each product area lives and which checks guard it.

| Area | Primary Files | Validation |
|---|---|---|
| GUI / UX | `scripts/gui.py`, `scripts/core/gui_readiness.py`, `assets/` | `py -3 scripts/gui.py --self-test`, `py -3 tests/python/gui_readiness_tests.py` |
| Shared readiness | `scripts/core/readiness.py`, `main.py probe` | `py -3 tests/python/readiness_tests.py` |
| Xray config | `config-src/`, `Xray-config/` | `py -3 scripts/build_config.py --check-runtime-sync --generate-profiles --check-profile-sync` |
| Routing | `Xray-config/*.json`, `configs/route-intent.json`, `scripts/route_*` | `py -3 tests/python/route_policy_tests.py`, `py -3 scripts/route_graph_verify.py Xray-config/MITM-DomainFronting.json` |
| Browser integration | `scripts/browser_common.py`, `scripts/browser_diagnostics.py`, `scripts/browser_stealth.py`, `configs/browser-integration.json` | `py -3 tests/python/browser_probe_semantics_test.py` |
| Certificate / trust | `scripts/mitm_trust.py`, `scripts/trust_store_check.py`, `scripts/core/trust_assistant.py` | `py -3 scripts/mitm_trust.py status --json`, `py -3 main.py probe --json` |
| DNS / profiles | `configs/dns-profiles.yml`, `scripts/check_dns.py`, `scripts/generate_profiles.py` | `py -3 scripts/validate_metadata.py`, `py -3 scripts/generate_profiles.py --base Xray-config/MITM-DomainFronting.json` |
| Release | `.github/workflows/build-gui.yml`, `scripts/build_gui_exe.py`, `scripts/release_check.py`, `scripts/verify_release_artifact.py` | `py -3 main.py release-check` |
| Rust core | `src/` | `py -3 tests/python/rust_core_tests.py` |
| Local telemetry | `scripts/gui.py`, `.local-state/` | GUI self-test and manual Dashboard inspection |

## Ownership Rules

- Keep operator commands in `scripts/`.
- Keep shared implementation helpers in `scripts/core/`.
- Keep regression tests in `tests/python/`.
- Keep generated/runtime artifacts out of source control unless they are committed runtime configs under `Xray-config/`.
- Do not add silent trust-store writes or automatic OS-wide proxy changes.
