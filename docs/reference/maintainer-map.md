# Maintainer map

## Purpose

Quick index of **where code lives**, **which tests guard it**, and **which engineering
doc owns policy** for each product area.

**Policy and ADRs:** [02-decisions-evasion-engineering.md](02-decisions-evasion-engineering.md)  
**Runtime architecture:** [01-architecture-runtime-delivery.md](01-architecture-runtime-delivery.md)  
**Known issues and validation:** [03-issues-risks-validation.md](03-issues-risks-validation.md)

---

## Code ownership

| Area | Primary files | Validation |
|---|---|---|
| GUI / UX | `scripts/gui.py`, `scripts/core/gui_readiness.py`, `assets/` | `py -3 scripts/gui.py --self-test`, `py -3 tests/python/gui_readiness_tests.py` |
| Shared readiness | `scripts/core/readiness.py`, `main.py probe` | `py -3 tests/python/readiness_tests.py` |
| Xray config | `config-src/`, `Xray-config/` | `py -3 scripts/build_config.py --check-runtime-sync --generate-profiles --check-profile-sync` |
| Routing | `Xray-config/*.json`, `configs/route-intent.json`, `scripts/route_*` | `py -3 tests/python/route_policy_tests.py`, `py -3 scripts/route_graph_verify.py Xray-config/MITM-DomainFronting.json` |
| Browser integration | `scripts/browser_common.py`, `scripts/browser_diagnostics.py`, `scripts/browser_stealth.py`, `configs/browser-integration.json` | `py -3 tests/python/browser_probe_semantics_test.py` |
| Certificate / trust | `scripts/mitm_trust.py`, `scripts/trust_store_check.py`, `scripts/core/trust_assistant.py` | `py -3 scripts/mitm_trust.py status --json`, `py -3 main.py probe --json` |
| DNS / profiles | `configs/dns-profiles.yml`, `scripts/check_dns.py`, `scripts/generate_profiles.py` | `py -3 scripts/validate_metadata.py`, `py -3 scripts/generate_profiles.py --base Xray-config/MITM-DomainFronting.json` |
| Release | `.github/workflows/build-gui.yml`, `scripts/build_gui_exe.py`, `scripts/release_check.py`, `scripts/verify_release_artifact.py` | `py -3 main.py release-check` |
| Rust validation crate | `src/`, `Cargo.toml` | `py -3 tests/python/rust_core_tests.py`, `cargo test --locked` |
| SNI camouflage | `scripts/core/sni_camouflage.py`, `docs/sni-camouflage.md` | `py -3 tests/python/sni_camouflage_tests.py` |
| Live data plane | `xray/xray.exe`, `Xray-config/MITM-DomainFronting.json` | Preflight + manual smoke; not Rust `src/` |

---

## Documentation ownership

| Document | Use when changing… |
|---|---|
| [00-engineering-handbook.md](00-engineering-handbook.md) | Glossary, doc index, validation command list |
| [01-architecture-runtime-delivery.md](01-architecture-runtime-delivery.md) | Runtime graph, Tracks A–D tasks, component inventory |
| [02-decisions-evasion-engineering.md](02-decisions-evasion-engineering.md) | ADRs, evasion technique acceptance, survivability specs |
| [03-issues-risks-validation.md](03-issues-risks-validation.md) | Known issues §1, verification gates §4 |
| [generated-files.md](generated-files.md) | Which generated artifacts are committed vs ignored |
| Operational guides under `docs/` | Operator-facing how-tos (CA, DNS, GUI, platform) |

Edit **policy** only in `docs/reference/0*.md`. Edit **procedures** in the matching
`docs/*.md` guide — do not duplicate ADR text in operational docs; summarize inline
and link once to the ADR.

---

## Repository rules

- Operator commands → `scripts/`
- Shared helpers → `scripts/core/`
- Regression tests → `tests/python/`
- Generated/runtime secrets → gitignored (`mycert.key`, `.local-state/`)
- **Never** silent trust-store writes or automatic OS-wide proxy changes
- **Never** add doc generator scripts — plain Markdown only
