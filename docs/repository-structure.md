# Repository structure

## Purpose

Directory layout contract for reviewers, release engineers, and contributors. The
**primary runtime artifact** is `Xray-config/MITM-DomainFronting.json`; Python and
Rust tooling surround that config.

**Engineering docs:** start at [reference/00-engineering-handbook.md](reference/00-engineering-handbook.md).

## Design goal

Keep the repository simple while making it easier to review, test, troubleshoot, and release. The primary user-facing runtime config remains `Xray-config/MITM-DomainFronting.json`; generated profiles, metadata, diagnostics, and the local GUI are supporting tools around that config.

## Recommended tree

```text
MITM-DomainFronting/
  README.md
  SECURITY.md
  PRIVACY.md
  CHANGELOG.md
  SUPPORT_MATRIX.md
  build_gui_exe.bat
  bootstrap.py
  main.py
  Cargo.toml
  .gitignore

  src/
    lib.rs
    main.rs
    parser.rs
    cert_cache.rs
    scheduler.rs
    alpn_policy.rs
    tls_orchestrator.rs
    tls_orchestrator_backend.rs
    h2_coalescing.rs
    backend_runtime.rs
    ingress.rs
    ingress_android_tun.rs
    ingress_loopback.rs
    ingress_xdp_gateway.rs
    cooperative_overlay.rs
    regression_harness.rs

  Xray-config/
    MITM-DomainFronting.json
    certificate_generator.bat
    certificate_generator.sh
    mycert.crt                 # local only, ignored by git
    mycert.key                 # local only, ignored by git

  docs/
    reference/
      00-engineering-handbook.md
      01-architecture-runtime-delivery.md
      02-decisions-evasion-engineering.md
      03-issues-risks-validation.md
      generated-files.md
      maintainer-map.md
    fa/
      quick-start.md
    routing-correctness.md
    dns-resilience.md
    protocol-coverage.md
    platform-compatibility.md
    preflight-and-diagnostics.md
    decision-engine.md
    dns-profiles.md
    gui.md
    local-telemetry.md
    rust-stream-core-baseline.md
    operating-profiles.md
    intelligent-automation.md
    relay-and-metrics-policy.md
    transport-profiles.md
    release-engineering.md
    release-evidence.md
    provider-status.md
    tun-operational-notes.md
    certificate-lifecycle.md
    windows-guide.md
    linux-guide.md
    macos-guide.md
    android-guide.md
    android-trust-model.md
    uninstall.md
    ca-install-guide.md
    ca-verify-guide.md
    ca-rotate-guide.md
    ca-remove-guide.md
    ca-emergency-key-compromise.md
    ca-expired-certificate-recovery.md
    ca-wrong-certificate-recovery.md
    listener-binding.md
    chromium-integration.md
    sni-camouflage.md
    transport-extension-governance.md
    lab-evidence-checklist.md
    firewall-and-network-testing.md
    fakedns-recovery.md
    reviewer-checklist.md
    final-verdict-template.md
    evidence-map.md

  configs/
    compatibility.yml
    protocols.yml
    dns-edge-cases.yml
    dns-profiles.yml
    advanced-edge-cases.yml
    profiles.yml
    relay-profiles.yml
    metrics-profiles.yml
    tun-profiles.yml
    health-checks.yml
    browser-integration.json
    transport-experiments.json
    route-intent.json
    provider-status.example.yml
    release-checklist.yml

  config-src/
    base.json
    dns.yml
    manifest.json
    profiles.yml
    providers.yml
    README.md
    routes.yml
    static-cidrs.yml
    ja3-profile-pools.yml
    lab/
    fragments/
      README.md

  tools/
    ebpf/
      README.md
      ingress_telemetry.bpf.c
      containment_xdp.bpf.c

  providers/
    dns-resolvers.yml
    fastly.yml
    google.yml
    meta.yml

  scripts/
    preflight.py
    validate_config.py
    add_rule_tags.py
    build_gui_exe.py
    mitm_trust.py
    check_dns.py
    decision_report.py
    generate_profiles.py
    generate_evasion_profiles.py
    intelligent_advise.py
    lab_prepare.py
    ebpf_xdp_loader.py
    wire_proof_suricata.py
    apply_strategy_profile.py
    gui.py
    route_graph_verify.py
    route_rule_linter.py
    secret_scan.py
    trust_assistant.py
    validate_metadata.py
    build_release_manifest.py
    browser_common.py
    browser_diagnostics.py
    browser_stealth.py
    browser_smoke.py
    trust_store_check.py
    platform_capability_check.py
    dns_lab_harness.py
    fakedns_recovery_check.py
    geodata_pin.py
    provider_dossier_validate.py
    health_probe.py
    route_intent_sync.py
    config_src_validate.py
    config_src_build.py
    config_src_merge.py
    lab_evidence_run.py
    release_check.py
    transport_experiment_validate.py
    verify_release_artifact.py
    launch_browser_mitm.ps1
    core/
      __init__.py
      process_supervisor.py
      route_rule_linter.py
      trust_assistant.py
      sni_camouflage.py

  tests/
    python/
      browser_probe_semantics_test.py
      config_src_merge_test.py
      dns_lab_harness_tests.py
      failure_classifier_tests.py
      gui_readiness_tests.py
      health_policy_tests.py
      path_scorer_tests.py
      protocol_policy_tests.py
      provider_policy_validator_tests.py
      readiness_tests.py
      repository_structure_tests.py
      route_policy_tests.py
      rust_core_tests.py
      sni_camouflage_tests.py

  .github/
    ISSUE_TEMPLATE/
      bug.yml
      service-request.yml
      platform-setup.yml
    workflows/
      validate.yml
    PULL_REQUEST_TEMPLATE.md
```

## Why this structure

| Area | Why it exists | User impact | Maintainer impact |
|---|---|---|---|
| `Xray-config/` | Keeps the current simple import flow | No workflow disruption | Main config remains obvious |
| `docs/` | Keeps explanations out of the JSON | Easier troubleshooting | Lower duplicate issue volume |
| `scripts/` | Operator commands, diagnostics, builders, and app entrypoints | Faster diagnosis | Reproducible reports |
| `tests/` | Regression and structure checks | Stable releases | Cleaner command surface |
| `configs/` | Structured compatibility and protocol facts | Clear expectations | Easier updates without rewriting README |
| `.github/` | Issue and CI hygiene | Better bug reports | Fewer unsafe or incomplete reports |

## Non-goals

This structure intentionally does not require:

- a database;
- a server;
- remote telemetry;
- account login;
- automatic upload of diagnostics;
- automatic OS-wide certificate installation.

Generated operating profiles and the local GUI are optional repository tools. They must preserve the single primary config workflow and must not introduce remote telemetry, remote services, or automatic trust-store changes. Local GUI telemetry is permitted only as ignored, redacted troubleshooting state under `.local-state/`.

## Current safeguards

- `Xray-config/MITM-DomainFronting.json` remains the primary import file.
- `.gitignore` protects local certs, keys, logs, generated profiles, runtime geodata, browser profiles, packaging output, and lab evidence bundles.
- Routing, DNS, protocol support, platform compatibility, certificate lifecycle, browser checks, release evidence, and recovery workflows are documented under `docs/`.
- `preflight.py`, `validate_config.py`, route checks, provider checks, transport checks, secret scan, and repository-structure tests cover the release-critical paths.
- Issue templates ask for platform, client, DNS, and redacted diagnostics without requesting private key material.

## Related documents

| Document | Topic |
|---|---|
| [`reference/00-engineering-handbook.md`](reference/00-engineering-handbook.md) | Engineering handbook index |
| [`reference/generated-files.md`](reference/generated-files.md) | Source vs generated boundary |
| [`release-engineering.md`](release-engineering.md) | Release workflow |
| [`evidence-map.md`](evidence-map.md) | Evidence-to-safeguard map |
