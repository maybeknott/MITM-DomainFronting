#!/usr/bin/env python3
"""Repository layout and hygiene checks aligned with docs/repository-structure.md."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

ROOT = Path(__file__).resolve().parents[2]

REQUIRED_FILES = [
    "README.md",
    "SECURITY.md",
    "PRIVACY.md",
    "CHANGELOG.md",
    "SUPPORT_MATRIX.md",
    "build_gui_exe.bat",
    "bootstrap.py",
    "main.py",
    "Cargo.toml",
    "src/lib.rs",
    "src/main.rs",
    "src/alpn_policy.rs",
    "src/backend_runtime.rs",
    "src/h2_coalescing.rs",
    "src/cooperative_overlay.rs",
    "src/ingress.rs",
    "src/ingress_android_tun.rs",
    "src/ingress_loopback.rs",
    "src/ingress_xdp_gateway.rs",
    "src/parser.rs",
    "src/cert_cache.rs",
    "src/regression_harness.rs",
    "src/scheduler.rs",
    "src/tls_orchestrator.rs",
    "src/tls_orchestrator_backend.rs",
    ".gitignore",
    "Xray-config/Xray-Cooperative-Overlay.json",
    "Xray-config/certificate_generator.bat",
    "Xray-config/certificate_generator.sh",
    "docs/repository-structure.md",
    "docs/routing-correctness.md",
    "docs/dns-resilience.md",
    "docs/protocol-coverage.md",
    "docs/platform-compatibility.md",
    "docs/preflight-and-diagnostics.md",
    "docs/release-engineering.md",
    "docs/chromium-integration.md",
    "docs/local-telemetry.md",
    "docs/rust-stream-core-baseline.md",
    "docs/fa/quick-start.md",
    "docs/README.md",
    "docs/getting-started.md",
    "docs/gui.md",
    "docs/troubleshooting.md",
    "docs/intelligent-automation.md",
    "docs/reference/generated-files.md",
    "docs/reference/maintainer-map.md",
    "docs/reference/00-engineering-handbook.md",
    "docs/reference/01-architecture-runtime-delivery.md",
    "docs/reference/02-decisions-evasion-engineering.md",
    "docs/reference/03-issues-risks-validation.md",
    "configs/profiles.yml",
    "configs/dns-profiles.yml",
    "configs/compatibility.yml",
    "configs/protocols.yml",
    "configs/browser-integration.json",
    "configs/transport-experiments.json",
    "configs/transport-profiles.yml",
    "configs/route-intent.json",
    "docs/transport-extension-governance.md",
    "providers/fastly.yml",
    "providers/google.yml",
    "providers/meta.yml",
    "providers/dns-resolvers.yml",
    "scripts/preflight.py",
    "scripts/validate_config.py",
    "scripts/decision_report.py",
    "scripts/generate_profiles.py",
    "scripts/generate_evasion_profiles.py",
    "scripts/apply_strategy_profile.py",
    "scripts/intelligent_advise.py",
    "scripts/onboard.py",
    "scripts/lab_prepare.py",
    "scripts/ebpf_xdp_loader.py",
    "scripts/wire_proof_suricata.py",
    "scripts/browser_diagnostics.py",
    "scripts/browser_stealth.py",
    "scripts/browser_smoke.py",
    "tests/python/browser_probe_semantics_test.py",
    "scripts/build_config.py",
    "tests/python/repository_structure_tests.py",
    "scripts/trust_store_check.py",
    "scripts/platform_capability_check.py",
    "scripts/dns_lab_harness.py",
    "tests/python/dns_lab_harness_tests.py",
    "scripts/fakedns_recovery_check.py",
    "scripts/geodata_pin.py",
    "scripts/provider_dossier_validate.py",
    "scripts/provider_policy_validator.py",
    "tests/python/provider_policy_validator_tests.py",
    "scripts/health_probe.py",
    "tests/python/health_policy_tests.py",
    "tests/python/failure_classifier_tests.py",
    "tests/python/gui_readiness_tests.py",
    "scripts/path_scorer.py",
    "tests/python/path_scorer_tests.py",
    "tests/python/protocol_policy_tests.py",
    "tests/python/readiness_tests.py",
    "tests/python/verified_session_tests.py",
    "tests/python/release_artifact_tests.py",
    "tests/python/route_policy_tests.py",
    "tests/python/rust_core_tests.py",
    "tests/python/_path.py",
    "scripts/route_intent_sync.py",
    "scripts/route_graph_verify.py",
    "scripts/route_rule_linter.py",
    "scripts/trust_assistant.py",
    "scripts/core/__init__.py",
    "scripts/core/process_supervisor.py",
    "scripts/core/failure_classifier.py",
    "scripts/core/gui_readiness.py",
    "scripts/core/provider_policy.py",
    "scripts/core/readiness.py",
    "scripts/core/route_rule_linter.py",
    "scripts/core/trust_assistant.py",
    "scripts/core/sni_camouflage.py",
    "scripts/core/intelligent_advisor.py",
    "scripts/core/automation_playbook.py",
    "scripts/core/ja3_pool_attach.py",
    "scripts/core/strategy_winner.py",
    "scripts/core/ebpf_containment.py",
    "tests/python/sni_camouflage_tests.py",
    "docs/sni-camouflage.md",
    "scripts/transport_experiment_validate.py",
    "scripts/transport_profile_validate.py",
    "scripts/protocol_smoke.py",
    "config-src/manifest.json",
    "config-src/README.md",
    "config-src/base.json",
    "config-src/routes.yml",
    "config-src/dns.yml",
    "config-src/profiles.yml",
    "config-src/providers.yml",
    "config-src/static-cidrs.yml",
    "config-src/ja3-profile-pools.yml",
    "config-src/lab/wire-proof-manifest.json",
    "config-src/lab/suricata-sni-block.rules",
    "scripts/config_src_validate.py",
    "scripts/config_src_build.py",
    "scripts/config_src_merge.py",
    "tests/python/config_src_merge_test.py",
    "config-src/fragments/README.md",
    "scripts/lab_evidence_run.py",
    "scripts/lab_evidence_validate.py",
    "tools/ebpf/README.md",
    "tools/ebpf/ingress_telemetry.bpf.c",
    "tools/ebpf/containment_xdp.bpf.c",
    "Xray-config/Xray-Cooperative-Overlay.evasion-high-stealth.json",
    "tests/python/intelligent_advisor_test.py",
    "tests/python/automation_playbook_test.py",
    "tests/python/ja3_pool_attach_test.py",
    "tests/python/ebpf_xdp_loader_test.py",
    "tests/python/ebpf_containment_test.py",
    "tests/python/strategy_winner_test.py",
    "tests/python/wire_proof_suricata_test.py",
    "docs/lab-evidence-checklist.md",
    "release-geodata-lock.example.json",
    "release-geodata-lock.json",
    "scripts/gui.py",
    "scripts/build_gui_exe.py",
    "scripts/release_check.py",
    "scripts/verify_release_artifact.py",
    "scripts/verified_session.py",
    ".github/workflows/validate.yml",
    ".github/workflows/pipeline-audit.yml",
    ".github/ISSUE_TEMPLATE/bug.yml",
    ".github/ISSUE_TEMPLATE/platform-setup.yml",
    ".github/ISSUE_TEMPLATE/service-request.yml",
]

SHOULD_BE_IGNORED = [
    "Xray-config/mycert.crt",
    "Xray-config/mycert.key",
    "validation-report.json",
    "checksums.txt",
    "browser-profiles/diagnostics-playwright",
    "browser-profiles/stealth-cloakbrowser",
    "build/_tmp",
    "dist/_tmp",
    "target/_tmp",
    "build/config",
    "lab-evidence.bundle.json",
    ".local-state/gui-telemetry.jsonl",
]


def check_exists(paths: List[str]) -> List[str]:
    errors: List[str] = []
    for rel in paths:
        if not (ROOT / rel).exists():
            errors.append(f"missing required path: {rel}")
    return errors


def git_check_ignore(path: str) -> Tuple[bool, str]:
    proc = subprocess.run(
        ["git", "check-ignore", path],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return proc.returncode == 0, (proc.stdout.strip() or proc.stderr.strip())


def check_ignored(paths: List[str]) -> List[str]:
    errors: List[str] = []
    for rel in paths:
        ignored, detail = git_check_ignore(rel)
        if not ignored:
            errors.append(f"expected ignored but tracked-visible: {rel} ({detail or 'not ignored'})")
    return errors


def check_primary_config_contract() -> List[str]:
    errors: List[str] = []
    primary = ROOT / "Xray-config/Xray-Cooperative-Overlay.json"
    if not primary.exists():
        errors.append("primary config missing: Xray-config/Xray-Cooperative-Overlay.json")
    script = ROOT / "scripts/generate_profiles.py"
    expected = 'default=Path("Xray-config/Xray-Cooperative-Overlay.json")'
    text = script.read_text(encoding="utf-8")
    if expected not in text:
        errors.append("generate_profiles.py default --base is not Xray-config/Xray-Cooperative-Overlay.json")
    return errors


def main() -> int:
    errors: List[str] = []
    errors.extend(check_exists(REQUIRED_FILES))
    errors.extend(check_ignored(SHOULD_BE_IGNORED))
    errors.extend(check_primary_config_contract())
    if errors:
        for error in errors:
            print(error)
        return 2
    print("repository structure checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
