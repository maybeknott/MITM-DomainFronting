#!/usr/bin/env python3
"""Context-aware recommendations: profiles, evasion lab, eBPF, and automation commands."""
from __future__ import annotations

import json
import platform
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from core.readiness import ProjectState

ROOT = Path(__file__).resolve().parents[2]

EVASION_PROFILES = (
    "evasion-fragment",
    "evasion-reality-stub",
    "evasion-tun-stub",
    "evasion-fakedns",
    "evasion-high-stealth",
)


def _evasion_profiles_present(root: Path) -> Dict[str, bool]:
    return {
        name: (root / "Xray-config" / f"MITM-DomainFronting.{name}.json").is_file()
        for name in EVASION_PROFILES
    }


def load_decision_labels(root: Path) -> tuple[str, ...]:
    report_path = root / ".local-state" / "decision-report.latest.json"
    if not report_path.is_file():
        return ()
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return ()
    strategy = data.get("strategy_recommendation")
    if isinstance(strategy, dict):
        labels = strategy.get("failure_labels")
        if isinstance(labels, list):
            return tuple(str(item) for item in labels)
    phase = data.get("phase_diagnostics", {})
    if isinstance(phase, dict):
        classification = str(phase.get("phase_classification") or "").strip()
        if classification:
            from core.failure_classifier import derive_strategy_labels

            return derive_strategy_labels(phase=classification)
    return ()


def build_advisor_plan(
    *,
    root: Path = ROOT,
    state: Optional["ProjectState"] = None,
) -> Dict[str, Any]:
    """Return ranked recommendations and one-shot automation commands."""
    from core.strategy_profiles import recommend_profile
    from core.strategy_winner import load_winner

    root = root.resolve()
    plan: Dict[str, Any] = {
        "generated_by": "scripts/core/intelligent_advisor.py",
        "platform": platform.system(),
        "recommendations": [],
        "automation_commands": [],
        "evasion_profiles": _evasion_profiles_present(root),
    }

    labels = load_decision_labels(root)
    if state and state.page_check_status == "fail":
        labels = (*labels, "tcp_timeout")

    if not labels and state and state.ja3_configured and not state.ja3_measured:
        labels = ("static_ja3",)

    remembered = load_winner()
    if remembered:
        plan["remembered_profile"] = remembered.to_dict()

    if state and not state.config_ok:
        plan["recommendations"].append(
            _rec(
                "P0",
                "repair_config",
                "Repair primary config",
                "Xray-config/MITM-DomainFronting.json is missing or invalid.",
                "py -3 scripts/validate_config.py Xray-config/MITM-DomainFronting.json",
            )
        )
        return plan

    if state and (not state.profiles_present or not state.profiles_synced):
        plan["recommendations"].append(
            _rec(
                "P0",
                "regenerate_profiles",
                "Regenerate operating profiles",
                "Sync strict/balanced/compatibility/debug with the base config.",
                "py -3 scripts/build_config.py --generate-profiles --check-profile-sync",
            )
        )
        plan["automation_commands"].append("py -3 scripts/build_config.py --generate-profiles --check-profile-sync")

    missing_evasion = [name for name, present in plan["evasion_profiles"].items() if not present]
    if missing_evasion:
        plan["recommendations"].append(
            _rec(
                "P1",
                "lab_prepare",
                "Generate evasion lab profiles",
                f"Missing optional lab configs: {', '.join(missing_evasion)}",
                "py -3 main.py lab-prepare",
            )
        )
        plan["automation_commands"].append("py -3 main.py lab-prepare")

    try:
        decision = recommend_profile(
            failure_labels=labels,
            operator_intent="balanced",
            session_counter=0,
            root=root,
        )
        plan["suggested_profile"] = {
            "profile_id": decision.selected_profile_id,
            "path": decision.selected_profile_path,
            "reason": decision.reason,
            "confidence": decision.confidence,
            "confirmation_required": decision.confirmation_required,
        }
        if decision.selected_profile_id.startswith("evasion-"):
            plan["recommendations"].append(
                _rec(
                    "P1",
                    "use_evasion_profile",
                    f"Use lab profile {decision.selected_profile_id}",
                    decision.reason,
                    f"Import {decision.selected_profile_path} in your Xray client",
                )
            )
        elif labels:
            plan["recommendations"].append(
                _rec(
                    "P2",
                    "apply_profile",
                    f"Apply profile {decision.selected_profile_id}",
                    decision.reason,
                    "py -3 scripts/apply_strategy_profile.py",
                )
            )
    except ValueError:
        plan["suggested_profile"] = None

    if "tls_block" in labels or "static_ja3" in labels:
        plan["recommendations"].append(
            _rec(
                "P1",
                "evasion_fragment",
                "Try TLS record fragmentation lab profile",
                "Labels suggest DPI/TLS blocking or static JA3 — use evasion-fragment after Page Check passes.",
                "py -3 scripts/generate_evasion_profiles.py --profile evasion-fragment",
            )
        )
    if "webrtc_leak" in labels or "dns_leak" in labels:
        plan["recommendations"].append(
            _rec(
                "P1",
                "evasion_high_stealth",
                "Try combined high-stealth lab profile",
                "Leak labels detected — fragment + FakeDNS + TUN stub profile for controlled lab testing.",
                "py -3 scripts/generate_evasion_profiles.py --profile evasion-high-stealth",
            )
        )

    ebpf_state = root / ".local-state" / "ebpf-xdp-loader.json"
    plan["ebpf"] = {
        "consent_env": "MITM_EBPF_CONSENT",
        "containment_env": "MITM_EBPF_CONTAINMENT",
        "state_present": ebpf_state.is_file(),
        "linux": platform.system().lower() == "linux",
    }
    if platform.system().lower() == "linux" and (labels or (state and state.listener_status == "open")):
        plan["recommendations"].append(
            _rec(
                "P3",
                "ebpf_containment_lab",
                "Optional: eBPF fail-closed containment (Linux lab)",
                "Set consent + containment env vars; load XDP program before Start Core.",
                "MITM_EBPF_CONSENT=1 MITM_EBPF_CONTAINMENT=1 py -3 scripts/ebpf_xdp_loader.py --program containment --interface eth0",
            )
        )

    if state and state.ja3_configured and state.ja3_validation_status != "match":
        plan["recommendations"].append(
            _rec(
                "P2",
                "ja3_oracle",
                "Measure TLS fingerprint (opt-in)",
                "Configured fingerprint differs from wire or not yet measured.",
                "py -3 main.py verified-session --page-check --ja3-oracle <trusted-echo-url>",
            )
        )

    plan["automation_commands"].extend(
        [
            "py -3 main.py audit",
            "py -3 main.py test",
            "py -3 scripts/lab_evidence_run.py --json-out lab-evidence.bundle.json --allow-warn",
        ]
    )
    plan["automation_commands"] = _dedupe(plan["automation_commands"])
    plan["recommendations"] = sorted(plan["recommendations"], key=lambda item: item["priority"])
    return plan


def _rec(priority: str, action_id: str, title: str, detail: str, command: str) -> Dict[str, str]:
    return {
        "priority": priority,
        "id": action_id,
        "title": title,
        "detail": detail,
        "command": command,
    }


def _dedupe(items: List[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
