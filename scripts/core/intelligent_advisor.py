#!/usr/bin/env python3
"""Context-aware recommendations: profiles, evasion lab, eBPF, playbooks, and automation."""
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
        name: (root / "Xray-config" / f"Xray-Cooperative-Overlay.{name}.json").is_file()
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
    persona: Optional[str] = None,
    persist: bool = True,
) -> Dict[str, Any]:
    """Return ranked recommendations, playbook, and one-shot automation commands."""
    from core.automation_playbook import (
        infer_persona,
        playbook_to_dict,
        save_advisor_plan,
    )
    from core.strategy_profiles import recommend_profile
    from core.strategy_winner import load_winner

    root = root.resolve()
    labels = load_decision_labels(root)
    if state and state.page_check_status == "fail":
        labels = (*labels, "tcp_timeout")

    if not labels and state and state.ja3_configured and not state.ja3_measured:
        labels = ("static_ja3",)

    chosen_persona = persona or infer_persona(state=state, failure_labels=labels, root=root)

    plan: Dict[str, Any] = {
        "generated_by": "scripts/core/intelligent_advisor.py",
        "platform": platform.system(),
        "persona": chosen_persona,
        "failure_labels": list(labels),
        "recommendations": [],
        "automation_commands": [],
        "evasion_profiles": _evasion_profiles_present(root),
        "playbook": playbook_to_dict(chosen_persona),
        "doc_links": playbook_to_dict(chosen_persona).get("doc_links", {}),
    }

    remembered = load_winner()
    if remembered:
        plan["remembered_profile"] = remembered.to_dict()

    if state:
        plan["readiness_summary"] = {
            "overall": state.overall,
            "next_action": state.next_action,
            "listener_exposure": state.listener_exposure,
            "trust_status": state.trust_status,
            "page_check_status": state.page_check_status,
            "release_ready": state.release_ready,
        }
        _append_readiness_recommendations(plan, state)

    if state and not state.config_ok:
        plan["recommendations"].append(
            _rec(
                "P0",
                "repair_config",
                "Repair primary config",
                "Xray-config/Xray-Cooperative-Overlay.json is missing or invalid.",
                "py -3 scripts/validate_config.py Xray-config/Xray-Cooperative-Overlay.json",
                "docs/troubleshooting.md",
            )
        )
        if persist:
            save_advisor_plan(plan)
        return plan

    if state and (not state.profiles_present or not state.profiles_synced):
        plan["recommendations"].append(
            _rec(
                "P0",
                "regenerate_profiles",
                "Regenerate operating profiles",
                "Sync strict/balanced/compatibility/debug with the base config.",
                "py -3 scripts/build_config.py --generate-profiles --check-profile-sync",
                "docs/operating-profiles.md",
            )
        )
        plan["automation_commands"].append("py -3 scripts/build_config.py --generate-profiles --check-profile-sync")

    missing_evasion = [name for name, present in plan["evasion_profiles"].items() if not present]
    if missing_evasion and chosen_persona == "lab":
        plan["recommendations"].append(
            _rec(
                "P1",
                "lab_prepare",
                "Generate evasion lab profiles",
                f"Missing optional lab configs: {', '.join(missing_evasion)}",
                "py -3 main.py lab-prepare --allow-warn",
                "docs/lab-evidence-checklist.md",
            )
        )
        plan["automation_commands"].append("py -3 main.py lab-prepare --allow-warn")

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
                    "docs/intelligent-automation.md",
                )
            )
        elif labels:
            plan["recommendations"].append(
                _rec(
                    "P2",
                    "apply_profile",
                    f"Apply profile {decision.selected_profile_id}",
                    decision.reason,
                    "py -3 scripts/apply_strategy_profile.py --remember",
                    "docs/decision-engine.md",
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
                "docs/intelligent-automation.md",
            )
        )
    if "webrtc_leak" in labels or "dns_leak" in labels:
        plan["recommendations"].append(
            _rec(
                "P1",
                "evasion_high_stealth",
                "Try combined high-stealth lab profile",
                "Leak labels detected — fragment + FakeDNS + TUN stub for controlled lab testing.",
                "py -3 scripts/generate_evasion_profiles.py --profile evasion-high-stealth",
                "docs/intelligent-automation.md",
            )
        )

    ebpf_state = root / ".local-state" / "ebpf-xdp-loader.json"
    plan["ebpf"] = {
        "consent_env": "MITM_EBPF_CONSENT",
        "containment_env": "MITM_EBPF_CONTAINMENT",
        "state_present": ebpf_state.is_file(),
        "linux": platform.system().lower() == "linux",
    }
    if platform.system().lower() == "linux" and chosen_persona == "lab":
        plan["recommendations"].append(
            _rec(
                "P3",
                "ebpf_containment_lab",
                "Optional: eBPF fail-closed containment (Linux lab)",
                "Set consent + containment env vars; load XDP program before Start Core.",
                "MITM_EBPF_CONSENT=1 MITM_EBPF_CONTAINMENT=1 py -3 scripts/ebpf_xdp_loader.py --program containment --interface eth0",
                "docs/reference/track-d-ebpf-helper-adr.md",
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
                "docs/chromium-integration.md",
            )
        )

    if chosen_persona == "newcomer":
        plan["recommendations"].append(
            _rec(
                "P2",
                "onboard",
                "Run guided newcomer checklist",
                "Executes validate, preflight, probe, and advisor in one report.",
                "py -3 main.py onboard",
                "docs/getting-started.md",
            )
        )
    if chosen_persona == "maintainer":
        plan["automation_commands"].extend(
            [
                "py -3 main.py release-check",
                "py -3 scripts/config_src_validate.py --run-steps",
            ]
        )
    else:
        plan["automation_commands"].extend(
            [
                "py -3 main.py audit",
                "py -3 main.py test",
            ]
        )
    if chosen_persona == "lab":
        plan["automation_commands"].append(
            "py -3 scripts/lab_evidence_run.py --json-out lab-evidence.bundle.json --allow-warn"
        )

    for step in plan["playbook"].get("steps", []):
        if isinstance(step, dict) and step.get("argv"):
            argv = step["argv"]
            if isinstance(argv, list) and len(argv) >= 2:
                cmd = " ".join(str(part) for part in argv)
                plan["automation_commands"].append(cmd)

    plan["automation_commands"] = _dedupe(plan["automation_commands"])
    plan["recommendations"] = sorted(plan["recommendations"], key=lambda item: item["priority"])

    if persist:
        save_advisor_plan(plan)
    return plan


def _append_readiness_recommendations(plan: Dict[str, Any], state: "ProjectState") -> None:
    if state.listener_exposure == "exposed":
        plan["recommendations"].append(
            _rec(
                "P0",
                "fix_listener",
                "Fix exposed listener",
                "A proxy is listening on a non-loopback address. Bind external clients to 127.0.0.1.",
                "py -3 main.py probe --json",
                "docs/listener-binding.md",
            )
        )
    if not state.cert_exists or not state.key_exists:
        plan["recommendations"].append(
            _rec(
                "P0",
                "generate_ca",
                "Generate local CA",
                "Browser MITM requires mycert.crt and mycert.key on this machine.",
                "py -3 scripts/gui.py  # Generate Local CA in Dashboard, or certificate_generator.bat",
                "docs/ca-install-guide.md",
            )
        )
    elif state.trust_status not in {"pass", "not_supported", "skipped"}:
        plan["recommendations"].append(
            _rec(
                "P1",
                "trust_ca",
                "Install CA trust manually",
                "Certificate files exist but trust store does not match yet.",
                "py -3 scripts/trust_assistant.py --cert Xray-config/mycert.crt",
                "docs/ca-install-guide.md",
            )
        )
    if state.listener_status == "closed":
        plan["recommendations"].append(
            _rec(
                "P1",
                "start_core",
                "Start local core",
                "No listener on the configured port — start bundled core or open v2rayN.",
                "py -3 main.py gui",
                "docs/gui.md",
            )
        )
    if state.page_check_status != "pass" and state.playwright_ok:
        plan["recommendations"].append(
            _rec(
                "P1",
                "page_check",
                "Run browser page check",
                "Verify a stock browser loads a page through the local proxy.",
                "py -3 scripts/browser_diagnostics.py",
                "docs/chromium-integration.md",
            )
        )
    if not state.playwright_ok:
        plan["recommendations"].append(
            _rec(
                "P2",
                "install_playwright",
                "Install page-check tools",
                "Playwright is required for the stock browser page check.",
                "py -3 -m pip install -r requirements-browser-diagnostics.txt",
                "docs/chromium-integration.md",
            )
        )
    if state.release_blockers:
        plan["recommendations"].append(
            _rec(
                "P2",
                "release_blockers",
                "Resolve release blockers",
                f"{len(state.release_blockers)} readiness check(s) block release readiness.",
                "py -3 main.py probe --json",
                "docs/release-engineering.md",
            )
        )


def _rec(
    priority: str,
    action_id: str,
    title: str,
    detail: str,
    command: str,
    doc: str = "",
) -> Dict[str, str]:
    entry = {
        "priority": priority,
        "id": action_id,
        "title": title,
        "detail": detail,
        "command": command,
    }
    if doc:
        entry["doc"] = doc
    return entry


def _dedupe(items: List[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
