#!/usr/bin/env python3
"""Persona-based automation playbooks (newcomer, maintainer, lab)."""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from core.readiness import ProjectState

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PLAN_PATH = ROOT / ".local-state" / "advisor-plan.latest.json"


@dataclass(frozen=True)
class PlaybookStep:
    id: str
    title: str
    detail: str
    argv: tuple[str, ...]
    optional: bool = False
    timeout_s: float = 120.0
    doc: str = ""

    def command_line(self) -> str:
        return " ".join(self.argv)


PLAYBOOKS: Dict[str, tuple[PlaybookStep, ...]] = {
    "newcomer": (
        PlaybookStep(
            "validate_config",
            "Validate primary config",
            "Confirm Xray JSON structure and project guardrails.",
            ("py", "-3", "scripts/validate_config.py", "Xray-config/Xray-Cooperative-Overlay.json"),
            doc="docs/getting-started.md",
        ),
        PlaybookStep(
            "static_preflight",
            "Static preflight",
            "Files, routes, and metadata without live DNS or your CA on disk.",
            (
                "py",
                "-3",
                "scripts/preflight.py",
                "--config",
                "Xray-config/Xray-Cooperative-Overlay.json",
                "--no-dns",
                "--skip-cert",
                "--skip-runtime",
            ),
            doc="docs/preflight-and-diagnostics.md",
        ),
        PlaybookStep(
            "readiness_probe",
            "Readiness probe",
            "Shared state model used by GUI and CLI (includes intelligent block).",
            ("py", "-3", "main.py", "probe", "--json"),
            doc="docs/intelligent-automation.md",
        ),
        PlaybookStep(
            "advisor",
            "Smart advisor",
            "Ranked next steps from local decision report and readiness.",
            ("py", "-3", "main.py", "advise", "--text"),
            doc="docs/intelligent-automation.md",
        ),
    ),
    "maintainer": (
        PlaybookStep(
            "audit",
            "Static audit",
            "Fast config, route, provider, and governance checks.",
            ("py", "-3", "main.py", "audit"),
            doc="docs/reference/00-engineering-handbook.md",
        ),
        PlaybookStep(
            "release_check",
            "Release readiness",
            "Profiles, docs, artifacts, and advisor smoke.",
            ("py", "-3", "main.py", "release-check"),
            doc="docs/release-engineering.md",
        ),
        PlaybookStep(
            "config_src",
            "Config-src validate",
            "Manifest, fragments, and build pipeline boundaries.",
            ("py", "-3", "scripts/config_src_validate.py", "--run-steps"),
            doc="docs/reference/generated-files.md",
        ),
        PlaybookStep(
            "build_profiles",
            "Regenerate profiles",
            "Operating + evasion lab configs from manifest.",
            (
                "py",
                "-3",
                "scripts/build_config.py",
                "--check-runtime-sync",
                "--generate-profiles",
                "--check-profile-sync",
            ),
            doc="docs/operating-profiles.md",
        ),
    ),
    "lab": (
        PlaybookStep(
            "lab_prepare",
            "Lab prepare",
            "Evasion profiles, JA3/eBPF smoke, optional evidence bundle.",
            ("py", "-3", "main.py", "lab-prepare", "--allow-warn"),
            doc="docs/lab-evidence-checklist.md",
        ),
        PlaybookStep(
            "lab_evidence",
            "Lab evidence bundle",
            "DNS harness + protocol structure probes.",
            (
                "py",
                "-3",
                "scripts/lab_evidence_run.py",
                "--json-out",
                "lab-evidence.bundle.json",
                "--allow-warn",
            ),
            doc="docs/lab-evidence-checklist.md",
        ),
        PlaybookStep(
            "wire_proof_structure",
            "Suricata wire-proof structure",
            "Validates harness without requiring a PCAP on CI hosts.",
            ("py", "-3", "scripts/wire_proof_suricata.py", "--scenario", "structure"),
            doc="docs/intelligent-automation.md",
        ),
    ),
}

DOC_LINKS: Dict[str, str] = {
    "getting_started": "docs/getting-started.md",
    "troubleshooting": "docs/troubleshooting.md",
    "gui": "docs/gui.md",
    "intelligent_automation": "docs/intelligent-automation.md",
    "preflight": "docs/preflight-and-diagnostics.md",
    "lab_evidence": "docs/lab-evidence-checklist.md",
    "operating_profiles": "docs/operating-profiles.md",
    "decision_engine": "docs/decision-engine.md",
}


def infer_persona(
    *,
    state: Optional["ProjectState"] = None,
    failure_labels: tuple[str, ...] = (),
    root: Path = ROOT,
) -> str:
    """Pick newcomer, maintainer, or lab playbook from local signals."""
    labels = {label.strip().lower() for label in failure_labels if label.strip()}
    lab_labels = {"tls_block", "static_ja3", "webrtc_leak", "dns_leak", "tcp_timeout"}
    if labels & lab_labels:
        return "lab"
    evasion_present = any(
        (root / "Xray-config" / f"Xray-Cooperative-Overlay.{name}.json").is_file()
        for name in ("evasion-fragment", "evasion-high-stealth")
    )
    if labels and evasion_present:
        return "lab"
    if state and state.overall == "pass" and state.page_check_status == "pass":
        return "maintainer"
    if state and state.release_ready:
        return "maintainer"
    return "newcomer"


def playbook_for(persona: str) -> tuple[PlaybookStep, ...]:
    return PLAYBOOKS.get(persona, PLAYBOOKS["newcomer"])


def playbook_to_dict(persona: str) -> Dict[str, Any]:
    steps = playbook_for(persona)
    return {
        "persona": persona,
        "summary": _persona_summary(persona),
        "steps": [asdict(step) for step in steps],
        "doc_links": DOC_LINKS,
    }


def _persona_summary(persona: str) -> str:
    return {
        "newcomer": "First-time setup: validate config, probe readiness, then follow advisor output.",
        "maintainer": "Release and config-src hygiene before merging or tagging.",
        "lab": "Regenerate evasion artifacts and collect lab evidence bundles.",
    }.get(persona, "")


def run_playbook(
    persona: str,
    *,
    root: Path = ROOT,
    dry_run: bool = False,
    stop_on_fail: bool = True,
) -> Dict[str, Any]:
    """Execute playbook steps; return structured run report."""
    steps = playbook_for(persona)
    report: Dict[str, Any] = {
        "persona": persona,
        "dry_run": dry_run,
        "started_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "steps": [],
    }
    overall = "pass"
    for step in steps:
        entry: Dict[str, Any] = {
            "id": step.id,
            "title": step.title,
            "command": step.command_line(),
            "optional": step.optional,
        }
        if dry_run:
            entry["status"] = "skipped"
            entry["detail"] = "dry-run"
            report["steps"].append(entry)
            continue
        resolved: List[str] = []
        for index, part in enumerate(step.argv):
            if index == 0 and part in {"py", "python"}:
                resolved.append(sys.executable)
            elif part.endswith(".py") and not Path(part).is_absolute():
                resolved.append(str(root / part))
            elif part == "main.py":
                resolved.append(str(root / "main.py"))
            else:
                resolved.append(part)
        try:
            proc = subprocess.run(
                resolved,
                cwd=str(root),
                text=True,
                capture_output=True,
                timeout=step.timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired:
            entry["status"] = "fail"
            entry["detail"] = f"timeout after {step.timeout_s}s"
            report["steps"].append(entry)
            overall = "fail"
            if stop_on_fail and not step.optional:
                break
            continue
        entry["returncode"] = proc.returncode
        entry["stdout_tail"] = (proc.stdout or "")[-1500:]
        entry["stderr_tail"] = (proc.stderr or "")[-800:]
        if proc.returncode == 0:
            entry["status"] = "pass"
        elif step.optional:
            entry["status"] = "warn"
        else:
            entry["status"] = "fail"
            overall = "fail"
        report["steps"].append(entry)
        if entry["status"] == "fail" and stop_on_fail:
            break
    report["overall"] = overall
    report["finished_at_utc"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    return report


def save_advisor_plan(plan: Dict[str, Any], path: Path = DEFAULT_PLAN_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(plan, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path
