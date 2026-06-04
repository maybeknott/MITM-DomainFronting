#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from core.automation_playbook import infer_persona, playbook_for, run_playbook  # noqa: E402
from core.readiness import ProjectState  # noqa: E402


def main() -> int:
    steps = playbook_for("newcomer")
    assert len(steps) >= 3
    report = run_playbook("newcomer", root=ROOT, dry_run=True)
    assert report["overall"] == "pass"
    assert len(report["steps"]) == len(steps)

    state = ProjectState(
        generated_at="2026-01-01T00:00:00+00:00",
        root=str(ROOT),
        overall="pass",
        next_action="Ready",
        next_action_detail="ok",
        config_ok=True,
        config_path="Xray-config/MITM-DomainFronting.json",
        profiles_present=True,
        profiles_synced=True,
        page_check_status="pass",
        release_ready=True,
    )
    assert infer_persona(state=state, failure_labels=()) == "maintainer"
    assert infer_persona(state=state, failure_labels=("tls_block",)) == "lab"
    print('{"status": "pass"}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
