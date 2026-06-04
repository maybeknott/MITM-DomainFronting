#!/usr/bin/env python3
"""Run the newcomer automation playbook with a structured report."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from core.automation_playbook import run_playbook  # noqa: E402
from core.intelligent_advisor import build_advisor_plan  # noqa: E402
from core.readiness import build_project_state  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Guided onboarding automation for MITM-DomainFronting")
    parser.add_argument("--persona", choices=("newcomer", "maintainer", "lab"), default="newcomer")
    parser.add_argument("--config", default="Xray-config/MITM-DomainFronting.json")
    parser.add_argument("--dry-run", action="store_true", help="list steps without executing")
    parser.add_argument("--json-out", type=Path, default=None)
    parser.add_argument("--skip-playbook", action="store_true", help="only emit advisor plan")
    args = parser.parse_args()

    state = build_project_state(
        root=ROOT,
        config_path=ROOT / args.config,
        skip_runtime=False,
    )
    plan = build_advisor_plan(root=ROOT, state=state, persona=args.persona, persist=True)

    payload: dict = {
        "persona": args.persona,
        "advisor": plan,
        "playbook_run": None,
    }
    if not args.skip_playbook:
        payload["playbook_run"] = run_playbook(args.persona, root=ROOT, dry_run=args.dry_run)

    text = json.dumps(payload, indent=2, ensure_ascii=False)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(text + "\n", encoding="utf-8")
    print(text)

    if args.skip_playbook:
        return 0
    run = payload.get("playbook_run") or {}
    return 0 if run.get("overall") == "pass" or args.dry_run else 1


if __name__ == "__main__":
    raise SystemExit(main())
