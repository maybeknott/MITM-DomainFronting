#!/usr/bin/env python3
"""Emit intelligent advisor plan (profiles, evasion, eBPF, automation)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from core.intelligent_advisor import build_advisor_plan  # noqa: E402
from core.readiness import build_project_state, emit_text  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Context-aware recommendations for MITM-DomainFronting")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--config", default="Xray-config/MITM-DomainFronting.json")
    parser.add_argument("--skip-runtime", action="store_true")
    parser.add_argument("--text", action="store_true", help="human-readable summary")
    args = parser.parse_args()

    state = build_project_state(
        root=args.root,
        config_path=args.root / args.config,
        skip_runtime=args.skip_runtime,
    )
    plan = build_advisor_plan(root=args.root, state=state)
    if args.text:
        lines = ["Intelligent advisor", "=" * 40]
        if plan.get("suggested_profile"):
            sp = plan["suggested_profile"]
            lines.append(f"Suggested profile: {sp['profile_id']} ({sp['confidence']}) — {sp['reason']}")
        for rec in plan.get("recommendations", []):
            lines.append(f"[{rec['priority']}] {rec['title']}: {rec['detail']}")
            if rec.get("command"):
                lines.append(f"    -> {rec['command']}")
        if plan.get("automation_commands"):
            lines.append("")
            lines.append("Automation:")
            for cmd in plan["automation_commands"]:
                lines.append(f"  {cmd}")
        print("\n".join(lines))
    else:
        print(json.dumps({"readiness": {"overall": state.overall, "next_action": state.next_action}, **plan}, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
