#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from core.intelligent_advisor import build_advisor_plan  # noqa: E402


def main() -> int:
    plan = build_advisor_plan(root=ROOT)
    assert plan.get("generated_by")
    assert isinstance(plan.get("evasion_profiles"), dict)
    assert isinstance(plan.get("automation_commands"), list)
    assert isinstance(plan.get("recommendations"), list)
    print(json.dumps({"status": "pass", "recommendation_count": len(plan["recommendations"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
