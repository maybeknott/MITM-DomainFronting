#!/usr/bin/env python3
"""Generate optional evasion lab profiles from reference config-src fragments."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "Xray-config" / "MITM-DomainFronting.json"
FRAGMENTS = {
    "evasion-fragment": ROOT / "config-src" / "fragments" / "tls-fragment-overlay.json",
    "evasion-reality-stub": ROOT / "config-src" / "fragments" / "reality-outbound-stub.json",
    "evasion-tun-stub": ROOT / "config-src" / "fragments" / "tun-inbound-stub.json",
}

sys.path.insert(0, str(ROOT / "scripts"))
from config_src_merge import compile_config  # noqa: E402


def generate_profile(name: str, fragment: Path, out_dir: Path) -> Path:
    if not BASE.exists():
        raise FileNotFoundError(f"base config missing: {BASE}")
    if not fragment.exists():
        raise FileNotFoundError(f"fragment missing: {fragment}")
    compiled = compile_config(BASE, [fragment])
    compiled["remarks"] = f"MITM-DomainFronting.{name}"
    output = out_dir / f"MITM-DomainFronting.{name}.json"
    output.write_text(json.dumps(compiled, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate optional evasion lab profiles (not in manifest sync)")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "Xray-config")
    parser.add_argument("--profile", choices=sorted(FRAGMENTS), nargs="*", default=list(FRAGMENTS))
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    generated: list[str] = []
    for name in args.profile:
        path = generate_profile(name, FRAGMENTS[name], args.out_dir)
        generated.append(str(path))
        print(path)
    print(json.dumps({"generated": generated, "note": "optional lab profiles — exclude from --check-profile-sync"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
