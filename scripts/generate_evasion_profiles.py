#!/usr/bin/env python3
"""Generate optional evasion lab profiles from reference config-src fragments."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "Xray-config" / "Xray-Cooperative-Overlay.json"
FRAGMENT_DIR = ROOT / "config-src" / "fragments"
FRAGMENTS = {
    "evasion-fragment": FRAGMENT_DIR / "tls-fragment-overlay.json",
    "evasion-reality-stub": FRAGMENT_DIR / "reality-outbound-stub.json",
    "evasion-tun-stub": FRAGMENT_DIR / "tun-inbound-stub.json",
    "evasion-fakedns": FRAGMENT_DIR / "fakedns-19818-trap.json",
}
HIGH_STEALTH_FRAGMENTS = [
    FRAGMENT_DIR / "tls-fragment-overlay.json",
    FRAGMENT_DIR / "fakedns-19818-trap.json",
    FRAGMENT_DIR / "tun-inbound-stub.json",
]

sys.path.insert(0, str(ROOT / "scripts"))
from config_src_merge import compile_config  # noqa: E402
from core.ja3_pool_attach import attach_for_operating_profile  # noqa: E402


def generate_profile(name: str, fragments: list[Path], out_dir: Path) -> Path:
    if not BASE.exists():
        raise FileNotFoundError(f"base config missing: {BASE}")
    for fragment in fragments:
        if not fragment.exists():
            raise FileNotFoundError(f"fragment missing: {fragment}")
    compiled = compile_config(BASE, fragments)
    compiled["remarks"] = f"Xray-Cooperative-Overlay.{name}"
    attach_for_operating_profile(compiled, name, ROOT)
    output = out_dir / f"Xray-Cooperative-Overlay.{name}.json"
    output.write_text(json.dumps(compiled, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate optional evasion lab profiles (not in manifest sync)")
    parser.add_argument("--out-dir", type=Path, default=ROOT / "Xray-config")
    parser.add_argument(
        "--profile",
        choices=sorted({*FRAGMENTS.keys(), "evasion-high-stealth"}),
        nargs="*",
        default=[*FRAGMENTS.keys(), "evasion-high-stealth"],
    )
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    generated: list[str] = []
    for name in args.profile:
        if name == "evasion-high-stealth":
            path = generate_profile(name, HIGH_STEALTH_FRAGMENTS, args.out_dir)
        else:
            path = generate_profile(name, [FRAGMENTS[name]], args.out_dir)
        generated.append(str(path))
        print(path)
    print(
        json.dumps(
            {
                "generated": generated,
                "note": "optional lab profiles — exclude from --check-profile-sync",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
