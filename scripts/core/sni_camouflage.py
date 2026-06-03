#!/usr/bin/env python3
"""SNI camouflage (a.k.a. legitimate "SNI spoofing") inspection and validation helpers.

Camouflage SNI means the TLS ClientHello presents a front ``serverName`` that differs
from the logical destination — domain fronting / REALITY-style camouflage expressed
in Xray via ``tlsSettings.serverName`` or ``realitySettings.serverName``. This module
is read-only: no sockets, no privileges, no packet injection.

For the raw TCP-segment / eBPF meaning of "SNI spoofing", see ADR-0008.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CamouflageBinding:
    outbound_tag: str
    protocol: str
    transport: str
    server_name: str


@dataclass(frozen=True)
class CamouflageIssue:
    severity: str
    outbound_tag: str
    code: str
    detail: str


@dataclass
class CamouflageReport:
    bindings: list[CamouflageBinding] = field(default_factory=list)
    issues: list[CamouflageIssue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(issue.severity == "error" for issue in self.issues)

    def to_dict(self) -> dict[str, Any]:
        return {
            "bindings": [asdict(binding) for binding in self.bindings],
            "issues": [asdict(issue) for issue in self.issues],
            "summary": self.summary_line(),
        }

    def summary_line(self) -> str:
        tls_like = [b for b in self.bindings if b.transport in {"tls", "reality"}]
        if not tls_like:
            return "summary: no TLS/REALITY outbounds with camouflage SNI"
        return f"summary: {len(tls_like)}/{len(tls_like)} TLS/REALITY outbounds carry a camouflage SNI"


def hostname_plausible(name: str) -> bool:
    candidate = name.strip().rstrip(".")
    if not candidate or len(candidate) > 253:
        return False
    if candidate == "localhost" or candidate.endswith(".local"):
        return False
    return bool(HOST_RE.fullmatch(candidate))


def _normalize_server_name(raw: Any) -> str | None:
    if not isinstance(raw, str):
        return None
    value = raw.strip()
    return value or None


def extract_bindings(config: dict[str, Any]) -> list[CamouflageBinding]:
    bindings: list[CamouflageBinding] = []
    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list):
        return bindings
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        tag = str(outbound.get("tag") or "").strip() or "<untagged>"
        protocol = str(outbound.get("protocol") or "unknown")
        stream = outbound.get("streamSettings")
        if not isinstance(stream, dict):
            continue
        security = str(stream.get("security") or "").strip().lower()
        if security == "tls":
            tls = stream.get("tlsSettings")
            if not isinstance(tls, dict):
                continue
            server_name = _normalize_server_name(tls.get("serverName"))
            if server_name is None:
                continue
            bindings.append(
                CamouflageBinding(
                    outbound_tag=tag,
                    protocol=protocol,
                    transport="tls",
                    server_name=server_name,
                )
            )
        elif security == "reality":
            reality = stream.get("realitySettings")
            if not isinstance(reality, dict):
                continue
            server_name = _normalize_server_name(reality.get("serverName"))
            if server_name is None:
                continue
            bindings.append(
                CamouflageBinding(
                    outbound_tag=tag,
                    protocol=protocol,
                    transport="reality",
                    server_name=server_name,
                )
            )
    return bindings


def validate_bindings(
    bindings: list[CamouflageBinding],
    *,
    tls_repack_tags: set[str] | None = None,
) -> list[CamouflageIssue]:
    issues: list[CamouflageIssue] = []
    tls_repack_tags = tls_repack_tags or set()
    for outbound in bindings:
        if not hostname_plausible(outbound.server_name):
            issues.append(
                CamouflageIssue(
                    severity="warning",
                    outbound_tag=outbound.outbound_tag,
                    code="hostname_implausible",
                    detail=f"camouflage serverName looks implausible: {outbound.server_name!r}",
                )
            )
    return issues


def inspect_outbounds(
    outbounds: list[dict[str, Any]],
    *,
    tls_repack_tags: set[str] | None = None,
) -> CamouflageReport:
    """Inspect a list of outbound dicts (or full config via inspect_config)."""
    config = {"outbounds": outbounds}
    bindings = extract_bindings(config)
    issues = list(validate_bindings(bindings, tls_repack_tags=tls_repack_tags))

    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        tag = str(outbound.get("tag") or "").strip() or "<untagged>"
        stream = outbound.get("streamSettings")
        if not isinstance(stream, dict):
            continue
        security = str(stream.get("security") or "").strip().lower()
        if security == "reality":
            reality = stream.get("realitySettings")
            if not isinstance(reality, dict) or _normalize_server_name(reality.get("serverName")) is None:
                issues.append(
                    CamouflageIssue(
                        severity="error",
                        outbound_tag=tag,
                        code="reality_server_name_required",
                        detail="REALITY outbounds must set realitySettings.serverName (camouflage SNI).",
                    )
                )
        elif security == "tls":
            tls = stream.get("tlsSettings")
            has_name = isinstance(tls, dict) and _normalize_server_name(tls.get("serverName")) is not None
            expect = tag in (tls_repack_tags or set()) or tag.startswith("tls-repack")
            if expect and not has_name:
                issues.append(
                    CamouflageIssue(
                        severity="warning",
                        outbound_tag=tag,
                        code="tls_server_name_recommended",
                        detail="TLS repack/fronting outbounds should set tlsSettings.serverName.",
                    )
                )

    return CamouflageReport(bindings=bindings, issues=issues)


def inspect_config(config: dict[str, Any]) -> CamouflageReport:
    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list):
        return CamouflageReport(
            issues=[
                CamouflageIssue(
                    severity="error",
                    outbound_tag="",
                    code="invalid_config",
                    detail="config.outbounds must be a list",
                )
            ]
        )
    tls_repack = {
        str(item.get("tag"))
        for item in outbounds
        if isinstance(item, dict) and str(item.get("tag", "")).startswith("tls-repack")
    }
    return inspect_outbounds(outbounds, tls_repack_tags=tls_repack)


def load_config(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: root must be a JSON object")
    return raw


def inspect_path(path: Path) -> CamouflageReport:
    return inspect_config(load_config(path))


def format_report_lines(report: CamouflageReport) -> list[str]:
    lines = [
        f"{binding.outbound_tag} [{binding.transport}] -> {binding.server_name}"
        for binding in report.bindings
    ]
    for issue in report.issues:
        lines.append(f"{issue.severity}: {issue.outbound_tag} [{issue.code}] {issue.detail}")
    lines.append(report.summary_line())
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inspect camouflage SNI (tlsSettings/realitySettings serverName) in Xray JSON configs.",
    )
    parser.add_argument(
        "configs",
        nargs="*",
        help="Xray JSON paths (default: Xray-config/MITM-DomainFronting.json)",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of human lines")
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parents[2]
    paths = [Path(p) for p in args.configs] if args.configs else [root / "Xray-config" / "MITM-DomainFronting.json"]
    exit_code = 0
    for path in paths:
        try:
            report = inspect_path(path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"{path}: {exc}", file=sys.stderr)
            exit_code = 1
            continue
        if args.json:
            payload = report.to_dict()
            payload["path"] = str(path)
            print(json.dumps(payload, indent=2))
        else:
            print(f"# {path}")
            for line in format_report_lines(report):
                print(line)
        if not report.ok:
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
