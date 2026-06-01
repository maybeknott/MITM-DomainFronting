#!/usr/bin/env python3
"""Advisory path scoring from phase-classified decision reports."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple


PHASE_STATUS = {
    "healthy": ("HEALTHY", 92.0, "NO_CHANGE", "keep_current_profile"),
    "dns_resolution_failed": ("SUSPECT", 24.0, "ROTATE_PROFILE", "run_dns_resolver_probe"),
    "dns_timeout": ("SUSPECT", 20.0, "ROTATE_PROFILE", "run_dns_resolver_probe"),
    "dns_poisoned_or_failed": ("SUSPECT", 24.0, "ROTATE_PROFILE", "run_dns_resolver_probe"),
    "tcp_timeout_blackhole": ("CIRCUIT_OPEN", 4.0, "ROTATE_PROFILE", "swap_edge_ip_or_provider"),
    "tcp_refused": ("CIRCUIT_OPEN", 0.0, "ROTATE_PROFILE", "swap_edge_ip_or_provider"),
    "tcp_failed": ("SUSPECT", 18.0, "ROTATE_PROFILE", "retry_tcp_connect_probe"),
    "tls_alert_or_rst": ("QUARANTINED", 10.0, "ROTATE_PROFILE", "rotate_fronted_sni"),
    "tls_silent_drop": ("QUARANTINED", 8.0, "ROTATE_PROFILE", "rotate_fronted_sni"),
    "alpn_mismatch": ("QUARANTINED", 16.0, "ROTATE_PROFILE", "validate_alpn_policy"),
    "http_status_bad": ("SUSPECT", 35.0, "ROTATE_PROFILE", "inspect_http_status_and_route_policy"),
    "first_byte_timeout": ("SUSPECT", 28.0, "ROTATE_PROFILE", "run_first_byte_and_throughput_probe"),
    "throughput_stall": ("SUSPECT", 26.0, "ROTATE_PROFILE", "run_first_byte_and_throughput_probe"),
}


def _extract_phase_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    # `decision_report.py` wraps phased probe under phase_diagnostics.
    if isinstance(data.get("phase_diagnostics"), dict):
        phase = data["phase_diagnostics"]
        return {
            "phase": str(phase.get("phase_classification", "unknown")),
            "confidence": float(phase.get("confidence_score", 0.0) or 0.0),
            "telemetry": phase.get("telemetry", {}) if isinstance(phase.get("telemetry"), dict) else {},
            "provider_family": str(phase.get("provider_family", "unknown")),
            "target": str(phase.get("target", "unknown")),
        }

    # Backward-compatible direct shape.
    return {
        "phase": str(data.get("phase_classification", "unknown")),
        "confidence": float(data.get("confidence_score", 0.0) or 0.0),
        "telemetry": data.get("telemetry", {}) if isinstance(data.get("telemetry"), dict) else {},
        "provider_family": str(data.get("provider_family", "unknown")),
        "target": str(data.get("target", "unknown")),
    }


def _score_from_phase(payload: Dict[str, Any]) -> Tuple[float, str, str, str, str]:
    phase = payload["phase"]
    telemetry = payload.get("telemetry", {})
    status, base_score, advisory_action, next_check = PHASE_STATUS.get(
        phase,
        ("SUSPECT", 20.0, "MANUAL_REVIEW", "inspect_decision_report"),
    )

    score = base_score
    reason = f"phase={phase}"

    if phase == "healthy":
        tcp_ms = float(telemetry.get("tcp_connect_ms") or 0.0)
        tls_ms = float(telemetry.get("tls_server_hello_ms") or 0.0)
        total = tcp_ms + tls_ms
        score = max(0.0, base_score + (8.0 - (total * 0.03)))
        reason = f"healthy path with tcp+tls latency={int(total)}ms"
    elif phase in {"tcp_timeout_blackhole", "tls_silent_drop"}:
        detail = str(telemetry.get("error_detail") or "").strip()
        if detail:
            reason = f"{phase}: {detail}"

    return score, status, advisory_action, next_check, reason


def build_advisory(report_data: Dict[str, Any], source: str = "") -> Dict[str, Any]:
    payload = _extract_phase_payload(report_data)
    score, status, advisory_action, next_check, reason = _score_from_phase(payload)
    confidence = float(payload.get("confidence", 0.0))

    # Confidence is only advisory; score remains deterministic.
    confidence_weighted_score = max(0.0, min(100.0, score * max(0.2, min(1.0, confidence))))

    return {
        "source": source,
        "provider_family": payload.get("provider_family", "unknown"),
        "target": payload.get("target", "unknown"),
        "phase_classification": payload.get("phase", "unknown"),
        "confidence": round(confidence, 3),
        "status": status,
        "computed_score": round(score, 2),
        "confidence_weighted_score": round(confidence_weighted_score, 2),
        "advisory_action": advisory_action,
        "recommended_next_check": next_check,
        "reason": reason,
    }


def compute_path_score(report_path: Path) -> Dict[str, Any]:
    report_data = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(report_data, dict):
        raise ValueError(f"{report_path}: report must be a JSON object")
    return build_advisory(report_data, source=str(report_path))


def aggregate_provider_rankings(advisories: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for advisory in advisories:
        provider = str(advisory.get("provider_family", "unknown") or "unknown")
        grouped.setdefault(provider, []).append(advisory)

    ranking: List[Dict[str, Any]] = []
    for provider, items in grouped.items():
        sample_count = len(items)
        avg_score = sum(float(item.get("computed_score", 0.0) or 0.0) for item in items) / sample_count
        avg_weighted = sum(float(item.get("confidence_weighted_score", 0.0) or 0.0) for item in items) / sample_count

        status_counts: Dict[str, int] = {}
        for item in items:
            status = str(item.get("status", "SUSPECT"))
            status_counts[status] = status_counts.get(status, 0) + 1
        dominant_status = sorted(status_counts.items(), key=lambda pair: (-pair[1], pair[0]))[0][0]

        best = max(items, key=lambda item: float(item.get("confidence_weighted_score", 0.0) or 0.0))
        ranking.append(
            {
                "provider_family": provider,
                "sample_count": sample_count,
                "avg_computed_score": round(avg_score, 2),
                "avg_confidence_weighted_score": round(avg_weighted, 2),
                "dominant_status": dominant_status,
                "best_target": best.get("target", "unknown"),
                "best_phase_classification": best.get("phase_classification", "unknown"),
                "best_advisory_action": best.get("advisory_action", "MANUAL_REVIEW"),
            }
        )

    ranking.sort(
        key=lambda item: (
            -float(item.get("avg_confidence_weighted_score", 0.0) or 0.0),
            -float(item.get("avg_computed_score", 0.0) or 0.0),
            -int(item.get("sample_count", 0) or 0),
            str(item.get("provider_family", "")),
        )
    )
    for index, item in enumerate(ranking, start=1):
        item["rank"] = index
    return ranking


def main() -> int:
    parser = argparse.ArgumentParser(description="Compute advisory path score from decision report JSON")
    parser.add_argument("--input", dest="inputs", type=Path, action="append", required=True, help="Path to decision report JSON (repeatable)")
    parser.add_argument("--compact", action="store_true", help="Print one-line summaries")
    args = parser.parse_args()

    advisories: List[Dict[str, Any]] = []
    for report_path in args.inputs:
        advisories.append(compute_path_score(report_path))

    if args.compact:
        for item in advisories:
            print(
                f"{item['source']} | {item['status']} | score={item['computed_score']} | "
                f"phase={item['phase_classification']} | action={item['advisory_action']}"
            )
        return 0

    payload: Dict[str, Any]
    if len(advisories) == 1:
        payload = advisories[0]
    else:
        best = max(advisories, key=lambda item: item["confidence_weighted_score"])
        provider_ranking = aggregate_provider_rankings(advisories)
        payload = {
            "advisories": advisories,
            "best_candidate": best,
            "provider_ranking": provider_ranking,
            "best_provider_family": provider_ranking[0]["provider_family"] if provider_ranking else "unknown",
            "note": "Advisory-only scoring; no runtime auto-switch is performed.",
        }
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
