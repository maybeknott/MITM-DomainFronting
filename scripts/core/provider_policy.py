#!/usr/bin/env python3
"""Typed validation helpers for provider policy YAML files."""
from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.IGNORECASE)
ROUTE_TAG_RE = re.compile(r"^r\d+_[a-z0-9_]+$")
PROVIDER_ID_RE = re.compile(r"^[a-z0-9-]+$")
CIDR_HINT_VALUE_RE = re.compile(r"^[a-z0-9:._/\-]+$", re.IGNORECASE)

ALLOWED_PROFILES = {"strict", "balanced", "compatibility", "debug"}
ALLOWED_FAILURE_POLICY = {"block", "direct", "user_selected_direct_or_report"}
ALLOWED_ALPN = {"h2", "http/1.1"}
ALLOWED_CIDR_ACTIONS = {"allow", "block", "redirect"}


def _as_list_of_str(raw: Any, field_name: str, errors: List[str]) -> List[str]:
    if not isinstance(raw, list) or not raw:
        errors.append(f"{field_name}: must be a non-empty list")
        return []
    values: List[str] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{field_name}: entries must be non-empty strings")
            continue
        values.append(item.strip())
    return values


def validate_policy_dict(data: Dict[str, Any], *, source: str, stale_days: int = 90) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []

    provider_id = data.get("id")
    if not isinstance(provider_id, str) or not PROVIDER_ID_RE.fullmatch(provider_id):
        errors.append("id: must match ^[a-z0-9-]+$")

    last_tested = data.get("last_tested")
    tested_date: dt.date | None = None
    if isinstance(last_tested, dt.date):
        tested_date = last_tested
    elif isinstance(last_tested, str):
        try:
            tested_date = dt.date.fromisoformat(last_tested)
        except ValueError:
            errors.append("last_tested: invalid ISO date")
    else:
        errors.append("last_tested: must be an ISO date string (YYYY-MM-DD)")

    if tested_date is not None:
        age_days = (dt.date.today() - tested_date).days
        if age_days > stale_days:
            warnings.append(f"last_tested is stale ({age_days} days)")

    routes = _as_list_of_str(data.get("routes"), "routes", errors)
    for route in routes:
        if not ROUTE_TAG_RE.fullmatch(route):
            errors.append(f"routes: invalid route tag '{route}'")

    profiles = _as_list_of_str(data.get("supported_profiles"), "supported_profiles", errors)
    for profile in profiles:
        if profile not in ALLOWED_PROFILES:
            errors.append(f"supported_profiles: unsupported profile '{profile}'")

    failure_policy = data.get("failure_policy")
    if not isinstance(failure_policy, dict):
        errors.append("failure_policy: must be an object")
    else:
        for key in ("strict", "balanced"):
            value = failure_policy.get(key)
            if not isinstance(value, str) or value not in ALLOWED_FAILURE_POLICY:
                errors.append(
                    f"failure_policy.{key}: must be one of {sorted(ALLOWED_FAILURE_POLICY)}"
                )

    tested_with = data.get("tested_with")
    if not isinstance(tested_with, dict):
        errors.append("tested_with: must be an object")
    else:
        for key in ("os", "client", "xray_min", "xray", "environment"):
            value = tested_with.get(key)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"tested_with.{key}: required non-empty string")

    front_sni = _as_list_of_str(data.get("front_sni"), "front_sni", errors)
    for hostname in front_sni:
        if not HOST_RE.fullmatch(hostname):
            errors.append(f"front_sni: invalid hostname '{hostname}'")

    alpn_policy = data.get("alpn_policy")
    if not isinstance(alpn_policy, dict):
        errors.append("alpn_policy: must be an object")
    else:
        allowed = _as_list_of_str(alpn_policy.get("allowed"), "alpn_policy.allowed", errors)
        preferred = alpn_policy.get("preferred")
        if not isinstance(preferred, str) or not preferred:
            errors.append("alpn_policy.preferred: required non-empty string")
        for alpn in allowed:
            if alpn not in ALLOWED_ALPN:
                errors.append(f"alpn_policy.allowed: unsupported ALPN '{alpn}'")
        if isinstance(preferred, str) and preferred and preferred not in allowed:
            errors.append("alpn_policy.preferred must exist in alpn_policy.allowed")
        if isinstance(preferred, str) and preferred and preferred not in ALLOWED_ALPN:
            errors.append(f"alpn_policy.preferred: unsupported ALPN '{preferred}'")

    cidr_hints = data.get("cidr_hints")
    if not isinstance(cidr_hints, list) or not cidr_hints:
        errors.append("cidr_hints: must be a non-empty list")
    else:
        for index, hint in enumerate(cidr_hints):
            if not isinstance(hint, dict):
                errors.append(f"cidr_hints[{index}]: must be an object")
                continue
            value = hint.get("value")
            action = hint.get("action")
            rationale = hint.get("rationale")
            if not isinstance(value, str) or not value.strip():
                errors.append(f"cidr_hints[{index}].value: required non-empty string")
            elif not CIDR_HINT_VALUE_RE.fullmatch(value):
                errors.append(f"cidr_hints[{index}].value: invalid format '{value}'")
            if not isinstance(action, str) or action not in ALLOWED_CIDR_ACTIONS:
                errors.append(
                    f"cidr_hints[{index}].action: must be one of {sorted(ALLOWED_CIDR_ACTIONS)}"
                )
            if not isinstance(rationale, str) or not rationale.strip():
                errors.append(f"cidr_hints[{index}].rationale: required non-empty string")

    if errors:
        errors = [f"{source}: {error}" for error in errors]
    if warnings:
        warnings = [f"{source}: {warning}" for warning in warnings]
    return errors, warnings


def provider_source(path: Path) -> str:
    return str(path.as_posix())
