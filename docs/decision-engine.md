# Deterministic Decision Report

## Purpose

Produce a local, redacted explanation of routing, DNS, certificate, and health state without opaque heuristics or remote telemetry. `scripts/decision_report.py` maps preflight facts through named profiles to a support-safe JSON report.

The project should avoid opaque intelligence. Local diagnostics should be explainable:

```text
preflight facts
  -> policy profile
  -> protocol classifier
  -> DNS profile
  -> route decision
  -> health state
  -> failure policy
  -> redacted explanation
```

`scripts/decision_report.py` produces that kind of local, redacted report. It does not inspect payloads, cookies, authorization headers, request bodies, or private-key contents.

The expected local health checks and profile failure policies are defined in [health-checks.yml](../configs/health-checks.yml). This metadata is intentionally local-only and redacted-by-default; it must not become remote telemetry. The GUI's local status log is limited to redacted operational events described in [local-telemetry.md](local-telemetry.md).

## Command

```bash
python scripts/decision_report.py --config Xray-config/Xray-Cooperative-Overlay.json --profile balanced
```

## Report Shape

```json
{
  "config_version": "Xray-Cooperative-Overlay_v1",
  "xray_min_required": "26.2.6",
  "profile": "balanced",
  "cert": {
    "crt_exists": true,
    "key_exists": true,
    "key_permissions_ok": true,
    "trusted_store_fingerprint_match": {
      "status": "pass|missing|mismatch|unknown|not_supported"
    }
  },
  "ports": {
    "10808": "listening-loopback",
    "11666": "not-listening",
    "11777": "not-listening"
  },
  "dns": {
    "primary": "configured",
    "fallback": "configured",
    "local_private": "configured"
  },
  "platform_capabilities": {
    "ech": {
      "status": "info|warn"
    }
  },
  "captive_portal": {
    "id": "captive_portal",
    "status": "pass|warn|info",
    "detail": "best-effort HTTP connectivity probe"
  },
  "policy_recommendation": {
    "auto_switch": false,
    "suggested_profile": "balanced",
    "profile_policy": {},
    "local_actions": []
  }
}
```

`policy_recommendation.auto_switch` is always `false`. The report suggests profiles and local actions only; it never mutates Xray config.

## Boundary

The report is support-safe by design. It may contain route tags, status labels, file-existence booleans, and local port state. It must not contain full URLs, account identifiers, request/response bodies, cookies, private keys, or decrypted payload logs.

## Related documents

| Document | Topic |
|---|---|
| [`preflight-and-diagnostics.md`](preflight-and-diagnostics.md) | Inputs to the decision report |
| [`operating-profiles.md`](operating-profiles.md) | Profile failure policies |
| [`lab-evidence-checklist.md`](lab-evidence-checklist.md) | Repeatable DNS and captive scenarios |
| [`local-telemetry.md`](local-telemetry.md) | GUI telemetry boundaries |
