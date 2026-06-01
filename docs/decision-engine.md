# Deterministic Decision Report

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

The expected local health checks and profile failure policies are defined in [health-checks.yml](../configs/health-checks.yml). This metadata is intentionally local-only and redacted-by-default; it must not become telemetry.

## Command

```bash
python scripts/decision_report.py --config Xray-config/MITM-DomainFronting.json --profile balanced
```

## Report Shape

```json
{
  "config_version": "MITM-DomainFronting_v22",
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
  }
}
```

## Boundary

The report is support-safe by design. It may contain route tags, status labels, file-existence booleans, and local port state. It must not contain full URLs, account identifiers, request/response bodies, cookies, private keys, or decrypted payload logs.
