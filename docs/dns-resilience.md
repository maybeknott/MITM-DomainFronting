# DNS Resilience

## Objective

DNS is not a helper detail. It is a core runtime dependency. If DNS breaks, routing breaks. If DNS drifts, services break. This document keeps one simple config while adding clear DNS handling, tests, and recovery steps.

## Current DNS dependency model

The config uses a mix of:

- FakeDNS for selected domains.
- Tagged Cloudflare and Google external resolver paths.
- Localhost fallback for private, regional, captive, or enterprise cases.
- Explicit Xray DNS query strategy (`UseIPv4` in the shipped baseline) rather than recursive OS resolver handoff.
- `serveStale`.
- Routing rules for port 53.

These are useful, but they need explicit operational behavior.

## DNS edge-case table

| Edge case | Risk | Required handling | Validation |
|---|---|---|---|
| Resolver timeout | Service failure | Multi-resolver fallback | Simulate primary resolver timeout and confirm secondary path |
| Local DNS hijack | Wrong destination | Avoid silent local fallback for targeted domains unless documented | Test with local DNS returning wrong IP |
| DNS64/NAT64 | IPv4 assumptions fail | IPv6-only tests | Test on IPv6-only/NAT64 network or lab |
| HTTPS/SVCB record changes | Protocol negotiation changes | qtype-aware tests | Query A, AAAA, HTTPS/SVCB separately |
| FakeDNS stale cache | Network broken after exit | Recovery guide | Start/stop Xray and flush OS/browser DNS cache |
| Captive portal DNS | Setup impossible | Captive portal note and local-first temporary troubleshooting | Test on portal network or lab DNS hijack |
| Enterprise split DNS | Internal domains break | Private-domain local policy | Test `.lan`, `.local`, internal suffixes |
| DNS loop | Self-referential resolver path | Loop detection | Preflight checks resolver target is not routed back into itself |

## Simple recommended DNS behavior

Do not introduce complex DNS profiles unless maintainers want them. For the current single config:

1. Keep `no-filter-dns-cloudflare` as the primary external resolver path.
2. Keep `no-filter-dns-google` as a separate secondary resolver path.
3. Keep local resolver only for private, regional, captive, or enterprise cases.
4. Keep resolver timeouts low enough that users do not wait excessively.
5. Keep `serveStale` documented because stale answers can help or confuse.
6. Document FakeDNS recovery.
7. Validate that DNS rules reference existing outbound tags.

## Recommended resolver logic

```text
Targeted service DNS:
  no-filter-dns-cloudflare with timeout
  no-filter-dns-google with timeout
  local resolver only where explicitly intended

Private/local DNS:
  local resolver first
  no FakeDNS for private suffixes unless explicitly tested

Captive portal:
  temporary local resolver behavior may be necessary
  user should disable method until portal login is completed if DNS is hijacked
```

## DNS test plan

Run a query-type-aware diagnostic when checking HTTPS/SVCB drift:

```bash
python scripts/check_dns.py --domain example.com --resolver 1.1.1.1 --resolver 8.8.8.8 --all-types
```

For scenario-driven manual lab evidence, use the DNS harness:

```bash
python scripts/dns_lab_harness.py --scenario resolver-timeout --domain example.com --primary-resolver 203.0.113.1 --fallback-resolver 1.1.1.1
python scripts/dns_lab_harness.py --scenario fallback-order --domain example.com --resolver 1.1.1.1 --resolver 8.8.8.8
python scripts/dns_lab_harness.py --scenario dns-hijack --domain example.com --trusted-resolver 1.1.1.1 --suspect-resolver 8.8.8.8
python scripts/dns_lab_harness.py --scenario fake-dns-lab --domain example.com --trusted-resolver 1.1.1.1 --fake-dns-bind-port 5533 --fake-ipv4 203.0.113.99
python scripts/dns_lab_harness.py --scenario split-dns --private-domain router.local --resolver 1.1.1.1 --resolver 8.8.8.8
python scripts/dns_lab_harness.py --scenario nat64-dns64 --nat64-domain ipv4only.arpa --resolver 1.1.1.1 --resolver 8.8.8.8
python scripts/dns_lab_harness.py --scenario captive-portal
```

See also [`lab-evidence-checklist.md`](lab-evidence-checklist.md) and:

```bash
python scripts/lab_evidence_run.py --json-out lab-evidence.bundle.json
```

Use `--allow-warn` on desktops or in CI when full lab network conditions are not available (exit 0 with `overall: warn`).

### Harness output schema (redacted)

```json
{
  "scenario": "resolver-timeout",
  "checks": [],
  "observations": {},
  "overall": "pass|warn|fail"
}
```

### Test 1: Resolver timeout

- Disable or blackhole the primary resolver in a lab.
- Run the preflight DNS check.
- Confirm secondary resolver is attempted.
- Confirm failure report identifies resolver timeout, not generic site failure.

### Test 2: NXDOMAIN

- Query a deliberately nonexistent domain.
- Confirm NXDOMAIN does not poison future valid queries.
- Confirm no route rule changes because of NXDOMAIN.

### Test 3: Private domain

- Query router or LAN host.
- Confirm private domain does not get sent through FakeDNS path unexpectedly.
- Confirm local route stays direct.

### Test 4: HTTPS/SVCB

- Query A, AAAA, and HTTPS/SVCB for a known HTTP/3-capable domain.
- Confirm docs state whether QUIC/HTTP/3 is expected to work, downgrade, direct-route, or fail.

### Test 5: FakeDNS stale cache

- Start Xray.
- Resolve FakeDNS-enabled destination.
- Stop Xray.
- Flush OS/browser DNS cache.
- Confirm normal internet works after disabling the method.

### Test 6: DNS loop

- Ensure the DNS resolver target is not itself routed into the same local tunnel in a way that depends on DNS resolving itself.
- If detected, report `dns_loop_possible` in preflight.

## Success criteria

- Resolver timeout produces a clear result.
- Private/local DNS still works.
- FakeDNS cache recovery is documented.
- DNS rule tags are present.
- DNS validation runs in CI.
