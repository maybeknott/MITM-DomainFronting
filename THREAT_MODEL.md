# Threat Model

## Purpose

State supported and unsupported use cases, sensitive assets, trust boundaries, and controls for the public repository, local Xray configuration, and release process.

## Scope

This threat model covers the public repository files, local Xray configuration, local certificate/key files, local listeners, DNS/FakeDNS behavior, troubleshooting scripts, and release process.

## Supported use cases

- User-controlled local testing.
- User-owned device configuration.
- Browser-oriented local operation where the user installs their own CA.
- Troubleshooting routing, DNS, protocol, and platform compatibility.
- Maintaining a public config repository with reproducible release validation.

## Unsupported or unsafe use cases

- Intercepting another person's traffic without explicit authorization.
- Sharing `mycert.key`.
- Distributing a shared CA/private key to many users.
- Running unauthenticated open relays.
- Collecting request bodies, cookies, credentials, or authorization headers for support.
- Bypassing app certificate pinning.
- Asking users to upload private keys or full decrypted traffic logs.

## Assets

| Asset | Sensitivity | Why it matters |
|---|---|---|
| `mycert.key` | Critical | Can issue certificates for the local trusted CA |
| `mycert.crt` | Medium | Safe to install locally, but must match user's key |
| Xray config | Medium | Determines routing and local listener behavior |
| DNS rules | Medium | Control domain resolution and route selection |
| Local ports | Medium | Should be loopback-only |
| Release artifacts | Medium | Users import and run them |
| Diagnostic output | Medium | May reveal setup/network details |

## Trust boundaries

| Boundary | Expected trust |
|---|---|
| User device | Trusted by user |
| Local loopback | Trusted local process boundary |
| LAN/public Wi-Fi | Not trusted |
| Remote websites/providers | Not controlled by repo |
| GitHub issues | Public/untrusted |
| Browser/app trust stores | Platform-dependent |

## Main risks and controls

| Risk | Control |
|---|---|
| Private key committed or posted | `.gitignore`, issue warnings, emergency rotation guide |
| Local listener exposed to LAN | explicit loopback binding, preflight check, firewall guide |
| Wrong CA installed | fingerprint verification guide |
| Expired CA | status check and rotation guide |
| DNS resolver timeout | fallback test and DNS resilience docs |
| FakeDNS stale cache | recovery guide |
| Route drift | rule tags and validation script |
| Geosite/GeoIP drift | release hashes and support matrix |
| Android app failure | compatibility matrix and app trust explanation |
| Provider policy change | provider status documentation and validation |
| Debug data over-sharing | redaction rules and issue template warnings |

## Maintainer boundaries

Maintainers should:

- review config changes carefully;
- reject private keys in PRs/issues;
- reject unauthenticated relay additions;
- keep release validation artifacts;
- keep documentation aligned with actual config behavior;
- avoid claiming unsupported apps or protocols work without testing.

## Architectural boundaries (evasion)

Per engineering policy in `docs/reference/02-decisions-evasion-engineering.md`:

- On-the-wire evasion is expressed primarily in **Xray configuration** (domain
  fronting, uTLS, REALITY, TLS record fragmentation) and optionally in privileged
  kernel shaping where explicitly consented — not via the Rust validation crate as
  a live byte forwarder.
- Trust, elevation, and telemetry remain **consent-based and local**. **Accepted:**
  profile-scoped trust and OPSEC modes with user opt-in. **Rejected:** silent
  DLL/`LD_PRELOAD` or covert system modification.
- Supported use remains user-controlled testing on user-owned devices; techniques
  aimed at intercepting third-party traffic without authorization stay unsupported.

## Traceability IDs

Use these IDs in `docs/reference/` normative statements (`[Mitigates: TM-NN]`).

| ID | Threat | Primary control | Reference |
|---|---|---|---|
| TM-01 | Local listener reachable from LAN | Loopback bind + preflight | `docs/listener-binding.md`, preflight |
| TM-02 | Cooperative proxy bypass (WebRTC, DNS, QUIC) | Track D TUN/firewall; probe labels | `03` PROTO-004 |
| TM-03 | Upstream DNS poisoning / captive DNS | Resolver fallback + FakeDNS design | `docs/dns-resilience.md` |
| TM-04 | Raw IP / system DNS bypassing proxy | FakeDNS `198.18.0.0/15` (TARGET) | `03` DNS-004 |
| TM-05 | Route misconfiguration deanonymizes or loops | Route linter + validate_config | `docs/routing-correctness.md` |
| TM-06 | Static TLS / JA3 fingerprint clustering | JA3 pool artifacts + Xray uTLS (Track A/B) | `03` PROTO-005 |
| TM-07 | Stateful DPI blocks uniform ClientHello | TLS `fragment` + REALITY (Track A) | `02` Part III §4 |
| TM-08 | Orphan Xray after supervisor exit | Windows Job Object; Linux `killpg` | `process_supervisor.py` |
| TM-09 | Machine-wide CA / trust-store IoC | Profile-scoped trust, CDP (Track D) | `03` CERT-004, ADR-0002 |
| TM-10 | Second live egress in Rust crate | ADR-0007/0008 rejection | `02` ADR-0007 |

## Related documents

| Document | Topic |
|---|---|
| [`docs/reference/02-decisions-evasion-engineering.md`](docs/reference/02-decisions-evasion-engineering.md) | Evasion engineering decisions |
| [`docs/sni-camouflage.md`](docs/sni-camouflage.md) | Camouflage SNI vs rejected injection |
| [`SECURITY.md`](SECURITY.md) | Vulnerability reporting |
| [`PRIVACY.md`](PRIVACY.md) | Diagnostic redaction |
