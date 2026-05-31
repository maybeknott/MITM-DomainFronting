# Threat Model

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
| Provider policy change | provider status file and known issue entry |
| Debug data over-sharing | redaction rules and issue template warnings |

## Maintainer boundaries

Maintainers should:

- review config changes carefully;
- reject private keys in PRs/issues;
- reject unauthenticated relay additions;
- keep release validation artifacts;
- keep documentation aligned with actual config behavior;
- avoid claiming unsupported apps or protocols work without testing.
