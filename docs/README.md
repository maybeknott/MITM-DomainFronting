# Documentation index

Central map for Xray-Cooperative-Overlay documentation. Start here if you are new, maintaining the repo, or running lab evidence.

## Start here (pick one path)

| You are… | Start with | Then run |
|----------|------------|----------|
| **New user** | [getting-started.md](getting-started.md) | `py -3 main.py gui` or `py -3 main.py onboard` |
| **Farsi speaker** | [fa/quick-start.md](fa/quick-start.md) | Same GUI path on Dashboard |
| **Maintainer / release** | [reference/00-engineering-handbook.md](reference/00-engineering-handbook.md) | `py -3 main.py release-check` |
| **Lab / evasion work** | [intelligent-automation.md](intelligent-automation.md) | `py -3 main.py lab-prepare --allow-warn` |

## By topic

### Setup and daily use

| Document | Contents |
|----------|----------|
| [getting-started.md](getting-started.md) | English walkthrough, CLI map, glossary |
| [gui.md](gui.md) | Control Center screens, shortcuts, telemetry |
| [chromium-integration.md](chromium-integration.md) | Browser proxy and fingerprint checks |
| [windows-guide.md](windows-guide.md) | Windows-specific notes |
| [linux-guide.md](linux-guide.md) | Linux notes |
| [macos-guide.md](macos-guide.md) | macOS notes |
| [android-guide.md](android-guide.md) | Android / v2rayNG |
| [platform-compatibility.md](platform-compatibility.md) | Cross-platform matrix |

### Certificates and trust

| Document | Contents |
|----------|----------|
| [certificate-lifecycle.md](certificate-lifecycle.md) | Rotation and expiry overview |
| [ca-install-guide.md](ca-install-guide.md) | Install local CA (manual trust) |
| [ca-verify-guide.md](ca-verify-guide.md) | Verify trust alignment |
| [ca-rotate-guide.md](ca-rotate-guide.md) | Planned rotation |
| [ca-remove-guide.md](ca-remove-guide.md) | Remove CA from stores |
| [ca-emergency-key-compromise.md](ca-emergency-key-compromise.md) | Key compromise response |
| [ca-expired-certificate-recovery.md](ca-expired-certificate-recovery.md) | Expired cert recovery |
| [ca-wrong-certificate-recovery.md](ca-wrong-certificate-recovery.md) | Wrong cert pair recovery |

### Networking, DNS, routing

| Document | Contents |
|----------|----------|
| [routing-correctness.md](routing-correctness.md) | Route invariants and loopback rules |
| [dns-resilience.md](dns-resilience.md) | Resolver fallback and edge cases |
| [dns-profiles.md](dns-profiles.md) | Named DNS profiles |
| [fakedns-recovery.md](fakedns-recovery.md) | FakeDNS cache recovery |
| [listener-binding.md](listener-binding.md) | Loopback-only listeners |
| [protocol-coverage.md](protocol-coverage.md) | QUIC, UDP/443, WebRTC limits |
| [firewall-and-network-testing.md](firewall-and-network-testing.md) | WFP/nftables lab checklist |

### Profiles, policy, and automation

| Document | Contents |
|----------|----------|
| [operating-profiles.md](operating-profiles.md) | strict / balanced / compatibility / debug |
| [decision-engine.md](decision-engine.md) | Redacted decision reports |
| [intelligent-automation.md](intelligent-automation.md) | Advisor, playbooks, `main.py onboard` |
| [transport-profiles.md](transport-profiles.md) | Transport experiment profiles |
| [relay-and-metrics-policy.md](relay-and-metrics-policy.md) | Relay and metrics rules |
| [provider-status.md](provider-status.md) | CDN/provider drift register |

### Diagnostics and support

| Document | Contents |
|----------|----------|
| [preflight-and-diagnostics.md](preflight-and-diagnostics.md) | Preflight, health probe, checks table |
| [troubleshooting.md](troubleshooting.md) | Symptom → cause → fix |
| [local-telemetry.md](local-telemetry.md) | GUI telemetry scope |
| [lab-evidence-checklist.md](lab-evidence-checklist.md) | Lab bundle scenarios |
| [evidence-map.md](evidence-map.md) | Evidence artifact map |

### Release and repository

| Document | Contents |
|----------|----------|
| [release-engineering.md](release-engineering.md) | Build and release workflow |
| [release-evidence.md](release-evidence.md) | Release validation bundle |
| [repository-structure.md](repository-structure.md) | Directory layout contract |
| [reference/generated-files.md](reference/generated-files.md) | Committed vs generated files |
| [reference/maintainer-map.md](reference/maintainer-map.md) | Code ↔ test ↔ doc ownership |
| [uninstall.md](uninstall.md) | Remove local artifacts |

### Engineering reference (policy and architecture)

| Document | Contents |
|----------|----------|
| [reference/00-engineering-handbook.md](reference/00-engineering-handbook.md) | Glossary, tiers, validation commands |
| [reference/01-architecture-runtime-delivery.md](reference/01-architecture-runtime-delivery.md) | Runtime graph, tracks A–D |
| [reference/02-decisions-evasion-engineering.md](reference/02-decisions-evasion-engineering.md) | ADRs and evasion specs |
| [reference/03-issues-risks-validation.md](reference/03-issues-risks-validation.md) | Issues and closure register |
| [rust-stream-core-baseline.md](rust-stream-core-baseline.md) | Rust validation crate scope |
| [sni-camouflage.md](sni-camouflage.md) | SNI camouflage inspector |

## Automation commands (quick reference)

```powershell
py -3 main.py probe --json          # readiness + intelligent block
py -3 main.py advise --text         # human-readable recommendations
py -3 main.py onboard               # newcomer playbook (dry-run: --dry-run)
py -3 main.py onboard --persona maintainer
py -3 main.py lab-prepare --allow-warn
py -3 main.py audit
py -3 main.py test
py -3 main.py release-check
```

Plans are persisted locally at `.local-state/advisor-plan.latest.json` (redacted; safe to review before sharing).

## Editing rules

- **Policy** → edit under `docs/reference/`.
- **Procedures** → edit matching `docs/*.md` guide.
- Do not duplicate ADR text in operational docs; link once to the canonical file.
