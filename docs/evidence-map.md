# Evidence Map

## Purpose

Map repository evidence to the safeguards implemented around it. Use this table to see which docs, scripts, and tests back each operational conclusion.

This document maps repository evidence to the safeguards that are now implemented around it.

| Evidence | Conclusion | Implemented safeguard |
|---|---|---|
| Config defines `mixed-in` plus isolated Google/Fastly/Meta decrypt inbounds | Local ingress/decrypt graph exists | `validate_config.py`, `preflight.py`, and listener-binding docs validate local ports and loopback binding |
| Config uses certificate `usage: issue` with `mycert.crt` and `mycert.key` | Local certificate lifecycle is central | Certificate lifecycle docs, CA recovery guides, `mitm_trust.py`, and GUI certificate actions |
| Config uses DNS, FakeDNS, resolver aliases, localhost fallback, `serveStale`, and explicit Xray query strategy | DNS is a major runtime dependency | DNS resilience docs, DNS sweep, lab evidence harness, and FakeDNS recovery guide |
| Config uses service/provider routing groups | Route drift and provider drift are core risks | Route tags, route intent sync, provider status docs, provider dossier validation, and release evidence checks |
| Generated keys, logs, profiles, and geodata are local artifacts | They must not be committed accidentally | `.gitignore`, secret scan, repository structure tests, and release evidence rules |
| Certificate generation needs to stay easy | Usability and safety both matter | Batch/shell generation remains, while GUI and `mitm_trust.py` add status, pair checks, rotation, and trust instructions |
| Xray routing is ordered | First-match order can shadow later rules | Route graph verification and route rule linting |
| Xray supports multiple transports | Protocol expectations need clear boundaries | Protocol coverage docs, transport profiles, and protocol smoke tests |
| FakeDNS can create stale mappings | Normal internet access may look broken after exit | FakeDNS recovery guide and lab evidence checks |
| Android trust behavior varies by app | Browser success does not imply app success | Platform compatibility matrix and Android trust model docs |
| Provider policies can change | External drift can break routes | Provider status docs and provider policy validation |

## Related documents

| Document | Topic |
|---|---|
| [`release-evidence.md`](release-evidence.md) | Release validation workflow |
| [`reviewer-checklist.md`](reviewer-checklist.md) | Pre-merge verification |
| [`repository-structure.md`](repository-structure.md) | Tree and safeguard summary |
| [`reference/03-issues-risks-validation.md`](reference/03-issues-risks-validation.md) | Operational risks register |
