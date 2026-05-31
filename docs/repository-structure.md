# Repository Structure

## Goal

Keep the repository simple while making it easier to review, test, troubleshoot, and release. This structure does not require multiple generated configs or a complex build system. It keeps the current `Xray-config/MITM-DomainFronting.json` as the main user-facing config.

## Recommended tree

```text
MITM-DomainFronting/
  README.md
  SECURITY.md
  PRIVACY.md
  CHANGELOG.md
  SUPPORT_MATRIX.md
  KNOWN_ISSUES.md
  .gitignore

  Xray-config/
    MITM-DomainFronting.json
    certificate_generator.bat
    certificate_generator.sh
    mycert.crt                 # local only, ignored by git
    mycert.key                 # local only, ignored by git

  docs/
    architecture.md
    routing-correctness.md
    dns-resilience.md
    protocol-coverage.md
    platform-compatibility.md
    preflight-and-diagnostics.md
    decision-engine.md
    dns-profiles.md
    operating-profiles.md
    release-engineering.md
    release-evidence.md
    provider-status.md
    tun-operational-notes.md
    certificate-lifecycle.md
    ca-install-guide.md
    ca-verify-guide.md
    ca-rotate-guide.md
    ca-remove-guide.md
    ca-emergency-key-compromise.md
    ca-expired-certificate-recovery.md
    ca-wrong-certificate-recovery.md
    listener-binding.md
    firewall-and-network-testing.md
    fakedns-recovery.md
    assumptions-and-unknowns.md
    reviewer-checklist.md
    final-verdict-template.md
    evidence-map.md

  configs/
    compatibility.yml
    protocols.yml
    dns-edge-cases.yml
    dns-profiles.yml
    advanced-edge-cases.yml
    profiles.yml
    provider-status.example.yml
    release-checklist.yml

  providers/
    dns-resolvers.yml
    fastly.yml
    google.yml
    meta.yml

  scripts/
    preflight.py
    validate_config.py
    add_rule_tags.py
    mitm_trust.py
    check_dns.py
    decision_report.py
    generate_profiles.py
    validate_metadata.py
    build_release_manifest.py

  .github/
    ISSUE_TEMPLATE/
      bug.yml
      service-request.yml
      platform-setup.yml
    workflows/
      validate.yml
    PULL_REQUEST_TEMPLATE.md
```

## Why this structure

| Area | Why it exists | User impact | Maintainer impact |
|---|---|---|---|
| `Xray-config/` | Keeps the current simple import flow | No workflow disruption | Main config remains obvious |
| `docs/` | Keeps explanations out of the JSON | Easier troubleshooting | Lower duplicate issue volume |
| `scripts/` | Local checks before users open issues | Faster diagnosis | Reproducible reports |
| `configs/` | Structured compatibility and protocol facts | Clear expectations | Easier updates without rewriting README |
| `.github/` | Issue and CI hygiene | Better bug reports | Fewer unsafe or incomplete reports |

## Non-goals

This structure intentionally does not require:

- multiple runtime profiles;
- a config generator;
- a database;
- a server;
- telemetry;
- account login;
- automatic upload of diagnostics;
- automatic OS-wide certificate installation.

## Minimum adoption checklist

- [ ] Keep `Xray-config/MITM-DomainFronting.json` as the primary import file.
- [ ] Add `.gitignore` protection for local certs, keys, logs, and geodata.
- [ ] Add docs for routing, DNS, protocol support, platform compatibility, and certificate lifecycle.
- [ ] Add preflight script.
- [ ] Add config validation script.
- [ ] Add release checklist.
- [ ] Add issue templates that ask for version, platform, client, DNS, and redacted diagnostics.
