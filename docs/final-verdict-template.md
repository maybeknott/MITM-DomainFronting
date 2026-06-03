# Final Verdict Template Per Release

## Purpose

Template for a release verdict: what changed, what was validated, known limitations, rollback steps, and a clear recommendation level for normal users.

## Release

Version: `v__`
Date: `YYYY-MM-DD`
Config SHA-256: `...`
Xray version tested: `...`
Geosite hash/version: `...`
GeoIP hash/version: `...`

## Verdict

Choose one:

- Recommended for normal users.
- Recommended only for users affected by a specific issue.
- Experimental.
- Not recommended; release kept for testing only.

## What changed

- ...

## What was validated

- [ ] JSON parse.
- [ ] Xray config test.
- [ ] Route reference validation.
- [ ] Required local ports.
- [ ] Certificate generation.
- [ ] Certificate verification.
- [ ] DNS resolver behavior.
- [ ] FakeDNS recovery.
- [ ] Windows test.
- [ ] Android test.
- [ ] macOS test.
- [ ] Linux test.

## Known limitations

- ...

## Known regressions

- ...

## Rollback

Rollback to: `v__`
Reason: `...`
Steps:

1. Download previous config.
2. Import previous config.
3. Keep existing local certificate unless rotation was part of the release.
4. Run preflight.

## Release conclusion

State clearly whether the release improves reliability, compatibility, DNS handling, routing clarity, or documentation without introducing unacceptable regressions.

## Related documents

| Document | Topic |
|---|---|
| [`release-evidence.md`](release-evidence.md) | Release validation commands |
| [`lab-evidence-checklist.md`](lab-evidence-checklist.md) | Lab scenario matrix |
| [`reviewer-checklist.md`](reviewer-checklist.md) | Pre-merge review gates |
| [`SUPPORT_MATRIX.md`](../SUPPORT_MATRIX.md) | Platform support claims |
