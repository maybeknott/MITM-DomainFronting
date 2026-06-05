# Pull Request Checklist

## Summary

Describe what changed and why.

## Type of change

- [ ] Documentation only
- [ ] Xray config change
- [ ] DNS/routing change
- [ ] Certificate-generation change
- [ ] Platform guide change
- [ ] Release/CI change

## Validation

- [ ] JSON parses.
- [ ] `python scripts/validate_config.py Xray-config/Xray-Cooperative-Overlay.json` passed.
- [ ] `python scripts/preflight.py --no-dns ...` was run or not applicable.
- [ ] `xray run -test -config Xray-config/Xray-Cooperative-Overlay.json` passed or reason not run is stated.
- [ ] No private keys, user certs, cookies, request bodies, or credentials are included.
- [ ] Route order was reviewed if routing changed.
- [ ] DNS behavior was reviewed if DNS changed.
- [ ] Platform compatibility docs were updated if behavior changed.
- [ ] Issue registry in `docs/reference/03-issues-risks-validation.md` updated if a limitation remains.

## Notes for reviewers

List route tags, DNS changes, affected platforms, and rollback notes.
