# Wrong-Certificate Recovery

## Purpose

Fix browser privacy errors when a CA is installed but its fingerprint does not match the current `mycert.crt` and `mycert.key` pair. Compare fingerprints, remove stale trust entries, reinstall the current cert, and verify before restarting the client.

## Symptoms

- Browser shows certificate/privacy errors even though a CA is installed.
- `mycert.crt` was regenerated but the old CA remains installed.
- The installed CA fingerprint does not match the local file.
- Multiple old `mycert.crt` files exist.

## Diagnosis

Run:

```bash
python scripts/mitm_trust.py status --cert Xray-config/mycert.crt --key Xray-config/mycert.key
```

Write down the fingerprint. Then inspect the OS/browser trusted CA entry and compare the fingerprint.

## Fix

1. Stop the client.
2. Remove all old matching test CAs from OS/browser trust stores.
3. Install the current `Xray-config/mycert.crt`.
4. Verify fingerprint.
5. Restart client.
6. Test browser.

## Common causes

| Cause | Fix |
|---|---|
| Generated cert twice | Install the most recent cert matching the key |
| Copied cert from another device | Generate local cert/key pair and install that cert |
| Installed cert in OS but browser uses own store | Import into browser or enable browser OS trust |
| Android installed old cert | Remove old user credential and install current one |

## Related documents

| Document | Topic |
|---|---|
| [`ca-verify-guide.md`](ca-verify-guide.md) | Fingerprint verification steps |
| [`ca-install-guide.md`](ca-install-guide.md) | Platform install procedure |
| [`ca-remove-guide.md`](ca-remove-guide.md) | Remove stale trust entries |
| [`certificate-lifecycle.md`](certificate-lifecycle.md) | Cert/key mismatch lifecycle state |
