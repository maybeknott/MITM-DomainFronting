# Wrong-Certificate Recovery

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
