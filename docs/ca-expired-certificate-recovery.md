# Expired Certificate Recovery

## Symptoms

- Browser suddenly shows certificate/privacy errors.
- Previously working setup fails after a date change.
- `mitm_trust.py status` shows the certificate is expired.

## Check expiry

```bash
python scripts/mitm_trust.py status --cert Xray-config/mycert.crt --key Xray-config/mycert.key
```

If OpenSSL is installed, the script prints certificate expiry.

## Recovery

1. Stop the client.
2. Rotate certificate and key:

```bash
python scripts/mitm_trust.py rotate --out-dir Xray-config
```

3. Remove the expired CA from OS/browser trust store.
4. Install the new CA.
5. Verify fingerprint.
6. Restart the client.
7. Test a supported browser flow.

## Prevent recurrence

- Add expiry date to local notes.
- Check expiry before each release or major troubleshooting session.
- Prefer rotation over trying to extend an old CA.
