# Expired Certificate Recovery

## Purpose

Recover when the local CA has expired and the browser begins showing certificate or privacy errors. Check expiry with `mitm_trust.py`, rotate to a new pair, reinstall trust, and verify before restarting the client.

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

## Related documents

| Document | Topic |
|---|---|
| [`ca-rotate-guide.md`](ca-rotate-guide.md) | Full rotation workflow |
| [`ca-verify-guide.md`](ca-verify-guide.md) | Post-rotation verification |
| [`certificate-lifecycle.md`](certificate-lifecycle.md) | Expiry warnings and status fields |
