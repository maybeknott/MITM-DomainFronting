# CA Rotate Guide

## When to rotate

Rotate the local CA when:

- the certificate expired;
- the private key may have been shared;
- the wrong certificate was installed;
- the key file permissions were unsafe for a long time;
- moving to a new device and wanting a clean local CA;
- troubleshooting persistent trust mismatch.

## Rotation steps

1. Stop v2rayN/v2rayNG/Xray.
2. Back up current files locally if needed:

```bash
mkdir -p Xray-config/cert-backups
cp Xray-config/mycert.crt Xray-config/cert-backups/mycert.crt.$(date +%Y%m%d%H%M%S).bak
cp Xray-config/mycert.key Xray-config/cert-backups/mycert.key.$(date +%Y%m%d%H%M%S).bak
```

3. Generate new files:

```bash
python scripts/mitm_trust.py rotate --out-dir Xray-config
```

4. Remove the old trusted CA from OS/browser trust store.
5. Install the new `mycert.crt`.
6. Verify the new fingerprint.
7. Start the client again.
8. Test a known supported browser flow.

## Windows quick rotation

```powershell
python scripts\mitm_trust.py rotate --out-dir Xray-config
```

Then reinstall `Xray-config\mycert.crt` into the intended trust store.

## Failure handling

| Failure | Fix |
|---|---|
| Xray binary not found | Place generator script in Xray/v2rayN bin folder or set `XRAY_BIN` |
| New cert generated but browser still fails | Remove old CA from trust store and install new CA |
| New key missing | Regenerate both cert and key |
| Permission error | Run from writable directory or choose another output directory |
