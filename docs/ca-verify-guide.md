# CA Verify Guide

## Goal

Confirm that the certificate file, local key, and installed trusted certificate match what the config expects.

## Step 1: local status

```bash
python scripts/mitm_trust.py status --cert Xray-config/mycert.crt --key Xray-config/mycert.key
```

Expected:

- cert exists;
- key exists;
- fingerprint displayed;
- expiry displayed if OpenSSL is available;
- key is not world-readable on POSIX systems.

## Step 2: check config references

Open `Xray-config/MITM-DomainFronting.json` and confirm the certificate section references:

```json
"certificateFile": "mycert.crt",
"keyFile": "mycert.key"
```

## Step 3: check browser trust

Open the browser certificate manager and find the installed certificate. Confirm the SHA-256 fingerprint matches the local `mycert.crt` fingerprint.

## Step 4: check common mismatch cases

| Symptom | Likely cause | Fix |
|---|---|---|
| Browser privacy error | CA not installed or wrong CA installed | Install correct cert and verify fingerprint |
| Worked before, now fails | Cert expired or rotated without reinstall | Rotate/reinstall and verify |
| Windows works, Firefox fails | Firefox trust store differs | Import into Firefox or enable OS trust as applicable |
| Browser works, app fails | App ignores user CA or pins cert | Treat as app compatibility limitation |
| Android browser works, app fails | Android user CA limitation or pinning | Use browser path or app-specific support only if app cooperates |

## Step 5: support-safe output

When opening an issue, share only:

```text
cert_exists: yes/no
key_exists: yes/no
cert_fingerprint_prefix: first 12 hex chars only
cert_expiry: YYYY-MM-DD if available
platform:
browser:
client:
```

Never share `mycert.key`.
