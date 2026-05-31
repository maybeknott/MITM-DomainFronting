# Certificate Lifecycle

## Purpose

The config uses a local certificate authority certificate and private key. The certificate is trusted by the user, and the private key is used locally by Xray to issue certificates during local operation. This makes certificate lifecycle a reliability issue and a trust issue.

This guide preserves easy certificate generation. It does not remove the existing batch workflow. It adds verification, rotation, recovery, and cleanup procedures.

## Files

| File | Purpose | Git status |
|---|---|---|
| `mycert.crt` | Local CA certificate to trust | Must be ignored |
| `mycert.key` | Local CA private key | Must be ignored and kept private |

## Common commands

Status:

```bash
python scripts/mitm_trust.py status --cert Xray-config/mycert.crt --key Xray-config/mycert.key
```

Machine-readable status:

```bash
python scripts/mitm_trust.py status --cert Xray-config/mycert.crt --key Xray-config/mycert.key --json
```

Verify that `mycert.crt` and `mycert.key` are a matching pair:

```bash
python scripts/mitm_trust.py check-pair --cert Xray-config/mycert.crt --key Xray-config/mycert.key
```

Generate using Xray:

```bash
python scripts/mitm_trust.py generate --out-dir Xray-config
```

Rotate:

```bash
python scripts/mitm_trust.py rotate --out-dir Xray-config
```

Remove local files:

```bash
python scripts/mitm_trust.py remove-local --cert Xray-config/mycert.crt --key Xray-config/mycert.key --yes
```

Emergency local rotation:

```bash
python scripts/mitm_trust.py emergency --out-dir Xray-config
```

## Lifecycle states

| State | Meaning | Action |
|---|---|---|
| Missing cert/key | Not initialized | Generate cert/key |
| Cert exists, key missing | Broken | Regenerate or restore matching key |
| Key exists, cert missing | Broken | Regenerate both |
| Cert not trusted | Browser privacy error likely | Install/verify CA |
| Cert/key mismatch | Xray cannot issue certificates from the trusted CA | Regenerate both or restore matching pair |
| Cert expired | Browser privacy error likely | Rotate and reinstall |
| Cert expires soon | Future browser privacy errors | Rotate before expiration |
| Wrong cert installed | Browser trust mismatch | Remove wrong CA and install matching CA |
| Key shared or exposed | Compromised | Remove installed CA, rotate, and stop using old files |

## Minimum rule

The `.crt` can be installed locally by the user. The `.key` must remain private on the user's device. Never upload or paste `mycert.key` into issues, chats, screenshots, logs, or websites.

## Status fields

`mitm_trust.py status --json` reports:

- whether cert and key files exist;
- certificate SHA-256;
- certificate expiration date and days remaining when OpenSSL can parse it;
- whether expiration is within the warning window;
- key permission status on POSIX;
- whether the certificate and key public keys match.

It does not print private-key contents.
