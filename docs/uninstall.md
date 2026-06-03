# Uninstall and Disable Guide

## Purpose

Disable the method safely: stop the client, clear proxy or TUN settings, remove local CA trust, delete local cert files, and recover DNS if normal internet access breaks after exit.

## Disable

1. Stop the client.
2. Disable system proxy or TUN/VPN mode.
3. Close browser tabs using the method.
4. Flush DNS cache if normal internet breaks.

## Remove local certificate trust

Follow [`ca-remove-guide.md`](ca-remove-guide.md).

## Remove local files

```bash
python scripts/mitm_trust.py remove-local --cert Xray-config/mycert.crt --key Xray-config/mycert.key --yes
```

## Recover from FakeDNS stale cache

Follow [`fakedns-recovery.md`](fakedns-recovery.md).

## Related documents

| Document | Topic |
|---|---|
| [`ca-remove-guide.md`](ca-remove-guide.md) | Trust-store removal by platform |
| [`fakedns-recovery.md`](fakedns-recovery.md) | DNS cache recovery |
| [`certificate-lifecycle.md`](certificate-lifecycle.md) | Local file lifecycle |
