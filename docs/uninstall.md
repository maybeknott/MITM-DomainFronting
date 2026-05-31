# Uninstall and Disable Guide

## Disable

1. Stop the client.
2. Disable system proxy or TUN/VPN mode.
3. Close browser tabs using the method.
4. Flush DNS cache if normal internet breaks.

## Remove local certificate trust

Follow `docs/ca-remove-guide.md`.

## Remove local files

```bash
python scripts/mitm_trust.py remove-local --cert Xray-config/mycert.crt --key Xray-config/mycert.key --yes
```

## Recover from FakeDNS stale cache

Follow `docs/fakedns-recovery.md`.
