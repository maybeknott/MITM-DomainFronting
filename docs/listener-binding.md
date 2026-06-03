# Listener Binding and Local Port Exposure

## Purpose

Keep local inbounds on loopback so proxy and decrypt ports are not reachable from other devices on a LAN or public Wi-Fi. This document lists required ports, recommended `listen` fields, and verification commands.

## Required local ports

| Port | Expected tag | Expected exposure |
|---|---|---|
| 10808 | `mixed-in` | loopback-only |
| 11666 | `tls-decrypt-google-h11` | loopback-only |
| 11777 | `tls-decrypt-google-h2` | loopback-only |
| 11888 | `tls-decrypt-fastly-h2` | loopback-only |
| 11999 | `tls-decrypt-meta-h2` | loopback-only |
| metrics/debug ports if ever added | metrics/debug | loopback-only |

## Recommended config pattern

Add explicit `listen` fields to each inbound:

```json
{
  "tag": "mixed-in",
  "listen": "127.0.0.1",
  "port": 10808,
  "protocol": "mixed"
}
```

For the tunnel inbounds:

```json
{
  "tag": "tls-decrypt-google-h11",
  "listen": "127.0.0.1",
  "port": 11666,
  "protocol": "tunnel"
}
```

```json
{
  "tag": "tls-decrypt-google-h2",
  "listen": "127.0.0.1",
  "port": 11777,
  "protocol": "tunnel"
}
```

## Verify listener binding

Run:

```bash
python scripts/preflight.py --config Xray-config/MITM-DomainFronting.json --cert Xray-config/mycert.crt --key Xray-config/mycert.key --no-dns
```

Manual checks:

Windows:

```powershell
netstat -ano -p tcp | findstr ":10808 :11666 :11777 :11888 :11999"
```

Linux:

```bash
ss -ltnp | grep -E ':10808|:11666|:11777|:11888|:11999'
```

macOS:

```bash
lsof -nP -iTCP:10808 -sTCP:LISTEN
lsof -nP -iTCP:11666 -sTCP:LISTEN
lsof -nP -iTCP:11777 -sTCP:LISTEN
lsof -nP -iTCP:11888 -sTCP:LISTEN
lsof -nP -iTCP:11999 -sTCP:LISTEN
```

Pass condition:

```text
127.0.0.1:10808
127.0.0.1:11666
127.0.0.1:11777
127.0.0.1:11888
127.0.0.1:11999
```

Warning condition:

```text
0.0.0.0:10808
*:10808
LAN_IP:10808
```

## API/admin endpoints

Do not expose unauthenticated admin/API endpoints. If metrics or debug endpoints are added later, bind them to `127.0.0.1` only and keep them disabled by default unless needed for local troubleshooting.

## Related documents

| Document | Topic |
|---|---|
| [`firewall-and-network-testing.md`](firewall-and-network-testing.md) | LAN and public Wi-Fi exposure tests |
| [`preflight-and-diagnostics.md`](preflight-and-diagnostics.md) | Automated loopback checks |
| [`routing-correctness.md`](routing-correctness.md) | Redirect rules to tunnel ports |
| [`THREAT_MODEL.md`](../THREAT_MODEL.md) | Local listener risk controls |
