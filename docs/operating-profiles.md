# Operating Profiles

## Purpose

Describe optional generated profiles that make failure policy explicit for testing and support. The primary import file remains `Xray-config/Xray-Cooperative-Overlay.json`; profiles adjust UDP/443 handling, catch-all behavior, and logging without replacing the main workflow.

The primary import file remains `Xray-config/Xray-Cooperative-Overlay.json`. Additional profiles make failure policy explicit for testing and support.

## Profiles

| Profile | Purpose | Unsupported non-private traffic | UDP/443 / QUIC policy | Logs |
|---|---|---|---|---|
| `strict` | Safer fail-closed testing | Block | Block | Minimal |
| `balanced` | Current user-friendly behavior | Direct | Direct with documented warning | Minimal |
| `compatibility` | Captive portal or app troubleshooting | Direct | Direct with warning | Minimal |
| `debug` | Deterministic redacted diagnostics | Direct | Block to surface QUIC mismatch | `info` log level, no access log |

## Generated Files

```text
Xray-config/Xray-Cooperative-Overlay.strict.json
Xray-config/Xray-Cooperative-Overlay.balanced.json
Xray-config/Xray-Cooperative-Overlay.compatibility.json
Xray-config/Xray-Cooperative-Overlay.debug.json
```

Regenerate them with:

```bash
python scripts/generate_profiles.py --base Xray-config/Xray-Cooperative-Overlay.json
```

## Alternate Local Ports

If `10808`, `11666`, or `11777` are already occupied, generate a temporary alternate-port set instead of editing only one listener by hand. The generator shifts the public mixed inbound and the internal decrypt listeners together, including redirect outbounds that point back to those local listeners:

```bash
python scripts/generate_profiles.py \
  --base Xray-config/Xray-Cooperative-Overlay.json \
  --out-dir Xray-config \
  --port-offset 100 \
  --suffix .altports
```

That example creates files such as `Xray-Cooperative-Overlay.strict.altports.json` using `10908`, `11766`, and `11877`. Do not commit local alternate-port outputs unless they are intentionally promoted as supported profiles.

## Safety Rules

- Profiles must not include private keys or generated certificates.
- Debug profile must not enable request-body, cookie, authorization-header, or decrypted payload logging.
- Strict profile must not silently direct-route unknown non-private traffic.
- Compatibility profile must not be presented as more private or safer than strict.
- Profile docs, `configs/profiles.yml`, generated JSON, and validator expectations must be updated together.

## Triage Mapping

| Detected condition | Suggested profile | Rule |
|---|---|---|
| First-time user | `strict` | Safer fail-closed baseline |
| DNS primary timeout | `balanced` | Uses tagged DNS fallback |
| Captive portal | `compatibility` | Temporary troubleshooting only |
| Android browser | `balanced` | Browser-oriented, app claims separate |
| Debugging route behavior | `debug` | Redacted diagnostics only |
| Missing CA trust | stop | Do not auto-install silently |
| Weak key permissions | stop | Fix before running |

## Evasion lab profiles (optional)

For controlled lab testing against DPI or leak labels, regenerate:

```bash
python scripts/generate_evasion_profiles.py
python main.py lab-prepare --allow-warn
```

See [`intelligent-automation.md`](intelligent-automation.md) for advisor commands and `main.py advise`.

## Related documents

| Document | Topic |
|---|---|
| [`intelligent-automation.md`](intelligent-automation.md) | Advisor, lab-prepare, strategy winner |
| [`decision-engine.md`](decision-engine.md) | Profile in decision report |
| [`protocol-coverage.md`](protocol-coverage.md) | UDP/443 and QUIC expectations |
| [`dns-profiles.md`](dns-profiles.md) | DNS profile names |
| [`configs/profiles.yml`](../configs/profiles.yml) | Profile policy source |
