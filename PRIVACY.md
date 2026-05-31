# Privacy and Diagnostic Data

## Runtime data

The repository does not need telemetry, analytics, remote logging, or uploaded diagnostics to function.

## Local plaintext exposure

The method uses a local trusted CA and local TLS handling. For flows handled by the local tunnel, plaintext exists inside the user's own local process boundary before being repackaged. This is why the private key must remain local and why logs must avoid request bodies, cookies, tokens, and credentials.

## CA trust implication

Installing `mycert.crt` tells the OS/browser to trust certificates issued by the matching local `mycert.key`. If the key is exposed, rotate it and remove the old CA from trust stores.

## What the tool does not protect

This configuration does not guarantee:

- anonymity;
- protection from malicious browser extensions;
- protection from malware on the local device;
- protection if the private key is shared;
- compatibility with apps that ignore user CAs;
- compatibility with certificate-pinned apps;
- compatibility with every UDP/QUIC/WebRTC flow;
- stable behavior if providers change policy.

## Debug-log risks

Debug logs can accidentally include domains, timing, route decisions, IP addresses, or client metadata. They must not include request bodies, cookies, credentials, authorization headers, or private keys.

## Support redaction rules

Before posting an issue:

- remove full URLs with tokens;
- remove cookies;
- remove Authorization headers;
- remove request/response bodies;
- remove screenshots showing accounts, chats, tokens, QR codes, or private keys;
- do not upload `mycert.key`;
- share only route tags, platform details, version numbers, and redacted preflight output.

## Maintainer policy

Maintainers should delete or hide private keys and sensitive logs posted publicly, then instruct the user to rotate their CA.
