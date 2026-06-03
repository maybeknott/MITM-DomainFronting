# Emergency Key-Compromise Guide

## Purpose

Respond when `mycert.key` may have been exposed through git, issues, chat, screenshots, or an untrusted environment. Treat the old CA as compromised: remove trust, rotate locally, and verify the new fingerprint before resuming.

## Trigger

Use this guide if `mycert.key` was uploaded, pasted, emailed, committed to git, screenshotted, shared, or generated on an untrusted website.

## Impact

Anyone with the private key and a trusted copy of the matching CA context may impersonate certificates within that local trust boundary. Treat the old CA as compromised.

## Immediate actions

1. Stop the client.
2. Disconnect from untrusted networks if concerned.
3. Remove the old CA from OS/browser trust stores.
4. Delete old `mycert.crt` and `mycert.key` from the active config folder.
5. Generate a new CA locally.
6. Install the new CA.
7. Verify new fingerprint.
8. Search the repository and issue history for accidental key exposure.

## Commands

```bash
python scripts/mitm_trust.py emergency --out-dir Xray-config
```

This command rotates local files. You must still remove the old trusted CA from each OS/browser trust store manually.

## Git exposure response

If a key was committed:

1. Remove it from the latest commit.
2. Rotate the CA immediately.
3. Treat the old key as permanently compromised.
4. Add `.gitignore` protection.
5. Consider repository history cleanup if appropriate.

## Issue exposure response

If a user posts a key in an issue:

1. Hide/delete the comment if possible.
2. Tell the user to rotate immediately.
3. Do not reuse that key.
4. Do not download or test the user's key.

## Related documents

| Document | Topic |
|---|---|
| [`ca-rotate-guide.md`](ca-rotate-guide.md) | Standard rotation steps |
| [`ca-remove-guide.md`](ca-remove-guide.md) | Remove compromised CA from trust stores |
| [`SECURITY.md`](../SECURITY.md) | Vulnerability and secret-handling policy |
| [`certificate-lifecycle.md`](certificate-lifecycle.md) | Key exposure lifecycle state |
