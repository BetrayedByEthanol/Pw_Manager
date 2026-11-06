# V01-A — interrupted legacy-vault write and native-host failure procedure

**Scope:** V01-A safety tests for the **disabled legacy VLT1 prototype**. These instructions do not certify its cryptography, create a recovery system, or authorize writing real credentials. Canonical V02/V04M must provide authenticated ancestry, anti-divergence and verified restore.

## What the writer actually does

The V01 writer takes a create-new mode-0600 `vault.lock`, writes and fsyncs a unique mode-0600 `vault.tmp-<uuid>`, copies the previously active ciphertext into `vault.previous-tmp-<uuid>`, fsyncs and renames it to `vault.previous`, fsyncs the parent, renames the new temp file to `vault`, and fsyncs the directory. The writer does not hold VMK between stages.

On a **recoverable pre-rename error**, the active ciphertext remains intact. On a **post-rename error**, an error return does **not** mean no commit: the active file may contain the new generation and `vault.previous` holds the old generation. The legacy previous-copy format has **no authenticated ancestry or validated reopen**, so the presence of those files is not proof of consistent contents.

## Manual stale lock / interrupted operation

1. Stop all Vaulty-related processes; verify no writer remains (operator inspection such as `ps`/`lsof`). **Do not delete a lock based only on age.**
2. Do not open the disabled prototype to test the file. Preserve encrypted byte-for-byte copies of `vault`, `vault.previous`, all `vault.tmp-*`, `vault.previous-tmp-*` and `vault.lock` in a separate private directory before any deletion. Record size, timestamps and checksums. Avoid copying into cloud locations or logs.
3. If a crash occurred before active rename, `vault` should still be the previous version. After active rename, determine which copy is newer **without blindly overwriting either**; use the future canonical authenticated verifier/migration before accepting either as trusted.
4. For a verified stale `vault.lock` with no active writer, after preserving copies, the operator may remove the stale lock to permit a **future reviewed** write. Never automatically steal/expire a lock from another process. If a path unexpectedly becomes a symlink or directory, treat it as suspicious and do not bypass the check.
5. Do not delete the only recoverable encrypted backup. Reconciliation or restore remains manual until V02/V04M provide authenticated ancestry, source version detection, verified reopen and safe rollback. Rotate any credentials affected by the previously discovered nonce reuse or secret logging as appropriate.

## V01-A deterministic evidence

The root unit tests inject failures immediately after temp sync, before backup rename, after backup sync, before active rename, after active rename and after parent sync. A child process exits abruptly after the backup is durable but **before** committing the active temp; it must leave the original active file, encrypted previous copy and a stale lock. Tests also reject symlinked target and parent paths, preserve unrelated synthetic file bytes and test default-binary non-operation.

These are **bounded test-path assertions**. The current writer is not race-free against a malicious same-user attacker who can swap directory entries between checks: V02 requires dirfd/openat/O_NOFOLLOW or platform-equivalent descriptor-based operations and a threat-model review. Simulated fault injection is not comprehensive power-loss/fsync ordering certification.

## Native-host default behavior

The installed native host is not a trusted vault authorization service. All recognized valid messages receive a framed `RELAY_ERROR` with `error.code=UNAVAILABLE` and **never** a password, unlocked status, synthetic successful save or durable receipt. Invalid length/JSON framing returns a generic framed error and unsuccessful process exit. Browser/extension input fields and origin strings remain untrusted; a future V07 authenticated extension-to-daemon E2E protocol must validate identity, gesture, origin/frame and operation separately. Never turn on mock persistence behavior through environment variables.
