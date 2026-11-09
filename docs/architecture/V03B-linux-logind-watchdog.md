# V03-B — Linux logind subscription and suspend-aware watchdog v0

**Status: review-gated Linux observer foundation. REAL system-bus subscription only when run locally with opt-in; NO Vaulty session integration or production readiness.**

V03-A established a fail-closed Rust lifecycle *model*, but did not connect to Linux's system bus. V03-B adds a separate, non-root, observation-only Python client, `tools/lifecycle/v03b_logind.py`, using the optional pure-Python `dbus-next` system-bus transport. Its output is **diagnostic only**, not an authenticated daemon-to-session capability. Neither the disabled default executable nor the non-activating Rust `Session` consumes this output. The Rust public `LOADED` constructor remains absent and OPEN-01, OPEN-15 and G1–G3 remain blocked.

## Supported behavior

- Connects directly to **system** D-Bus (no shell, no `dbus-monitor` output parsing). Subscribes to logind `Manager` and `Session` signals, relevant logind property changes and `org.freedesktop.DBus.NameOwnerChanged`.
- Installs matches **before** resolving the service owner's unique name and local session. Any security event while the startup snapshot is being assembled rejects observation (`STARTUP_RACE` or a stricter rejection), rather than treating an earlier sample as authorization.
- Resolves the local session through `GetSessionByPID(os.getpid())`; pins the returned object path and logind *unique bus owner* from `GetNameOwner`. Rejects owner changes, removed sessions, mismatched senders, malformed signals and untrusted path binding. Rechecks both owner and PID session on every watchdog cycle.
- Fails closed unless the session's systemd properties confirm the local UID, a locally seated non-remote `Class=user` session, active/unlocked `x11` or `wayland` mode, `CanLock=true`, and neither `PreparingForSleep` nor `PreparingForShutdown`. This **does not** prove the desktop compositor's lock is trustworthy or that every desktop sends a Lock signal.
- Treats lock, unlock, sleep (both start and wake), shutdown, session removal and relevant property changes as terminal observation events. A completed observation does not become a valid secret-use session.
- Watchdog polls the real system bus, including locked/active state, instead of treating mere process liveness as a trusted heartbeat. Every call is bounded (2-second individual bus-query timeout); a finite event queue rejects overflow. Uses Linux `CLOCK_BOOTTIME` to detect clock gaps across suspend/resume and reject stale observations.
- Avoids printing the session path, UID, service owner, raw signal payload, vault metadata or secrets. Any event/error causes a fixed failure classification; no PIN or hardware operation is performed. Root execution and non-Linux platforms are refused.

### Explicit gaps (not deferred silently)

1. **No daemon integration.** The Python process does not control, authenticate or mark the V03-A Rust lifecycle guard healthy. It never issues a token the daemon would accept. A secure same-process Rust D-Bus integration, or independently reviewed authenticated internal transport, is needed before any production LOADED state.
2. **No delay inhibitor.** `PrepareForSleep(true)` is observed but Vaulty cannot guarantee a daemon will complete key zeroization *before* actual suspend. A delayed inhibitor obtained and held by the trusted daemon is a separate integration requirement.
3. **Desktop lock limitations.** logind `Lock()` is a request to the compositor and `LockedHint` is set by the desktop environment. Some desktops may not propagate lock events correctly. This code therefore cannot alone certify secure lock propagation; actual Pop!_OS tests and independent fail-closed integration are needed.
4. **No end-to-end lifecycle enforcement.** The offline CI fake bus tests are not a controlled real sleep/unplug or compositor test. The observer never calls `Session.lock` across a trusted in-process boundary and cannot prevent secret operations in another process.
5. **No Windows/macOS equivalent**, authenticated client pairing, device trust, or process memory/core-dump hardening. No prior EV-023/EV-025 hardware evidence is promoted to authentication approval.

## Local non-secret observation (Linux desktop)

~~~sh
# Use a separate environment for this optional test; do NOT add to product lockfiles.
python3 -m venv "$HOME/.local/state/vaulty-v03b-venv"
"$HOME/.local/state/vaulty-v03b-venv/bin/python" -m pip install \
  -r tools/lifecycle/requirements-live.txt

# Requires an active unlocked logind-managed desktop session.
# No sudo, no real Vaulty credential, no raw session metadata recorded.
"$HOME/.local/state/vaulty-v03b-venv/bin/python" \
  tools/lifecycle/v03b_logind.py --observe-only --seconds 30 --interval 2

# Offline deterministic failure injection; no dbus-next required:
python3 -B -m unittest discover -s tools/lifecycle -p 'test_*.py' -v
~~~

Outputs `OBSERVED_ONLY` on a clean bounded observation or `FAIL_CLOSED`
with a fixed reason. **Neither means `READY`.** A watcher that refuses to start
because the local desktop/session does not expose required logind properties
is an acceptable conservative outcome; do not weaken the checks to force
success. Do not ask users to disable screen locking or change systemd policy.

## Evidence and review acceptance

| Acceptance | Evidence in this PR | Still missing |
| --- | --- | --- |
| A03B-01 direct bus and logind binding | Owner pin, PID-bound session and match subscriptions | Local live execution + trusted daemon ownership |
| A03B-02 startup race and malformed events | Offline fake-bus deterministic tests | Actual system bus replay/failure lab |
| A03B-03 listener loss and owner restart | Offline owner-change/disconnect, state and queue failure probes | OS integration during actual restart/disconnect |
| A03B-04 suspend/lock fail-closed | Signal/locked-hint and CLOCK_BOOTTIME watchdog | Delay inhibitor + synchronous daemon secret wipe proof |
| A03B-05 no release-gate escalation | Non-root read-only observer; inert Rust code; source manifest | OPEN-01/15 + G1–G3 separate independent approvals |

**Proposed follow-up:** V03-B1 — in-process Rust system bus integration + test harness
for real desktop sessions, with authenticated signal subscription, Trusted
LifecycleGuard activation *only after* a complete startup snapshot and
independent timeout enforcement. V03-B is the transport evidence foundation;
not a substitute for these controls.

## References

- [systemd logind D-Bus interface](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.login1.html)
- [dbus-next aio MessageBus API](https://python-dbus-next.readthedocs.io/en/latest/message-bus/aio-message-bus.html)
