# V03-C — Trusted Rust Lifecycle Integration & Session Lock Enforcement v0

**Status: review candidate. Rust in-process safety event integration and a separate opt-in, logind-connected Rust observer; no production unlock path.**

## Summary

V03-B provides an observation-only Python system-bus client. V03-C adds
`src/v03c.rs`, a Rust **SessionSupervisor that exclusively owns a V03 Session**
and applies terminal lifecycle events directly to it. Lock, unlock, sleep,
wake, shutdown, owner changes, lost bus, malformed event, snapshot failure
and watchdog expiry all immediately call `Session::on_lifecycle`, which
drops loaded metadata, masked VERS shares and any pending operation. Once
terminated, it never resumes or grants authorization. A successful poll or
snapshot is **diagnostic only** and does not set V03's private monitor-live
flag, produce a factor proof, or enable LOADED.

`tools/lifecycle/v03c_rust/` is a separate, optional Rust review runner using
`zbus` and `tokio`. It holds the SessionSupervisor and the D-Bus observer
in **one process**. No Python-to-Rust health token, shell-printed event or
unauthenticated IPC crosses the boundary.

**This is not the final Vaulty daemon:** the runner owns a CLOSED session and
normal-built Rust still has no LOADED constructor. Real credential access
remains disabled. The Rust default executable and native host remain inert.

## Event and health boundaries

The runner:
- Opens the **system** bus, subscribes to logind manager, session and
  properties signals and NameOwnerChanged, then checks the service's unique
  name and PID-bound logind session. Revalidates bindings every second.
- Uses a direct, **uncached** D-Bus Properties.Get for `User`, `Seat`,
  `Active`, `LockedHint`, lock capability hints (not universally exposed), `Remote`, `Class`, `Type`,
  `State`, `PreparingForSleep` and `PreparingForShutdown`.
- Requires a local, non-remote, active, unlocked, seat-backed `user`
  session on X11 or Wayland belonging to the invoking process's UID.
  The logind owner is checked for change on every poll.
- Routes terminal signals in-process directly to SessionSupervisor.
  Unexpected changes also terminate; it never silently weakens policy to
  continue watching.
- Samples Linux `/proc/uptime` (suspend-inclusive boottime) and rejects
  polling/startup gaps. All calls have 2-second timeouts. The Rust
  SessionSupervisor separately enforces an independent maximum missed
  health deadline and calls `Session::poll`.
- Uses a bounded, read-only command with no credential input or vault file
  handling; only prints `OBSERVED_ONLY` or `FAIL_CLOSED`, never a session
  identifier, raw D-Bus message, PIN or token metadata.

### Important limitations and reviewer blockers

1. **No production daemon or LOADED activation.** The review runner and
   SessionSupervisor are in the same Rust process, but normal code cannot
   enter LOADED and the existing product daemon/native messaging does not
   call the V03-C monitor. The in-process unit tests use synthetic V02 keys.
2. **No sleep delay inhibitor.** Watching `PrepareForSleep(true)` does not
   prove all sensitive state was destroyed *before* kernel suspend. Actual
   Rust daemon use must acquire/hold a logind delay inhibitor and test
   suspend lock sequencing and process/core-dump hardening before G2.
3. **Race and desktop coverage:** Manager/owner signals are subscribed before
   the snapshot, but the specific Session path is resolved before the Session
   stream is subscribed. Concurrent Lock+Unlock in that gap can escape both
   signal observation and a later unlocked snapshot. logind LockedHint is
   supplied by desktop compositor and may not reflect all desktop events.
   **Do not treat startup as a production-ready safe-unlock gate** without
   subscription-order hardening and real Pop!_OS desktop failure tests.
4. **Dependency and lockfile:** The review-only Rust driver is isolated in
   its own Cargo manifest. It is not compiled into the root executable.
   The candidate's separately generated Cargo.lock is now committed
   and all integration checks run with `--locked`. Any dependency changes
   require a separate audit; CI compilation is not a supply-chain review.
5. **No independent approval:** OPEN-01, OPEN-15, OPEN-HW-ASSURANCE,
   OPEN-PRF-SALT, G1–G3 all remain blocked. No new READY routes, owner
   approvals, recovery capabilities or hardware attestation follow.

## Verification

Root+isolated synthetic Rust tests:
```sh
cargo test --manifest-path tools/v02_verifier/Cargo.toml --locked --lib -- v03c
cargo check --manifest-path tools/v02_verifier/Cargo.toml --locked --all-targets
```

Review-only Rust logind driver (no secrets):
```sh
cargo test --manifest-path tools/lifecycle/v03c_rust/Cargo.toml --locked --all-targets
cargo run --manifest-path tools/lifecycle/v03c_rust/Cargo.toml --locked -- \
  --observe-only --seconds 20
```

Run the second command only on an unlocked, logind-managed Linux desktop.
Any FAIL_CLOSED output is safe and informative; never weaken signal checks to
force an observation success. Root product CI must confirm the default
executable stays inert.

**Next:** V03-C1 harden early session-signal subscriptions and implement the
delay inhibitor in a trusted daemon; add real desktop logind failure-injection
and independent session/crypto review. No production unlock until then.


### P2 compatibility correction (review round)
The mandatory logind Session `CanLock` Properties.Get was removed from the
Rust and previous Python observers. Although modern systemd interfaces may
expose it, Ubuntu 24.04's installed Session XML does not. Both now require
supported, typed `LockedHint` plus logind session/owner state and explicitly
subscribed Lock/Unlock signals instead. These are **observations**, not a
cryptographic or compositor-backed promise that screen locking is reliable.
A real desktop integration test remains required for production G2.
