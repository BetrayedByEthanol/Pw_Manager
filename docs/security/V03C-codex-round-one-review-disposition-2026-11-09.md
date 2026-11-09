# V03-C — Codex review round one disposition (2026-11-09)

**Disposition: ACCEPT both P2 findings; corrected on open PR #28, pending final CI and independent re-review.** These source changes do not authorize real Vaulty credentials, approve OPEN-01/OPEN-15, or unblock G1–G3.

## P2-01: Version-dependent logind `CanLock` query

**Accepted.** The V03-C zbus review runner previously required
`org.freedesktop.login1.Session.CanLock` via `Properties.Get`. That
property is documented by newer systemd releases but absent from the
Ubuntu 24.04 interface XML identified by the reviewer. Requiring it caused
every such local observer run to fail during the startup snapshot.

**Fix:** Remove the mandatory query from the Rust V03-C observer, and
also from the earlier standalone Python V03-B observer to avoid retaining
the same compatibility defect. Keep the supported, typed session
`LockedHint`, `Active`, `State`, `Remote`, `Type`, `Class`, `User`,
`Seat`, and manager sleep/shutdown state checks. Explicitly subscribe to
logind Session Lock/Unlock signals. New pure Rust regression inputs exercise
active unlocked local desktop acceptance and locked/remote/greeter/tty
rejection; existing V03-B mock-bus tests now omit `CanLock` from their
snapshot altogether.

**Limit:** `LockedHint` is a session/desktop-reported hint, not an
attestation that a compositor responds to logind lock requests. Actual
desktop lock coverage remains unproved and must be validated before
production lifecycle assurance. Neither passing a snapshot nor subscribing
to signals permits LOADED.

## P2-02: Independent watchdog during slow health queries

**Accepted.** The prior runner awaited sequential owner, session and
Properties.Get calls inside the same `tokio::select!` timer branch
used to receive terminal logind signals. The individual 2-second timeouts
could accumulate. The after-the-fact uptime gap check detected eventual
lateness but did not lock promptly during an in-flight query.

**Fix:** The event loop now owns the `SessionSupervisor` and a
100-millisecond watchdog timer, while a **single bounded spawned Tokio
health probe** performs owner/session/snapshot validation and reports
only a non-authorizing result through a capacity-one MPSC channel.
No D-Bus await occurs inside the watchdog or signal branches.
The entire probe has a 4-second timeout, shorter than the 5-second
independent watchdog; its task is aborted on session termination.
The watchdog checks the last verified state with suspend-inclusive uptime
and calls `SessionSupervisor::tick` regardless of query progress.
Signals are selected with priority over health replies, so queued Lock,
Unlock, sleep, shutdown or ownership loss directly terminate and lock the
owned Rust session while the health task is pending. The elapsed
deadline is checked **before** accepting a health reply; a late result
cannot refresh an expired session.

**Regression cases:** synthetic long-blocked health probe while a
short watchdog expires; lock signal preempting a blocked health probe;
suspend-inclusive previous-tick and last-success deadlines; existing
V03-C supervisor test rejects a late positive health refresh.

**Limit:** The V03-C runner still owns only a non-unlockable CLOSED session
in ordinary builds, not the production Vaulty daemon. It has no logind delay
inhibitor or proved pre-suspend zeroization. The session-specific startup
subscription gap and real compositor reliability test remain independent
blockers; these changes must not be interpreted as making an active
production LOADED lifecycle safe.

## Validation before merge

- GitHub **Vaulty V03-C Rust Linux logind review** workflow: original
  Rust V03-C tests plus separately locked zbus runner tests.
- **Vaulty V02 candidate format**: source inventory and V03/V03-A/V03-C
  regression compatibility, V03-B offline fake-bus tests.
- **Vaulty V01 product safety**: legacy executable remains fail-closed.
- Codex re-review both corrected P2 findings at the final PR head.

No PIN, FIDO2 device, PRF output, VMK, DEK, real vault, or physical
suspend is required for these CI tests.
