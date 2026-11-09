# V03-D — Linux Lifecycle Hardening & Physical Verification v0

**Status: review-gated source candidate + operator-only evidence intake.** A real
Linux session bus is used only when an operator explicitly runs the standalone
review driver. This milestone does **not** activate a production Vaulty daemon,
VMK/DEK access, trusted FIDO2 adapters, vault writes or credential filling.

## Purpose

V03-C merged same-process Rust session revocation and a logind observer, but
left two serious implementation gaps: **Lock+Unlock startup race** (session
signals were subscribed only after GetSessionByPID) and **no suspend delay
inhibitor**. V03-D addresses both in the isolated Rust logind review runner,
and creates a redacted operator intake for actual desktop testing.

### 1. Early lifecycle signal subscription

Before querying the logind owner or local session path, the runner registers
bus match rules for **all logind Session.Lock/Unlock signals**, and session
PropertiesChanged events under
`/org/freedesktop/login1/session` (using
`zbus::MessageStream::for_match_rule` with a broad path namespace).
The logind manager, manager property and owner-change streams are also already
subscribed. Only after these streams are installed does the runner:

1. acquire its delay inhibitor (mandatory or fail closed);
2. read the logind unique owner and `GetSessionByPID`;
3. check the local, active, unlocked seat and supported properties;
4. revalidate the same unique owner and session;
5. reject **all buffered session/owner/lifecycle startup events** on the
   early streams (even if another session caused a session signal), but
   ignore a separately validated, inhibitor-only `DelayInhibited` manager
   property notification produced by our own required delay inhibitor;
6. inspect the startup boottime/window and begin the observer loop.

**Manager inhibitor bookkeeping (Codex P1):** Acquiring the required delay
inhibitor itself causes systemd/logind to emit
`PropertiesChanged(DelayInhibited)`. A manager-property classifier shared
by the startup drain and runtime event loop ignores **only** a well-formed,
unique-owner-authenticated `org.freedesktop.login1.Manager` change or
invalidation containing exclusively string-typed `DelayInhibited`.
`PreparingForSleep`, `PreparingForShutdown`, mixed/unknown properties,
invalid value types, invalidated security properties, unexpected sender,
incorrect manager path or malformed signal body still fail closed.
This avoids rejecting our own inhibitor setup without suppressing actual
sleep/shutdown notifications. The
[Codex P1 disposition](../security/V03D-codex-manager-property-inhibitor-p1-2026-11-09.md)
tracks the correction and required live-baseline verification.

There is no session-identity-dependent subscription **after** the PID query.
Subsequent events are checked for the exact pinned local session path and
unique owner. Unexpected path/sender for the pinned path, connection failure
or malformed message causes terminal revocation. This removes the specific
unsubscribed period where a transient Lock+Unlock could be lost before the
initial snapshot.

**Boundaries:** Bus queues are finite; lifecycle events during
bootstrap refuse startup. Only the narrowly validated `DelayInhibited`
bookkeeping exception is non-terminal; a real desktop can still send no Lock events or
provide stale LockedHint. This is *not* cryptographic session authentication.
The runner remains a review executable with a CLOSED-only production session.

### 2. logind sleep/shutdown delay inhibitor

The runner now explicitly requests
`Manager.Inhibit("sleep:shutdown", "Vaulty V03-D review", ...,
"delay")` and holds the returned owned file descriptor during observation.
If the call is rejected, times out or returns no valid FD, the runner
fails closed. No system-wide power policy is modified.

The Rust `InhibitedSupervisor` owns both the `SessionSupervisor` and the
inhibitor FD. On `PrepareForSleep(true)` or other terminal events it:

1. synchronously invokes `SessionSupervisor::on_event`, which calls
   `Session::on_lifecycle`, clearing all V03-owned pending operations and
   loaded material in the **synthetic** test case;
2. only **after** the controller is LOCKED drops the FD to release logind's
   delay lock;
3. never reestablishes a LOADED session on resume or error.

The same ordering applies on early failure and Rust scope drop, preventing
the explicit inhibitor from being freed before the controller is revoked.
Offline tests use mock FD Drop observers to check exact one-time release
and terminal ownership behavior.

**Critical limitation:** systemd ignores even a delay inhibitor after
`InhibitDelayMaxSec` (normally five seconds), and certain kernel/forced
suspend scenarios bypass logind. There is no guarantee of crash-time zeroing
or pre-suspend wipe of a **real production** LOADED vault, because the
optional runner does not have such a vault. The test confirms a real
inhibitor can be requested/held; it is not a formal pre-suspend security
certification.

References:
- [systemd Inhibitor Locks](https://systemd.io/INHIBITOR_LOCKS/)
- [logind D-Bus interface](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.login1.html)

### 2a. Operator observation readiness handshake (Codex P2)

The local Python evidence harness must **not** prompt for screen lock,
suspend or logind restart until the Rust observer is actually listening.
The earlier `RUNNING_OBSERVATION` marker was printed before launching
the child and could induce false `UNSAFE_SESSION` or `STARTUP_SIGNAL_RACE`
receipts when the operator acted too quickly.

The Rust runner now emits exactly
`V03-C: OBSERVER_READY; no session or credential authorized`, flushed
**after** it establishes signal subscriptions, holds the delay inhibitor,
pins the logind owner/session, checks startup state, drains queued startup
events and sets the initial watchdog. It does not emit a READY marker
on errors during initialization.

The Python capture tool uses a bounded read of this exact line from the
child process, rather than preemptively printing its own marker. Only when
the marker arrives and the observer remains running does it print
`RUNNING_OBSERVATION`; **only then** may the operator trigger the
selected lifecycle event. If no valid marker arrives within the finite
startup deadline, the child is stopped and the receipt is `INCOMPLETE`
without an action prompt.

The receipt classifier additionally requires the exact READY line before
a baseline finish or terminal event can be recorded as a local observation.
Receipts record `observer_ready_handshake` and
`operator_action_prompted_after_ready` as test bookkeeping, not
authorization. The marker is neither a proof that a production daemon is
safe nor an invitation to unlock a real vault.

See [Codex P2 disposition](../security/V03D-codex-readiness-handshake-p2-2026-11-09.md).

### 3. Operator physical/Linux tests

The **read-only** Rust executable remains opt-in, non-root, and must be
operated on an active unlocked logind-managed Linux desktop. No YubiKey,
Vaulty password, real vault, PID, token identifier, seat name, bus owner,
home directory path, or other raw desktop metadata is collected as evidence.

After checking out the PR branch and confirming a clean working tree:

```sh
export PYTHONDONTWRITEBYTECODE=1
python3 -B -m unittest discover -s tools/lifecycle -p 'test_*.py' -q

install -d -m 700 "$HOME/.local/state/vaulty-v03d"
OUT="$(mktemp -d "$HOME/.local/state/vaulty-v03d/run-XXXXXX")"

# Baseline: no lock/suspend while the observer runs.
python3 -B -I tools/lifecycle/v03d_capture.py \
  --mode baseline --seconds 30 \
  --receipt "$OUT/baseline.json" --hardware-test

# Lock case: DO NOT act at the startup/preparation message.
# Use the desktop's lock control only after RUNNING_OBSERVATION.
# Unlock normally afterwards, then read only the redacted receipt.
python3 -B -I tools/lifecycle/v03d_capture.py \
  --mode lock --seconds 60 \
  --receipt "$OUT/screen-lock.json" --hardware-test

# OPTIONAL suspend: on a test machine with saved work and a confirmed
# recovery path, manually request Suspend only after RUNNING_OBSERVATION.
# Never auto-trigger suspend from the verification utility.
python3 -B -I tools/lifecycle/v03d_capture.py \
  --mode suspend --seconds 60 \
  --receipt "$OUT/suspend.json" --hardware-test

# OPTIONAL disconnect/owner-restart: disposable VM only.
# Do not restart systemd-logind on a primary workstation.
python3 -B -I tools/lifecycle/v03d_capture.py \
  --mode disconnect --seconds 60 \
  --receipt "$OUT/disconnect.json" --hardware-test
```

The script first compiles the **locked** isolated review executable,
asks for explicit TEST confirmation, **waits for Rust OBSERVER_READY**, and
never invokes a sleep, lock, or service restart action itself. The operator
manually triggers an event **only after** RUNNING_OBSERVATION, never while
the runner is preparing. It writes an exclusive 0600 receipt in an existing private 0700
directory and refuses to overwrite previous evidence. It checks the Git
working tree is clean and records the full commit SHA.

Expected narrow redacted classifications:
- `baseline` / normal exit → `LOCAL_IDLE_OBSERVATION_REPORTED`
- `lock` / `SESSION_LOCK` → `LOCAL_TERMINAL_EVENT_REPORTED`
- `suspend` / `SLEEP_START` → `LOCAL_TERMINAL_EVENT_REPORTED`
- `disconnect` / `LOGIND_OWNER_CHANGED` or `BUS_DISCONNECTED` →
  `LOCAL_TERMINAL_EVENT_REPORTED`
- Any unexpected, unclassified or unsuccessful observation → `INCOMPLETE`.

A failure to start (e.g., unsupported desktop, permission failure, already
locked, inhibitor denied) is **not** evidence of correct locking. A generic
SNAPSHOT_REJECTED is not proof of a Lock or Sleep signal. Do not weaken
validation rules merely to make the test pass. Never share raw D-Bus traces
or console contents if they unexpectedly contain sensitive details; share
only the reviewed redacted JSON receipt.

### 4. Evidence boundaries and acceptance

| Requirement | Candidate source/offline proof | Independent evidence still needed |
| --- | --- | --- |
| A03D-01 Startup race | All-session signal subscriptions precede PID lookup; reject queued startup Lock/Unlock; match rule/source test | Actual rapid lock/unlock on Linux and verifier review |
| A03D-02 Inhibitor | Owned sleep:shutdown delay FD, fail-closed acquisition, synchronous session lock before FD drop, mock FD tests | Live inhibitor and pre-suspend transition, power-cycle safety and compositor reliability |
| A03D-03 Monitoring | V03-C independent watchdog, no blocking health probes, owner/session checks | Actual lock/suspend/disconnect and watchdog fault injection on test desktop |
| A03D-04 Receipts | Rust emits flushed READY only after full initialization; Python waits with deadline and emits action prompt only afterward; no READY/early failure is INCOMPLETE; private no-overwrite redacted mode-specific receipts and offline tests | Operator local runs; independent review and repeatability |
| A03D-05 Safety gates | No public V03 LOADED constructor, no real secret backend, locked CI | G1–G3, OPEN-01/15, actual daemon lifecycle and memory hardening |

**No source merge or operator receipt is itself a READY vote.** Security
approvals remain **OPEN-01/OPEN-15 BLOCKED, G1–G3 BLOCKED**. V03-D does not
resolve trusted device enrollment, actual VERS/DEK lifetime, process core
dump hardening, recovery consent or end-to-end native/browser authorization.
