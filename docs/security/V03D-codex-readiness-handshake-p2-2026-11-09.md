# V03-D — Codex P2: operator action before observer readiness (2026-11-09)

**Disposition: ACCEPTED; corrected on open PR #29.** Final CI, independent
re-review and local Linux desktop evidence remain required. No production
Vaulty session or FIDO2 authorization is enabled.

## Finding

The former `v03d_capture.py` printed `RUNNING_OBSERVATION` **before**
calling `subprocess.run` for the Rust observer. The operator was instructed
to lock or suspend immediately after that premature marker. During Rust
startup, bus matches, the sleep delay inhibitor, session pinning and initial
snapshot may not be established. The operator could follow all instructions
but receive `UNSAFE_SESSION` or `STARTUP_SIGNAL_RACE` and an `INCOMPLETE`
receipt. This is a test-harness race, not evidence of successful lifecycle
lock enforcement.

## Accepted correction: non-authorizing, flushed handshake

The Rust `tools/lifecycle/v03c_rust/src/main.rs` emits exactly:

```text
V03-C: OBSERVER_READY; no session or credential authorized
```

It writes and **flushes** this line only after subscriptions are installed,
the delay inhibitor FD is held, the unique owner/local session and initial
properties have been checked, startup signal queues have been drained safely,
the initial watchdog has been set, and the observation loop is ready to
receive events.

The Python capture tool now starts the Rust child with `subprocess.Popen`,
reads only the bounded exact readiness line from stdout, and waits for the
handshake with a startup deadline. Only on successful readiness **and while
the process is still running** does it print `RUNNING_OBSERVATION` and
instruct the operator to trigger the selected lifecycle event.

No stdout/stderr from a failed child is echoed, embedded in a receipt or
accepted as a factor proof. The final observation receipt classifier now
requires the exact preceding readiness protocol for **both** idle/baseline
and event-mode evidence. A missing, misspelled or oversized marker,
EOF before readiness, early process exit or deadline expiry yields
`INCOMPLETE`, never an observed lock/suspend. An expiring observer is
terminated and its pipes closed. Redacted receipts record whether readiness
was observed and whether a lifecycle action prompt was issued only after it.

The marker is **diagnostic readiness**, not an authenticated daemon session,
a hardware assertion or a release-gate vote. The default vault executable
still has no production LOADED transition.

## Regression matrix

- Delayed synthetic readiness: operator callback occurs only after the marker.
- Startup failure prior to readiness: no operator callback, incomplete receipt.
- No readiness / hung child: bounded timeout, no prompt, child terminated.
- Spoofed, incorrect, or extra marker/output: no credited evidence.
- Normal baseline with readiness + finish: accepted as local idle observation.
- Exact ready + appropriate terminal event: accepted only for matching mode;
  absent marker, unexpected event, wrong exit code or extra output rejected.
- Rust CI compiles the flushed readiness handshake; no D-Bus call or actual
  vault use is required for the regression suite.

## Unchanged blockers

No live desktop lock, suspend, owner-loss or delay-inhibitor observation has
yet been received for this correction. There is no independent proof that a
real compositor reliably publishes signals or that secrets are wiped before
suspend. The Rust runner remains isolated from the production daemon and owns
a normal-built CLOSED session. OPEN-01, OPEN-15 and G1–G3 remain BLOCKED.
