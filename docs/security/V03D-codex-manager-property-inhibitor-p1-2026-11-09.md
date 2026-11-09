# V03-D — Codex P1 manager-property/inhibitor collision (2026-11-09)

**Disposition: ACCEPTED. Source correction in PR #29, awaiting final CI, re-review and live Linux observation.** No hardware evidence or production vault capability is asserted by this disposition.

## Finding

systemd v255 `inhibitor_start()` emits a Manager `PropertiesChanged` notification for `DelayInhibited` whenever a delay inhibitor begins. The V03-D review runner subscribes to manager property signals before acquiring that inhibitor. Its prior startup drain treated *every* manager property notification as `STARTUP_SIGNAL_RACE`, while its runtime branch treated every manager property notification as a terminal `SnapshotRejected`.

Therefore merely acquiring its own required delay inhibitor could make a benign idle observation fail before entering the event loop, or fail shortly afterwards if the message was delivered later.

Source evidence: `systemd/systemd` v255 `src/login/logind-inhibit.c`, `bus_manager_send_inhibited_change()` / `inhibitor_start()` (emits `DelayInhibited` for delay-mode inhibitors). `DelayInhibited` is string-typed (`s`) in logind Manager interface source.

## Accepted correction

`tools/lifecycle/v03c_rust/src/main.rs` now has **one** `manager_property_event` classifier used by both:

- startup `drain_manager_properties` (after the unique logind owner is pinned and before accepting a snapshot);
- the runtime `manager_prop_signals.next()` event arm.

The classifier requires the exact unique logind owner sender, manager object path, `org.freedesktop.DBus.Properties.PropertiesChanged` member/interface and a decodable `(s, a{sv}, as)` body referring to `org.freedesktop.login1.Manager`. It only ignores a **nonempty** change/invalidated set whose property names are exclusively `DelayInhibited`, with expected D-Bus string value signature `s` for any changed value.

A mixed `DelayInhibited` plus `PreparingForSleep` or `PreparingForShutdown` event is **never** ignored. Changes or invalidations of sleep/shutdown properties, unknown properties and wrong values stay terminal. An empty, malformed or wrongly addressed message, wrong sender or wrong embedded interface also remains fail-closed.

This avoids broad suppression of Manager.PropertiesChanged and does not weaken the separate `Manager.PrepareForSleep/Shutdown` signal handling or the independent watchdog.

## Negative tests

The V03-C/Rust review binary's offline tests cover:
- changed/invalidated `DelayInhibited` alone is non-terminal;
- sleep/shutdown changed or invalidated remains terminal;
- mixed benign+security/unknown manager property events remain terminal;
- empty, wrong-interface and wrong-type manager-property bodies remain terminal;
- fully encoded D-Bus PropertiesChanged message with correct sender/path is ignored only when safe, while wrong sender/path and sleep change fail closed.

**CI is offline only**: these are constructed signals and Rust tests, not a live Ubuntu/POSIX system-bus run. The existing V03-D operator baseline, screen-lock, optional suspend and disposable-VM disconnect receipts still must be obtained with a clean branch and reviewed; do not claim those observations until supplied.

## Security status

PR #29 remains review-gated; production `LOADED` is still unavailable.
No real VMK/DEK/PRF key operation or process-memory zeroization is proven.
Independent OPEN-01/OPEN-15, G1–G3 and OS desktop verification remain **BLOCKED**.
