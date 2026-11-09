//! V03-C same-process Rust system-bus logind observer. NO vault unlocking.
#![forbid(unsafe_code)]
//! This runner owns a Rust SessionSupervisor and a CLOSED Session. It never
//! constructs LOADED, authorizes a client or forwards D-Bus output as proof
//! of authorization. All external D-Bus errors become fixed failure codes.
use futures_util::{FutureExt, StreamExt};
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::io::Write;
use std::time::{Duration, Instant};
use tokio::time::{MissedTickBehavior, timeout};
use vaulty_v02_candidate_verifier::v03::{Session, SessionLimits};
use vaulty_v02_candidate_verifier::v03c::{MonitorPhase, SessionSupervisor, TerminalEvent};
use zbus::{Connection, MatchRule, Message, MessageStream, Proxy,
    message::Type as MessageType, zvariant::{OwnedFd, OwnedObjectPath}};

const SERVICE: &str = "org.freedesktop.login1";
const MANAGER: &str = "/org/freedesktop/login1";
const DBUS: &str = "org.freedesktop.DBus";
const DBUS_PATH: &str = "/org/freedesktop/DBus";
const MANAGER_IFACE: &str = "org.freedesktop.login1.Manager";
const SESSION_IFACE: &str = "org.freedesktop.login1.Session";
const PROPERTIES_IFACE: &str = "org.freedesktop.DBus.Properties";

type Outcome<T> = Result<T, &'static str>;

/// Lifetime-coupled safety: on *all* exits after the delay FD is acquired,
/// revoke the Rust-owned session before closing the inhibitor. This includes
/// D-Bus errors, task cancellation, early returns and panic unwinding.
/// The review runner still only owns a CLOSED production session.
struct InhibitedSupervisor<F> {
    supervisor: SessionSupervisor,
    inhibitor: Option<F>,
}
impl<F> InhibitedSupervisor<F> {
    fn new(supervisor: SessionSupervisor, inhibitor: F) -> Self {
        Self { supervisor, inhibitor: Some(inhibitor) }
    }
    fn on_event(&mut self, event: TerminalEvent) {
        self.supervisor.on_event(event);
        self.release_after_revocation();
    }
    fn release_after_revocation(&mut self) {
        // A revoked controller must already be LOCKED before the inhibitor
        // is allowed to close. SessionSupervisor::on_event is synchronous.
        if self.supervisor.monitor_phase() == MonitorPhase::Terminated {
            debug_assert_eq!(
                self.supervisor.phase(),
                vaulty_v02_candidate_verifier::v03::Phase::Locked,
            );
            drop(self.inhibitor.take());
        }
    }
}
impl<F> std::ops::Deref for InhibitedSupervisor<F> {
    type Target = SessionSupervisor;
    fn deref(&self) -> &Self::Target { &self.supervisor }
}
impl<F> std::ops::DerefMut for InhibitedSupervisor<F> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.supervisor }
}
impl<F> Drop for InhibitedSupervisor<F> {
    fn drop(&mut self) {
        if self.supervisor.monitor_phase() != MonitorPhase::Terminated {
            self.supervisor.on_event(TerminalEvent::BusDisconnected);
        }
        self.release_after_revocation();
    }
}



async fn bounded<T>(future: impl Future<Output = zbus::Result<T>>) -> Outcome<T> {
    timeout(Duration::from_secs(2), future).await
        .map_err(|_| "DBUS_TIMEOUT")?.map_err(|_| "DBUS_FAILED")
}
async fn current_owner(bus: &Proxy<'_>) -> Outcome<String> {
    bounded(bus.call("GetNameOwner", &(SERVICE,))).await
}
async fn local_session(manager: &Proxy<'_>) -> Outcome<OwnedObjectPath> {
    bounded(manager.call("GetSessionByPID", &(std::process::id(),))).await
}

/// The lock is an owned file descriptor. Dropping it is the ONLY way we
/// release the delay: no global polkit/systemd policy is changed. Holding
/// it until AFTER the synchronous Rust session lock is essential.
async fn acquire_delay_inhibitor(manager: &Proxy<'_>) -> Outcome<OwnedFd> {
    bounded(manager.call(
        "Inhibit",
        &("sleep:shutdown", "Vaulty V03-D review",
          "Revoke the in-process Vaulty session before sleep or shutdown",
          "delay"),
    )).await
}

/// Install match rules BEFORE any local session object lookup; otherwise
/// Lock+Unlock can occur between GetSessionByPID and subscription.
async fn early_session_stream(
    connection: &Connection, interface: &str,
) -> Outcome<MessageStream> {
    let rule = MatchRule::builder()
        .msg_type(MessageType::Signal)
        .sender(SERVICE).map_err(|_| "INVALID_MATCH_RULE")?
        .interface(interface).map_err(|_| "INVALID_MATCH_RULE")?
        .path_namespace("/org/freedesktop/login1/session")
            .map_err(|_| "INVALID_MATCH_RULE")?
        .build();
    bounded(MessageStream::for_match_rule(rule, connection, Some(256))).await
}
async fn property<T>(proxy: &Proxy<'_>, name: &str) -> Outcome<T>
where T: TryFrom<zbus::zvariant::OwnedValue>,
{
    // Read the live property directly from logind, never a proxy cache.
    let props = bounded(Proxy::new(proxy.connection(), SERVICE,
        proxy.path().as_str(), PROPERTIES_IFACE)).await?;
    let raw: zbus::zvariant::OwnedValue = bounded(props.call(
        "Get", &(proxy.interface().as_str(), name))).await?;
    raw.try_into().map_err(|_| "INVALID_PROPERTY")
}
/// Validate only properties supported by the target logind interface.
/// These are OBSERVATIONS, not a certificate that a desktop compositor
/// implements a reliable lock screen. The logind Session Lock/Unlock stream
/// must also have been subscribed before snapshot reads commence.
fn acceptable_session_state(
    uid: u32, own_uid: u32, seat: &str, seat_path: &str,
    locked: bool, active: bool, remote: bool,
    state: &str, kind: &str, class: &str, sleeping: bool, shutdown: bool,
) -> bool {
    uid == own_uid && !seat.is_empty()
        && seat_path.starts_with("/org/freedesktop/login1/seat/")
        && !locked && active && !remote
        && !sleeping && !shutdown && state == "active"
        && class == "user" && matches!(kind, "x11" | "wayland")
}

async fn safe_snapshot(manager: &Proxy<'_>, session: &Proxy<'_>) -> Outcome<()> {
    let (uid, _): (u32, OwnedObjectPath) = property(session, "User").await?;
    let (seat, seat_path): (String, OwnedObjectPath) = property(session, "Seat").await?;
    // LockedHint and the subscribed Lock/Unlock signals are supported on
    // Ubuntu 24.04's logind interface. CanLock is version-dependent and
    // absent from that release, so it must not be a mandatory property.
    // LockedHint is only a compositor-supplied hint, NOT an attestation that
    // the desktop will reliably lock; production remains blocked.
    let (locked, active, remote): (bool, bool, bool) = (
        property(session, "LockedHint").await?,
        property(session, "Active").await?,
        property(session, "Remote").await?,
    );
    let (state, kind, class): (String, String, String) = (
        property(session, "State").await?,
        property(session, "Type").await?,
        property(session, "Class").await?,
    );
    let (sleeping, shutdown): (bool, bool) = (
        property(manager, "PreparingForSleep").await?,
        property(manager, "PreparingForShutdown").await?,
    );
    let own_uid = std::fs::metadata("/proc/self")
        .map_err(|_| "NO_KERNEL_UID")?.uid();
    if !acceptable_session_state(
        uid, own_uid, &seat, seat_path.as_str(), locked, active, remote,
        &state, &kind, &class, sleeping, shutdown,
    ) {
        return Err("UNSAFE_SESSION");
    }
    Ok(())
}
fn sender(message: &Message) -> Option<String> {
    message.header().sender().map(ToString::to_string)
}
fn path(message: &Message) -> Option<String> {
    message.header().path().map(ToString::to_string)
}
fn member(message: &Message) -> Option<String> {
    message.header().member().map(ToString::to_string)
}
fn classify_manager(message: &Message, owner: &str) -> TerminalEvent {
    if sender(message).as_deref() != Some(owner)
        || path(message).as_deref() != Some(MANAGER)
    {
        return TerminalEvent::MalformedMessage;
    }
    match member(message).as_deref() {
        Some("PrepareForSleep") => match message.body().deserialize::<bool>() {
            Ok(true) => TerminalEvent::SleepStart,
            Ok(false) => TerminalEvent::SleepEnd,
            _ => TerminalEvent::MalformedMessage,
        },
        Some("PrepareForShutdown") => match message.body().deserialize::<bool>() {
            Ok(true) => TerminalEvent::ShutdownStart,
            Ok(false) => TerminalEvent::ShutdownEnd,
            _ => TerminalEvent::MalformedMessage,
        },
        Some("SessionRemoved") => TerminalEvent::SessionRemoved,
        _ => TerminalEvent::MalformedMessage,
    }
}
fn classify_session(message: &Message, owner: &str, local: &str) -> TerminalEvent {
    if sender(message).as_deref() != Some(owner)
        || path(message).as_deref() != Some(local)
    {
        return TerminalEvent::MalformedMessage;
    }
    match member(message).as_deref() {
        Some("Lock") => TerminalEvent::SessionLock,
        Some("Unlock") => TerminalEvent::SessionUnlock,
        _ => TerminalEvent::MalformedMessage,
    }
}
fn event_classification(event: Option<TerminalEvent>) -> &'static str {
    match event {
        Some(TerminalEvent::SessionLock) => "SESSION_LOCK",
        Some(TerminalEvent::SessionUnlock) => "SESSION_UNLOCK",
        Some(TerminalEvent::SleepStart) => "SLEEP_START",
        Some(TerminalEvent::SleepEnd) => "SLEEP_END",
        Some(TerminalEvent::ShutdownStart) => "SHUTDOWN_START",
        Some(TerminalEvent::ShutdownEnd) => "SHUTDOWN_END",
        Some(TerminalEvent::SessionRemoved) => "SESSION_REMOVED",
        Some(TerminalEvent::LogindOwnerChanged) => "LOGIND_OWNER_CHANGED",
        Some(TerminalEvent::BusDisconnected) => "BUS_DISCONNECTED",
        Some(TerminalEvent::MalformedMessage) => "MALFORMED_SIGNAL",
        Some(TerminalEvent::SnapshotRejected) => "SNAPSHOT_REJECTED",
        Some(TerminalEvent::SessionMismatch) => "SESSION_MISMATCH",
        Some(TerminalEvent::WatchdogOverdue) => "WATCHDOG_EXPIRED",
        None => "UNKNOWN",
    }
}

fn uptime() -> Outcome<f64> {
    // Linux /proc/uptime first value includes suspend; unlike Instant this
    // catches suspend gaps even when no logind signal could be processed.
    let data = std::fs::read_to_string("/proc/uptime")
        .map_err(|_| "NO_BOOTTIME_CLOCK")?;
    let first: f64 = data.split_whitespace().next()
        .ok_or("NO_BOOTTIME_CLOCK")?.parse()
        .map_err(|_| "NO_BOOTTIME_CLOCK")?;
    if !first.is_finite() || first < 0.0 { return Err("NO_BOOTTIME_CLOCK"); }
    Ok(first)
}
/// Check session state on a SEPARATE task. No long D-Bus await may run in
/// the event/watchdog select loop, which owns and revokes SessionSupervisor.
/// This is not a grant of authorization: even a fully successful probe leaves
/// the underlying production session unable to become LOADED.
async fn live_health_probe(
    connection: Connection, expected_owner: String, expected_session: OwnedObjectPath,
) -> Outcome<()> {
    let bus = bounded(Proxy::new(&connection, DBUS, DBUS_PATH, DBUS)).await?;
    let manager = bounded(Proxy::new(&connection, SERVICE, MANAGER, MANAGER_IFACE)).await?;
    let session = bounded(Proxy::new(
        &connection, SERVICE, expected_session.as_str(), SESSION_IFACE,
    )).await?;
    if current_owner(&bus).await? != expected_owner
        || local_session(&manager).await? != expected_session
    {
        return Err("SESSION_MISMATCH");
    }
    safe_snapshot(&manager, &session).await?;
    // A service restart or session replacement mid-query is a denial, not
    // a valid heartbeat (individual property calls may span time).
    if current_owner(&bus).await? != expected_owner
        || local_session(&manager).await? != expected_session
    {
        return Err("SESSION_MISMATCH");
    }
    Ok(())
}

fn uptime_deadline_expired(previous: f64, last_good: f64, now: f64, seconds: f64) -> bool {
    !previous.is_finite() || !last_good.is_finite() || !now.is_finite()
        || now < previous || now < last_good
        || now - previous >= seconds || now - last_good >= seconds
}

fn drain<'a>(stream: &mut zbus::proxy::SignalStream<'a>) -> bool {
    loop {
        match stream.next().now_or_never() {
            Some(Some(_)) | Some(None) => return true,
            None => return false,
        }
    }
}

/// A logind delay inhibitor itself triggers the manager's
/// PropertiesChanged(DelayInhibited) notification. This is bookkeeping, not
/// a lock/sleep event, and MUST NOT fail startup or runtime monitoring.
/// Only a trusted, well-formed Manager.PropertiesChanged containing solely
/// that property may be ignored. Every other change stays terminal.
fn classify_manager_property_fields(
    changed_iface: &str,
    changed: &HashMap<String, zbus::zvariant::OwnedValue>,
    invalidated: &[String],
) -> Option<TerminalEvent> {
    if changed_iface != MANAGER_IFACE || (changed.is_empty() && invalidated.is_empty()) {
        return Some(TerminalEvent::MalformedMessage);
    }
    if changed.keys().chain(invalidated.iter()).all(|key| key == "DelayInhibited")
        // systemd's DelayInhibited property has D-Bus type 's'. Even a
        // trusted logind sender must not make us ignore a malformed value.
        && changed.values().all(|value| value.value_signature().to_string() == "s")
    {
        return None;
    }
    // PreparingForSleep / PreparingForShutdown remain fail-closed, including
    // invalidations. Unknown manager properties are also terminal rather
    // than creating a permissive allowlist of unreviewed notifications.
    Some(TerminalEvent::SnapshotRejected)
}

fn manager_property_event(message: &Message, owner: &str) -> Option<TerminalEvent> {
    if sender(message).as_deref() != Some(owner)
        || path(message).as_deref() != Some(MANAGER)
        || message.header().interface().map(|v| v.as_str()) != Some(PROPERTIES_IFACE)
        || member(message).as_deref() != Some("PropertiesChanged")
    {
        return Some(TerminalEvent::MalformedMessage);
    }
    let parsed: Result<
        (String, HashMap<String, zbus::zvariant::OwnedValue>, Vec<String>), _
    > = message.body().deserialize();
    match parsed {
        Ok((changed_iface, changed, invalidated)) =>
            classify_manager_property_fields(&changed_iface, &changed, &invalidated),
        Err(_) => Some(TerminalEvent::MalformedMessage),
    }
}

/// Startup and runtime must apply the EXACT same classifier. The observer
/// will not reject its own delay-inhibitor change, but cannot ignore sleep,
/// shutdown, unknown manager state or a corrupt/untrusted notification.
fn drain_manager_properties(
    stream: &mut zbus::proxy::SignalStream<'_>, owner: &str,
) -> bool {
    loop {
        match stream.next().now_or_never() {
            Some(Some(message)) => {
                if manager_property_event(&message, owner).is_some() {
                    return true;
                }
            }
            Some(None) => return true,
            None => return false,
        }
    }
}

/// Startup safety: any session signal (even another user's) is conservatively
/// a reason to reject initialization, since we had not pinned a target yet.
/// A stream error or closed stream is also fail-closed.
fn drain_early_session_stream(stream: &mut MessageStream) -> bool {
    match stream.next().now_or_never() {
        None => false,
        Some(_) => true,
    }
}

/// Only the pinned session is relevant after startup. Bad sender on the
/// pinned path fails closed. Signals from other sessions are ignored.
fn session_event_for_target(
    message: &Message, owner: &str, target: &str,
) -> Option<TerminalEvent> {
    if path(message).as_deref() != Some(target) { return None; }
    Some(classify_session(message, owner, target))
}
fn property_event_for_target(
    message: &Message, owner: &str, target: &str,
) -> Option<TerminalEvent> {
    if path(message).as_deref() != Some(target) { return None; }
    Some(if sender(message).as_deref() == Some(owner) {
        TerminalEvent::SnapshotRejected
    } else {
        TerminalEvent::MalformedMessage
    })
}
async fn monitor(seconds: u64) -> Outcome<()> {
    let limits = SessionLimits::new(Duration::from_secs(20),
        Duration::from_secs(90)).map_err(|_| "INVALID_SESSION_LIMIT")?;
    let controller = SessionSupervisor::new(Session::new(limits),
        Duration::from_secs(5)).map_err(|_| "INVALID_WATCHDOG")?;
    let start = Instant::now();
    let started_uptime = uptime()?;
    let connection = bounded(Connection::system()).await?;
    let dbus = bounded(Proxy::new(&connection, DBUS, DBUS_PATH, DBUS)).await?;
    let manager = bounded(Proxy::new(&connection, SERVICE, MANAGER, MANAGER_IFACE)).await?;
    // Subscribe to the owner/manager before consulting the initial snapshot.
    let mut owner_signals = bounded(dbus.receive_signal_with_args(
        "NameOwnerChanged", &[(0, SERVICE)])).await?;
    let mut manager_signals = bounded(manager.receive_all_signals()).await?;
    let manager_properties = bounded(Proxy::new(
        &connection, SERVICE, MANAGER, PROPERTIES_IFACE)).await?;
    let mut manager_prop_signals = bounded(manager_properties.receive_all_signals()).await?;
    // Broad session-path subscriptions are installed *before* resolving the
    // local session. They retain any initial Lock/Unlock or LockedHint change.
    let mut session_signals = early_session_stream(&connection, SESSION_IFACE).await?;
    let mut session_prop_signals =
        early_session_stream(&connection, PROPERTIES_IFACE).await?;
    // Request a delay inhibitor before accepting ANY observation. A missing
    // FD or rejected Inhibit call is a hard failure, not a silent downgrade.
    let mut controller = InhibitedSupervisor::new(
        controller, acquire_delay_inhibitor(&manager).await?,
    );
    let owner = current_owner(&dbus).await?;
    if !owner.starts_with(':') { return Err("INVALID_LOGIND_OWNER"); }
    let session_path = local_session(&manager).await?;
    if !session_path.as_str().starts_with("/org/freedesktop/login1/session/") {
        return Err("INVALID_LOCAL_SESSION");
    }
    let session = bounded(Proxy::new(
        &connection, SERVICE, session_path.as_str(), SESSION_IFACE)).await?;
    // No session-specific subscriptions are installed after PID resolution:
    // the all-session-path streams above cover the full startup interval.
    safe_snapshot(&manager, &session).await?;
    if current_owner(&dbus).await? != owner
        || local_session(&manager).await? != session_path
    { return Err("STARTUP_BINDING_CHANGED"); }
    if drain(&mut owner_signals) || drain(&mut manager_signals)
        || drain_manager_properties(&mut manager_prop_signals, &owner)
        || drain_early_session_stream(&mut session_signals)
        || drain_early_session_stream(&mut session_prop_signals)
    { return Err("STARTUP_SIGNAL_RACE"); }
    let u = uptime()?;
    if u < started_uptime || u - started_uptime > 15.0
        || start.elapsed() > Duration::from_secs(15)
    { return Err("STARTUP_WATCHDOG_GAP"); }
    controller.observe_snapshot().map_err(|_| "UNVERIFIED_SESSION")?;
    // The watchdog and event receivers must stay responsive even if a
    // health query is delayed. A single bounded probe runs on a separate
    // Tokio task, and returns ONLY a non-authorizing result via this channel.
    // In contrast to awaiting D-Bus inside the timer branch, there is no
    // query future capable of starving the lock/suspend/owner signal arms.
    let (probe_tx, mut probe_results) = tokio::sync::mpsc::channel::<Outcome<()>>(1);
    let mut probe_task: Option<tokio::task::JoinHandle<()>> = None;
    let mut next_probe = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut previous_uptime = uptime()?;
    let mut last_good_uptime = previous_uptime;
    let stop_at = Instant::now() + Duration::from_secs(seconds);
    // Diagnostic handshake for the local V03-D evidence harness ONLY.
    // This is reached after early subscriptions, inhibitor acquisition,
    // session/owner validation, startup drains and watchdog setup. The
    // unbuffered flush happens BEFORE the operator is instructed to act.
    // Never interpret this as trusted Vaulty session/factor authorization.
    {
        let mut out = std::io::stdout().lock();
        writeln!(out, "V03-C: OBSERVER_READY; no session or credential authorized")
            .map_err(|_| "READINESS_WRITE_FAILED")?;
        out.flush().map_err(|_| "READINESS_WRITE_FAILED")?;
    }
    loop {
        tokio::select! {
            biased;
            message = owner_signals.next() => {
                controller.on_event(message.map_or(
                    TerminalEvent::BusDisconnected,
                    |_| TerminalEvent::LogindOwnerChanged,
                ));
            }
            message = manager_signals.next() => {
                controller.on_event(message.map_or(TerminalEvent::BusDisconnected,
                    |m| classify_manager(&m, &owner)));
            }
            message = session_signals.next() => {
                match message {
                    Some(Ok(msg)) => {
                        if let Some(event) =
                            session_event_for_target(&msg, &owner, session_path.as_str())
                        { controller.on_event(event); }
                    }
                    _ => controller.on_event(TerminalEvent::BusDisconnected),
                }
            }
            message = manager_prop_signals.next() => {
                match message {
                    Some(msg) => {
                        if let Some(event) = manager_property_event(&msg, &owner) {
                            controller.on_event(event);
                        }
                    }
                    None => controller.on_event(TerminalEvent::BusDisconnected),
                }
            }
            message = session_prop_signals.next() => {
                match message {
                    Some(Ok(msg)) => {
                        if let Some(event) =
                            property_event_for_target(&msg, &owner, session_path.as_str())
                        { controller.on_event(event); }
                    }
                    _ => controller.on_event(TerminalEvent::BusDisconnected),
                }
            }
            received = probe_results.recv() => {
                // A task panic, dropped sender or failed validation is denial.
                // Crucially, no result is applied until the watchdog deadline
                // is checked against a suspend-inclusive clock.
                probe_task.take();
                let now = uptime()?;
                if uptime_deadline_expired(
                    previous_uptime, last_good_uptime, now, 5.0
                ) {
                    controller.on_event(TerminalEvent::WatchdogOverdue);
                } else if !matches!(received, Some(Ok(()))) {
                    controller.on_event(TerminalEvent::SnapshotRejected);
                } else if controller.observe_snapshot().is_err() {
                    controller.on_event(TerminalEvent::WatchdogOverdue);
                } else {
                    last_good_uptime = now;
                    next_probe = Instant::now() + Duration::from_secs(1);
                }
            }
            _ = tick.tick() => {
                let now = uptime()?;
                if uptime_deadline_expired(
                    previous_uptime, last_good_uptime, now, 5.0
                ) {
                    controller.on_event(TerminalEvent::WatchdogOverdue);
                } else if controller.tick().is_err() {
                    controller.on_event(TerminalEvent::WatchdogOverdue);
                }
                previous_uptime = now;
                if controller.monitor_phase() != MonitorPhase::Terminated
                    && probe_task.is_none() && Instant::now() >= next_probe
                {
                    let conn = connection.clone();
                    let pinned_owner = owner.clone();
                    let pinned_session = session_path.clone();
                    let sender = probe_tx.clone();
                    probe_task = Some(tokio::spawn(async move {
                        // The WHOLE probe has a shorter deadline than the
                        // independently enforced 5-second watchdog. It is
                        // canceled on timeout, not allowed to complete late.
                        let result = match timeout(
                            Duration::from_secs(4),
                            live_health_probe(conn, pinned_owner, pinned_session),
                        ).await {
                            Ok(result) => result,
                            Err(_) => Err("HEALTH_PROBE_TIMEOUT"),
                        };
                        let _ = sender.send(result).await;
                    }));
                }
            }
            _ = tokio::time::sleep_until(stop_at.into()) => {
                // Observation expiry is not an unlock or a factor success.
                break;
            }
        }
        if controller.monitor_phase() == MonitorPhase::Terminated {
            // InhibitedSupervisor::on_event already revoked the owned
            // session synchronously before closing its delay FD.
            if let Some(task) = probe_task.take() { task.abort(); }
            return Err(event_classification(controller.terminal_event()));
        }
    }
    if let Some(task) = probe_task.take() { task.abort(); }
    Ok(())
}
#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 || args[1] != "--observe-only" || args[2] != "--seconds" {
        eprintln!("V03-C: specify --observe-only --seconds N; no secrets supported");
        std::process::exit(2);
    }
    if std::fs::metadata("/proc/self").map(|m| m.uid() == 0).unwrap_or(true) {
        eprintln!("V03-C: non-root Linux desktop session required");
        std::process::exit(2);
    }
    let Ok(seconds) = args[3].parse::<u64>() else {
        eprintln!("V03-C: invalid duration");
        std::process::exit(2);
    };
    if !(1..=60).contains(&seconds) {
        eprintln!("V03-C: duration out of bounds");
        std::process::exit(2);
    }
    match monitor(seconds).await {
        Ok(()) => println!("V03-C: OBSERVED_ONLY; no session or credential authorized"),
        Err(reason) => {
            // All errors are fixed string categories; never print raw bus
            // messages, session paths, PIDs or provider details.
            eprintln!("V03-C: FAIL_CLOSED: {reason}; no session or credential authorized");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vaulty_v02_candidate_verifier::v03::Phase;

    #[test]
    fn redacted_event_classification_never_exposes_session_identifiers() {
        assert_eq!(event_classification(Some(TerminalEvent::SessionLock)), "SESSION_LOCK");
        assert_eq!(event_classification(Some(TerminalEvent::SleepStart)), "SLEEP_START");
        assert_eq!(event_classification(Some(TerminalEvent::BusDisconnected)), "BUS_DISCONNECTED");
        assert_eq!(event_classification(None), "UNKNOWN");
    }

    fn string_changed(name: &str) -> HashMap<String, zbus::zvariant::OwnedValue> {
        let mut changed = HashMap::new();
        changed.insert(
            name.into(),
            zbus::zvariant::OwnedValue::from(
                zbus::zvariant::Str::from("sleep:shutdown"),
            ),
        );
        changed
    }

    #[test]
    fn manager_inhibitor_bookkeeping_does_not_abort_startup_or_runtime() {
        // Covers both supported signal encodings: a changed-property
        // a{sv} entry and an invalidated-property as entry.
        let changed = string_changed("DelayInhibited");
        assert_eq!(
            classify_manager_property_fields(MANAGER_IFACE, &changed, &[]),
            None,
        );
        assert_eq!(
            classify_manager_property_fields(
                MANAGER_IFACE, &HashMap::new(), &["DelayInhibited".into()],
            ),
            None,
        );
        assert_eq!(
            classify_manager_property_fields(
                MANAGER_IFACE, &changed, &["DelayInhibited".into()],
            ),
            None,
        );
    }

    #[test]
    fn manager_sleep_shutdown_unknown_mixed_invalid_and_malformed_events_stay_terminal() {
        for property in ["PreparingForSleep", "PreparingForShutdown", "UnknownProperty"] {
            let changed = string_changed(property);
            assert_eq!(
                classify_manager_property_fields(MANAGER_IFACE, &changed, &[]),
                Some(TerminalEvent::SnapshotRejected),
            );
            assert_eq!(
                classify_manager_property_fields(
                    MANAGER_IFACE, &HashMap::new(), &[property.into()],
                ),
                Some(TerminalEvent::SnapshotRejected),
            );
        }
        let mut mixed = string_changed("DelayInhibited");
        mixed.extend(string_changed("PreparingForSleep"));
        assert_eq!(
            classify_manager_property_fields(MANAGER_IFACE, &mixed, &[]),
            Some(TerminalEvent::SnapshotRejected),
        );
        assert_eq!(
            classify_manager_property_fields(
                MANAGER_IFACE, &string_changed("DelayInhibited"),
                &["PreparingForShutdown".into()],
            ),
            Some(TerminalEvent::SnapshotRejected),
        );
        assert_eq!(
            classify_manager_property_fields("org.example.Fake", &string_changed("DelayInhibited"), &[]),
            Some(TerminalEvent::MalformedMessage),
        );
        assert_eq!(
            classify_manager_property_fields(MANAGER_IFACE, &HashMap::new(), &[]),
            Some(TerminalEvent::MalformedMessage),
        );
        // Even an authentic logind sender cannot authorize an invalid
        // value type for the string-typed DelayInhibited property.
        let mut mistyped = HashMap::new();
        mistyped.insert("DelayInhibited".into(), zbus::zvariant::OwnedValue::from(true));
        assert_eq!(
            classify_manager_property_fields(MANAGER_IFACE, &mistyped, &[]),
            Some(TerminalEvent::SnapshotRejected),
        );
    }

    fn property_signal(
        sender: &str, path: &str, interface: &str,
        changed: HashMap<String, zbus::zvariant::OwnedValue>,
        invalidated: Vec<String>,
    ) -> Message {
        Message::signal(path, PROPERTIES_IFACE, "PropertiesChanged")
            .unwrap()
            .sender(sender).unwrap()
            .build(&(interface, changed, invalidated)).unwrap()
    }

    #[test]
    fn full_dbus_manager_signal_is_filtered_only_with_pinned_sender_and_path() {
        let legit = property_signal(
            ":1.42", MANAGER, MANAGER_IFACE, string_changed("DelayInhibited"), vec![],
        );
        assert_eq!(manager_property_event(&legit, ":1.42"), None);
        assert_eq!(
            manager_property_event(&legit, ":1.7"),
            Some(TerminalEvent::MalformedMessage),
        );
        let wrong_path = property_signal(
            ":1.42", "/org/freedesktop/login1/session/_10",
            MANAGER_IFACE, string_changed("DelayInhibited"), vec![],
        );
        assert_eq!(
            manager_property_event(&wrong_path, ":1.42"),
            Some(TerminalEvent::MalformedMessage),
        );
        let sleep_changed = property_signal(
            ":1.42", MANAGER, MANAGER_IFACE, string_changed("PreparingForSleep"), vec![],
        );
        assert_eq!(
            manager_property_event(&sleep_changed, ":1.42"),
            Some(TerminalEvent::SnapshotRejected),
        );
    }

    #[test]
    fn delay_fd_is_released_only_after_same_process_session_is_locked() {
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        struct MockFd(Arc<AtomicUsize>);
        impl Drop for MockFd {
            fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
        }
        let drops = Arc::new(AtomicUsize::new(0));
        let mut scope = InhibitedSupervisor::new(
            closed_controller(Duration::from_secs(5)),
            MockFd(drops.clone()),
        );
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        scope.on_event(TerminalEvent::SleepStart);
        assert_eq!(scope.phase(), Phase::Locked);
        assert_eq!(scope.terminal_event(), Some(TerminalEvent::SleepStart));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        drop(scope);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn early_return_releases_delay_fd_after_revoking_session() {
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        struct MockFd(Arc<AtomicUsize>);
        impl Drop for MockFd {
            fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); }
        }
        let drops = Arc::new(AtomicUsize::new(0));
        {
            let scope = InhibitedSupervisor::new(
                closed_controller(Duration::from_secs(5)),
                MockFd(drops.clone()),
            );
            assert_eq!(scope.monitor_phase(), MonitorPhase::Observing);
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            // Simulated D-Bus error exits this scope without a signal.
        }
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn all_session_path_subscription_can_reject_early_lock_unlock_races() {
        // A local signal path is not known until GetSessionByPID has
        // completed. The early stream therefore covers the entire session
        // path namespace rather than one object resolved too late.
        let rule = MatchRule::builder()
            .msg_type(MessageType::Signal)
            .sender(SERVICE).unwrap()
            .interface(SESSION_IFACE).unwrap()
            .path_namespace("/org/freedesktop/login1/session").unwrap()
            .build();
        let rendered = rule.to_string();
        assert!(rendered.contains("path_namespace='/org/freedesktop/login1/session'"));
        assert!(!rendered.contains("member='Lock'")); // Lock AND Unlock
        assert!(!rendered.contains("arg0=")); // no pre-resolution session ID
    }

    #[test]
    fn ubuntu_24_04_compatible_snapshot_requires_supported_lock_hint_not_canlock() {
        // There is no mandatory CanLock D-Bus Get. An active, unlocked,
        // local graphical session with supported LockedHint is observable.
        let good = |locked, active, remote, class, kind| acceptable_session_state(
            1000, 1000, "seat0", "/org/freedesktop/login1/seat/seat0",
            locked, active, remote, "active", kind, class, false, false,
        );
        assert!(good(false, true, false, "user", "wayland"));
        assert!(good(false, true, false, "user", "x11"));
        assert!(!good(true, true, false, "user", "wayland"));
        assert!(!good(false, false, false, "user", "wayland"));
        assert!(!good(false, true, true, "user", "wayland"));
        assert!(!good(false, true, false, "greeter", "wayland"));
        assert!(!good(false, true, false, "user", "tty"));
        assert!(!acceptable_session_state(
            1000, 1001, "seat0", "/org/freedesktop/login1/seat/seat0",
            false, true, false, "active", "wayland", "user", false, false,
        ));
        assert!(!acceptable_session_state(
            1000, 1000, "seat0", "/org/freedesktop/login1/seat/seat0",
            false, true, false, "active", "wayland", "user", true, false,
        ));
    }

    #[test]
    fn suspend_inclusive_watchdog_checks_previous_tick_and_last_success() {
        assert!(!uptime_deadline_expired(100.0, 98.0, 102.0, 5.0));
        assert!(uptime_deadline_expired(100.0, 98.0, 103.0, 5.0));
        assert!(uptime_deadline_expired(100.0, 100.0, 105.0, 5.0));
        assert!(uptime_deadline_expired(100.0, 100.0, 99.0, 5.0));
        assert!(uptime_deadline_expired(100.0, 100.0, f64::NAN, 5.0));
    }

    fn closed_controller(gap: Duration) -> SessionSupervisor {
        let limits = SessionLimits::new(
            Duration::from_secs(5), Duration::from_secs(30),
        ).unwrap();
        let mut controller = SessionSupervisor::new(
            Session::new(limits), gap,
        ).unwrap();
        controller.observe_snapshot().unwrap();
        controller
    }

    #[tokio::test]
    async fn a_blocked_health_probe_does_not_starve_the_independent_watchdog() {
        let mut controller = closed_controller(Duration::from_millis(80));
        let (tx, mut replies) = tokio::sync::mpsc::channel::<Outcome<()>>(1);
        let probe = tokio::spawn(async move {
            // Simulate many sequential two-second D-Bus calls hanging.
            tokio::time::sleep(Duration::from_secs(10)).await;
            let _ = tx.send(Ok(())).await;
        });
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        timeout(Duration::from_secs(1), async {
            loop {
                tokio::select! {
                    biased;
                    answer = replies.recv() => panic!(
                        "slow probe unexpectedly completed before lock: {answer:?}"
                    ),
                    _ = tick.tick() => {
                        if controller.tick().is_err() {
                            controller.on_event(TerminalEvent::WatchdogOverdue);
                            break;
                        }
                    }
                }
            }
        }).await.expect("watchdog must run while health query is pending");
        assert_eq!(controller.phase(), Phase::Locked);
        assert_eq!(controller.terminal_event(), Some(TerminalEvent::WatchdogOverdue));
        probe.abort();
    }

    #[tokio::test]
    async fn a_lock_signal_is_consumed_while_a_health_probe_is_blocked() {
        let mut controller = closed_controller(Duration::from_secs(5));
        let (tx, mut events) = tokio::sync::mpsc::channel::<TerminalEvent>(1);
        let mut probe = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        tx.send(TerminalEvent::SessionLock).await.unwrap();
        timeout(Duration::from_millis(500), async {
            tokio::select! {
                biased;
                Some(event) = events.recv() => controller.on_event(event),
                _ = &mut probe => panic!("probe should still be blocked"),
            }
        }).await.expect("terminal signals must preempt blocked health probes");
        assert_eq!(controller.phase(), Phase::Locked);
        assert_eq!(controller.terminal_event(), Some(TerminalEvent::SessionLock));
        probe.abort();
    }
}
