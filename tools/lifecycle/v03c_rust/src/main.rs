//! V03-C same-process Rust system-bus logind observer. NO vault unlocking.
#![forbid(unsafe_code)]
//! This runner owns a Rust SessionSupervisor and a CLOSED Session. It never
//! constructs LOADED, authorizes a client or forwards D-Bus output as proof
//! of authorization. All external D-Bus errors become fixed failure codes.
use futures_util::{FutureExt, StreamExt};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};
use tokio::time::{MissedTickBehavior, timeout};
use vaulty_v02_candidate_verifier::v03::{Session, SessionLimits};
use vaulty_v02_candidate_verifier::v03c::{MonitorPhase, SessionSupervisor, TerminalEvent};
use zbus::{Connection, Message, Proxy, zvariant::OwnedObjectPath};

const SERVICE: &str = "org.freedesktop.login1";
const MANAGER: &str = "/org/freedesktop/login1";
const DBUS: &str = "org.freedesktop.DBus";
const DBUS_PATH: &str = "/org/freedesktop/DBus";
const MANAGER_IFACE: &str = "org.freedesktop.login1.Manager";
const SESSION_IFACE: &str = "org.freedesktop.login1.Session";
const PROPERTIES_IFACE: &str = "org.freedesktop.DBus.Properties";

type Outcome<T> = Result<T, &'static str>;

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
async fn monitor(seconds: u64) -> Outcome<()> {
    let limits = SessionLimits::new(Duration::from_secs(20),
        Duration::from_secs(90)).map_err(|_| "INVALID_SESSION_LIMIT")?;
    let mut controller = SessionSupervisor::new(Session::new(limits),
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
    let owner = current_owner(&dbus).await?;
    if !owner.starts_with(':') { return Err("INVALID_LOGIND_OWNER"); }
    let session_path = local_session(&manager).await?;
    if !session_path.as_str().starts_with("/org/freedesktop/login1/session/") {
        return Err("INVALID_LOCAL_SESSION");
    }
    let session = bounded(Proxy::new(
        &connection, SERVICE, session_path.as_str(), SESSION_IFACE)).await?;
    let session_properties = bounded(Proxy::new(
        &connection, SERVICE, session_path.as_str(), PROPERTIES_IFACE)).await?;
    let mut session_signals = bounded(session.receive_all_signals()).await?;
    let mut session_prop_signals = bounded(session_properties.receive_all_signals()).await?;
    safe_snapshot(&manager, &session).await?;
    if current_owner(&dbus).await? != owner
        || local_session(&manager).await? != session_path
    { return Err("STARTUP_BINDING_CHANGED"); }
    if drain(&mut owner_signals) || drain(&mut manager_signals)
        || drain(&mut manager_prop_signals) || drain(&mut session_signals)
        || drain(&mut session_prop_signals)
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
                controller.on_event(message.map_or(TerminalEvent::BusDisconnected,
                    |m| classify_session(&m, &owner, session_path.as_str())));
            }
            message = manager_prop_signals.next() => {
                controller.on_event(message.map_or(TerminalEvent::BusDisconnected,
                    |_| TerminalEvent::SnapshotRejected));
            }
            message = session_prop_signals.next() => {
                controller.on_event(message.map_or(TerminalEvent::BusDisconnected,
                    |_| TerminalEvent::SnapshotRejected));
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
            if let Some(task) = probe_task.take() { task.abort(); }
            return Err("SESSION_LOCKED_FAIL_CLOSED");
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
        Err(_) => {
            eprintln!("V03-C: FAIL_CLOSED; no session or credential authorized");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vaulty_v02_candidate_verifier::v03::Phase;

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
