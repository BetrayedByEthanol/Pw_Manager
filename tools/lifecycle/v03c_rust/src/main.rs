//! V03-C same-process Rust system-bus logind observer. NO vault unlocking.
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
where T: for<'de> zbus::zvariant::Type + serde::de::Deserialize<'de>,
{
    bounded(proxy.get_property(name)).await
}
async fn safe_snapshot(manager: &Proxy<'_>, session: &Proxy<'_>) -> Outcome<()> {
    let (uid, _): (u32, OwnedObjectPath) = property(session, "User").await?;
    let (seat, seat_path): (String, OwnedObjectPath) = property(session, "Seat").await?;
    let (locked, active, can_lock, remote): (bool, bool, bool, bool) = (
        property(session, "LockedHint").await?,
        property(session, "Active").await?,
        property(session, "CanLock").await?,
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
    if uid != own_uid || seat.is_empty()
        || !seat_path.as_str().starts_with("/org/freedesktop/login1/seat/")
        || locked || !active || !can_lock || remote
        || sleeping || shutdown || state != "active"
        || class != "user" || !matches!(kind.as_str(), "x11" | "wayland")
    {
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
    let mut manager_properties = bounded(Proxy::new(
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
    bounded(async { safe_snapshot(&manager, &session).await
        .map_err(|_| zbus::Error::Failure("unsafe".into())) }).await
        .map_err(|_| "UNSAFE_SESSION")?;
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
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut previous_uptime = uptime()?;
    let stop_at = Instant::now() + Duration::from_secs(seconds);
    loop {
        if Instant::now() >= stop_at { break; }
        tokio::select! {
            message = owner_signals.next() => {
                if message.is_some() {
                    controller.on_event(TerminalEvent::LogindOwnerChanged);
                } else {
                    controller.on_event(TerminalEvent::BusDisconnected);
                }
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
            _ = tick.tick() => {
                let u = uptime()?;
                if u < previous_uptime || u - previous_uptime > 5.0 {
                    controller.on_event(TerminalEvent::WatchdogOverdue);
                }
                previous_uptime = u;
                if controller.monitor_phase() != MonitorPhase::Terminated {
                    if current_owner(&dbus).await? != owner
                       || local_session(&manager).await? != session_path {
                        controller.on_event(TerminalEvent::SessionMismatch);
                    } else if safe_snapshot(&manager, &session).await.is_err() {
                        controller.on_event(TerminalEvent::SnapshotRejected);
                    } else {
                        controller.observe_snapshot().map_err(|_| "MONITOR_TERMINATED")?;
                        controller.tick().map_err(|_| "MONITOR_TERMINATED")?;
                    }
                }
            }
        }
        if controller.monitor_phase() == MonitorPhase::Terminated {
            return Err("SESSION_LOCKED_FAIL_CLOSED");
        }
    }
    Ok(())
}
#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 || args[1] != "--observe-only" || args[2] != "--seconds" {
        eprintln!("V03-C: specify --observe-only --seconds N; no secrets supported");
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
