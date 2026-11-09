//! V03-C offline-only Rust tests. No system bus, real vault or keys.
use super::*;
use crate::v02::{
    self, EntryMode, EntryRecord, EntryTier, FactorPolicy, PublicHeader,
    RecoveryPolicy, Slot, SlotTarget, VaultBody, VaultMode, Vmk,
};
use crate::v03::SessionLimits;
use uuid::Uuid;

fn fixture() -> (SessionSupervisor, Uuid) {
    let header = PublicHeader::genesis(VaultMode::PasswordVirtual, vec![
        Slot::pending(SlotTarget::Vmk, Uuid::nil(), FactorPolicy::VaultPasswordVirtual),
        Slot::pending(SlotTarget::Vmk, Uuid::nil(), FactorPolicy::CodeOnly),
    ]);
    let entry_id = Uuid::new_v4();
    let mut body = VaultBody::for_header(&header);
    body.entries.push(EntryRecord {
        id: entry_id, revision: 1, mode: EntryMode::DefaultPhysical,
        tier: EntryTier::Isolated, recovery: RecoveryPolicy::StrictNone,
        tombstone: false, title: "synthetic".into(),
        username: String::new(), origin: String::new(), nonce: [8; 24],
        ciphertext: vec![1; 16], dek_slots: vec![],
    });
    let vmk = Vmk::random();
    let file = v02::seal_file(&header, &body, &vmk).unwrap();
    let opened = v02::open_file(&file, &vmk).unwrap();
    let mut session = Session::new(
        SessionLimits::new(Duration::from_secs(20), Duration::from_secs(90)).unwrap());
    session.inspect_public_file(&file).unwrap();
    session.load_synthetic(opened, [13; 32], [21; 32], Instant::now()).unwrap();
    session.synthetic_monitor_registered();
    (SessionSupervisor::new(session, Duration::from_secs(4)).unwrap(), entry_id)
}

#[test]
fn never_verified_listener_refuses_and_drops_loaded_state() {
    let (mut controller, _) = fixture();
    assert_eq!(controller.monitor_phase(), MonitorPhase::Unverified);
    assert_eq!(controller.tick(), Err(MonitorFailure::Unverified));
    assert_eq!(controller.monitor_phase(), MonitorPhase::Terminated);
    assert_eq!(controller.phase(), Phase::Locked);
    assert_eq!(controller.lock_reason(), Some(LockReason::ListenerUnavailable));
    assert_eq!(controller.observe_snapshot(), Err(MonitorFailure::Terminated));
}

#[test]
fn watchdog_gap_revokes_non_sliding_session_and_never_resumes() {
    let (mut controller, _) = fixture();
    let at = Instant::now();
    controller.observe_snapshot_at(at).unwrap();
    assert_eq!(controller.tick_at(at + Duration::from_secs(3)), Ok(()));
    assert_eq!(controller.tick_at(at + Duration::from_secs(4)),
        Err(MonitorFailure::WatchdogOverdue));
    assert_eq!(controller.terminal_event(), Some(TerminalEvent::WatchdogOverdue));
    assert_eq!(controller.phase(), Phase::Locked);
    assert_eq!(controller.observe_snapshot(), Err(MonitorFailure::Terminated));
}

#[test]
fn all_terminal_logind_events_cancel_and_drop_session() {
    for event in [
        TerminalEvent::SessionLock,
        TerminalEvent::SessionUnlock,
        TerminalEvent::SleepStart,
        TerminalEvent::SleepEnd,
        TerminalEvent::ShutdownStart,
        TerminalEvent::ShutdownEnd,
        TerminalEvent::SessionRemoved,
        TerminalEvent::LogindOwnerChanged,
        TerminalEvent::BusDisconnected,
        TerminalEvent::MalformedMessage,
        TerminalEvent::SnapshotRejected,
        TerminalEvent::SessionMismatch,
        TerminalEvent::WatchdogOverdue,
    ] {
        let (mut controller, _) = fixture();
        controller.observe_snapshot().unwrap();
        controller.on_event(event);
        assert_eq!(controller.phase(), Phase::Locked, "{event:?}");
        assert_eq!(controller.monitor_phase(), MonitorPhase::Terminated);
        assert_eq!(controller.terminal_event(), Some(event));
        let reason = match event {
            TerminalEvent::SessionLock => LockReason::ScreenLock,
            TerminalEvent::SleepStart | TerminalEvent::SleepEnd => LockReason::Suspend,
            TerminalEvent::ShutdownStart => LockReason::Shutdown,
            _ => LockReason::ListenerUnavailable,
        };
        assert_eq!(controller.lock_reason(), Some(reason));
        controller.on_event(TerminalEvent::SessionUnlock);
        assert_eq!(controller.terminal_event(), Some(event));
        assert_eq!(controller.observe_snapshot(), Err(MonitorFailure::Terminated));
    }
}

#[test]
fn finite_watchdog_config_and_non_secret_diagnostics() {
    let limits = SessionLimits::new(Duration::from_secs(5),
                                    Duration::from_secs(30)).unwrap();
    assert!(matches!(SessionSupervisor::new(Session::new(limits), Duration::ZERO),
        Err(MonitorFailure::InvalidLimits)));
    assert!(matches!(SessionSupervisor::new(Session::new(limits),
        Duration::from_secs(31)), Err(MonitorFailure::InvalidLimits)));
    let supervisor = SessionSupervisor::new(
        Session::new(limits), Duration::from_secs(2)).unwrap();
    assert_eq!(supervisor.phase(), Phase::Closed);
    assert_eq!(supervisor.monitor_phase(), MonitorPhase::Unverified);
}

#[test]
fn positive_probe_never_authorizes_or_changes_loaded_session_gate() {
    let (mut controller, _) = fixture();
    controller.observe_snapshot().unwrap();
    assert_eq!(controller.monitor_phase(), MonitorPhase::Observing);
    assert_eq!(controller.phase(), Phase::Loaded);
    // The V03 normal-built session has no public LOADED constructor, and
    // a diagnostic V03-C probe never establishes V03 monitor_live.
    controller.on_event(TerminalEvent::BusDisconnected);
    assert_eq!(controller.phase(), Phase::Locked);
}
