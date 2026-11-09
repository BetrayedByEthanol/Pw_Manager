//! V03-C — Rust-owned lifecycle locking controller, not a vault unlock path.
//!
//! This controller OWNS the V03 session. Trusted Linux messages will be
//! translated into terminal security events in the same Rust process by the
//! optional V03-C system-bus runner. A successful health observation is only
//! diagnostic: it NEVER sets V03's private monitor_live flag, issues an
//! authorization token or enables the test-only LOADED constructor.
//!
//! The default executable remains inert. G1/G2/G3 and OPEN-01/OPEN-15 remain
//! blocked. In particular no DBus event or snapshot is an authentication factor.
use crate::v03::{LifecycleEvent, LockReason, Phase, Session};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorPhase { Unverified, Observing, Terminated }

/// Events are solely revocations. Even unlock and resume are terminal:
/// they may mean a missed preceding lock/suspend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalEvent {
    SessionLock,
    SessionUnlock,
    SleepStart,
    SleepEnd,
    ShutdownStart,
    ShutdownEnd,
    SessionRemoved,
    LogindOwnerChanged,
    BusDisconnected,
    MalformedMessage,
    SnapshotRejected,
    SessionMismatch,
    WatchdogOverdue,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorFailure {
    InvalidLimits,
    Unverified,
    Terminated,
    WatchdogOverdue,
    SessionExpired,
}
pub struct SessionSupervisor {
    session: Session,
    monitor: MonitorPhase,
    max_gap: Duration,
    last_probe: Option<Instant>,
    termination: Option<TerminalEvent>,
}
impl SessionSupervisor {
    pub fn new(session: Session, max_gap: Duration)
        -> Result<Self, MonitorFailure>
    {
        if max_gap.is_zero() || max_gap > Duration::from_secs(30) {
            return Err(MonitorFailure::InvalidLimits);
        }
        Ok(Self {
            session, monitor: MonitorPhase::Unverified, max_gap,
            last_probe: None, termination: None,
        })
    }
    pub fn phase(&self) -> Phase { self.session.phase() }
    pub fn lock_reason(&self) -> Option<LockReason> {
        self.session.last_lock_reason()
    }
    pub fn monitor_phase(&self) -> MonitorPhase { self.monitor }
    pub fn terminal_event(&self) -> Option<TerminalEvent> { self.termination }
    /// Diagnostic only. A source-only observation MUST NEVER grant
    /// authorization to the underlying V03 session.
    pub fn observe_snapshot(&mut self) -> Result<(), MonitorFailure> {
        self.observe_snapshot_at(Instant::now())
    }
    fn observe_snapshot_at(&mut self, now: Instant) -> Result<(), MonitorFailure> {
        if self.monitor == MonitorPhase::Terminated {
            return Err(MonitorFailure::Terminated);
        }
        self.last_probe = Some(now);
        self.monitor = MonitorPhase::Observing;
        Ok(())
    }
    /// Must be invoked on an independent timer, even when no messages arrive.
    /// Every future daemon secret operation MUST independently fail closed
    /// until there is an authenticated, in-process session listener gate.
    pub fn tick(&mut self) -> Result<(), MonitorFailure> {
        self.tick_at(Instant::now())
    }
    fn tick_at(&mut self, now: Instant) -> Result<(), MonitorFailure> {
        match self.monitor {
            MonitorPhase::Terminated => return Err(MonitorFailure::Terminated),
            MonitorPhase::Unverified => {
                self.terminate(TerminalEvent::SnapshotRejected);
                return Err(MonitorFailure::Unverified);
            }
            MonitorPhase::Observing => (),
        }
        if self.last_probe.is_none_or(|last| {
            now.checked_duration_since(last)
                .is_none_or(|elapsed| elapsed >= self.max_gap)
        }) {
            self.terminate(TerminalEvent::WatchdogOverdue);
            return Err(MonitorFailure::WatchdogOverdue);
        }
        if self.session.poll() {
            return Err(MonitorFailure::SessionExpired);
        }
        Ok(())
    }
    pub fn on_event(&mut self, event: TerminalEvent) {
        self.terminate(event);
    }
    fn terminate(&mut self, event: TerminalEvent) {
        if self.monitor == MonitorPhase::Terminated { return; }
        self.monitor = MonitorPhase::Terminated;
        self.last_probe = None;
        self.termination = Some(event);
        let mapped = match event {
            TerminalEvent::SessionLock => LifecycleEvent::ScreenLocked,
            TerminalEvent::SleepStart | TerminalEvent::SleepEnd =>
                LifecycleEvent::Suspend,
            TerminalEvent::ShutdownStart => LifecycleEvent::Shutdown,
            TerminalEvent::SessionUnlock | TerminalEvent::ShutdownEnd
            | TerminalEvent::SessionRemoved | TerminalEvent::LogindOwnerChanged
            | TerminalEvent::BusDisconnected | TerminalEvent::MalformedMessage
            | TerminalEvent::SnapshotRejected | TerminalEvent::SessionMismatch
            | TerminalEvent::WatchdogOverdue =>
                LifecycleEvent::ListenerFailed,
        };
        self.session.on_lifecycle(mapped); // clears the owned LOADED body
    }
    /// No mutable session getter, resume, or ability to mark V03's internal
    /// monitor authorized. Any future production load requires fresh approval.
}
#[cfg(test)]
#[path = "v03c_tests.rs"]
mod tests;
