//! V03-A — fail-closed lifecycle and authenticator *boundary*.
//!
//! This is NOT a working Linux logind listener or authenticator. The public
//! Linux signal interface can only LOCK; it cannot register a healthy
//! lifecycle monitor, approve a provider or extend a session. A trusted
//! D-Bus subscription, owner/seat validation, watchdog and delay inhibitor
//! must be implemented and reviewed by the future daemon. There is no
//! production LOADED constructor or secret-release/DEK unwrap path.
//! OPEN-01 / OPEN-15 and G1–G3 remain blocked.
use crate::v03::{
    LifecycleEvent, ProviderRequirement, ReadIntent, Session,
};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Normalized Linux logind events, not proof of the sender of a D-Bus signal.
///
/// A future D-Bus adapter MUST establish the system-bus sender's unique
/// ownership of org.freedesktop.login1, bind the correct local session/seat,
/// check the initial LockedHint and subscribe without a race. Never consume
/// events from a browser/native host or untrusted IPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogindSafetyEvent {
    SessionLocked,
    SessionUnlocked,
    PrepareForSleep(bool),
    PrepareForShutdown(bool),
    SessionRemoved,
    SubscriptionLost,
    MalformedOrUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorError {
    InvalidWatchdog,
    NotTrusted,
    Stale,
    SessionExpired,
}
/// A watchdog cannot be declared healthy through the public API. The only
/// positive hook is synthetic and available exclusively under #[cfg(test)].
pub struct LifecycleGuard {
    max_silence: Duration,
    source_healthy: bool,
    last_verified_health: Option<Instant>,
}
impl LifecycleGuard {
    pub fn new(max_silence: Duration) -> Result<Self, MonitorError> {
        if max_silence.is_zero() || max_silence > Duration::from_secs(60) {
            return Err(MonitorError::InvalidWatchdog);
        }
        Ok(Self {
            max_silence, source_healthy: false, last_verified_health: None,
        })
    }
    pub fn enforce(&mut self, session: &mut Session) -> Result<(), MonitorError> {
        self.enforce_at(session, Instant::now())
    }
    fn enforce_at(&mut self, session: &mut Session, now: Instant)
        -> Result<(), MonitorError>
    {
        if !self.source_healthy {
            session.on_lifecycle(LifecycleEvent::ListenerFailed);
            return Err(MonitorError::NotTrusted);
        }
        if self.last_verified_health.is_none_or(|last| {
            now.checked_duration_since(last)
                .is_none_or(|elapsed| elapsed >= self.max_silence)
        }) {
            self.invalidate(session);
            return Err(MonitorError::Stale);
        }
        // The V03 session's own inactivity/absolute clocks are independent.
        if session.poll() {
            return Err(MonitorError::SessionExpired);
        }
        Ok(())
    }
    fn invalidate(&mut self, session: &mut Session) {
        self.source_healthy = false;
        self.last_verified_health = None;
        session.on_lifecycle(LifecycleEvent::ListenerFailed);
    }
    /// Fail-closed Linux event normalization. No event indicates a valid
    /// session unlock, enables the observer or conveys an authorization.
    pub fn handle_linux_event(&mut self, session: &mut Session, event: LogindSafetyEvent) {
        match event {
            LogindSafetyEvent::SessionLocked =>
                session.on_lifecycle(LifecycleEvent::ScreenLocked),
            LogindSafetyEvent::PrepareForSleep(_) =>
                session.on_lifecycle(LifecycleEvent::Suspend),
            LogindSafetyEvent::PrepareForShutdown(true) =>
                session.on_lifecycle(LifecycleEvent::Hibernate),
            LogindSafetyEvent::PrepareForShutdown(false)
            | LogindSafetyEvent::SessionUnlocked
            | LogindSafetyEvent::SessionRemoved
            | LogindSafetyEvent::SubscriptionLost
            | LogindSafetyEvent::MalformedOrUnknown =>
                session.on_lifecycle(LifecycleEvent::ListenerFailed),
        }
        // Do not automatically reestablish trust after wake/unlock; all
        // local protected operations require a new authenticated load.
        self.source_healthy = false;
        self.last_verified_health = None;
    }
    #[cfg(test)]
    pub(crate) fn simulate_verified_source(&mut self, session: &mut Session, now: Instant) {
        self.source_healthy = true;
        self.last_verified_health = Some(now);
        session.synthetic_monitor_registered();
    }
    #[cfg(test)]
    pub(crate) fn simulate_health_poll(&mut self, now: Instant) {
        if self.source_healthy { self.last_verified_health = Some(now); }
    }
}

/// A source's administrative status is NOT cryptographic credential proof.
/// Actual registry state will be authenticated and owned by the daemon in V06.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysicalCredentialState {
    Active,
    Suspended,
    Revoked,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryDeny {
    StaleOperation,
    WrongProvider,
    MissingCredential,
    SuspendedCredential,
    RevokedCredential,
    TrustedBackendUnavailable,
}

/// Sealed provider interface: arbitrary third-party code cannot implement
/// a fake "verified hardware" provider and have this boundary accept it.
mod sealed { pub trait Sealed {} }
pub trait ProviderAdapter: sealed::Sealed {
    fn requirement(&self) -> ProviderRequirement;
}
pub struct VirtualNonFactorAdapter;
pub struct PhysicalFido2Adapter;
impl sealed::Sealed for VirtualNonFactorAdapter {}
impl sealed::Sealed for PhysicalFido2Adapter {}
impl ProviderAdapter for VirtualNonFactorAdapter {
    fn requirement(&self) -> ProviderRequirement { ProviderRequirement::VirtualNonFactor }
}
impl ProviderAdapter for PhysicalFido2Adapter {
    fn requirement(&self) -> ProviderRequirement { ProviderRequirement::FreshPhysicalFido2 }
}

/// Only a review-time protocol planning boundary. Neither adapter possesses
/// a PRF implementation, a token, nor a method to mark a read authorized.
pub struct AuthenticatorBoundary {
    // Empty on every production constructor. Synthetic assignments can only
    // be installed from tests; no caller-controlled "verified" shortcut.
    physical: HashMap<Uuid, PhysicalCredentialState>,
}
impl Default for AuthenticatorBoundary {
    fn default() -> Self { Self::new() }
}
impl AuthenticatorBoundary {
    pub fn new() -> Self { Self { physical: HashMap::new() } }

    /// Validate the selected policy against the active session's immutable
    /// pending operation, then consume that operation on every attempted
    /// provider use. This method ALWAYS denies: it has no verified factor.
    /// Caller-supplied intent fields and credential IDs never grant access.
    pub fn attempt_read<A: ProviderAdapter>(
        &self, session: &mut Session, intent: &ReadIntent,
        adapter: &A, credential_id: Option<Uuid>,
    ) -> Result<(), BoundaryDeny> {
        if session.require_pending_read(
            intent.operation_id, intent.entry_id, intent.provider,
        ).is_err() {
            return Err(BoundaryDeny::StaleOperation);
        }
        let selected = adapter.requirement();
        let reason = if selected != intent.provider {
            BoundaryDeny::WrongProvider
        } else {
            match selected {
                ProviderRequirement::VirtualNonFactor =>
                    BoundaryDeny::TrustedBackendUnavailable,
                ProviderRequirement::FreshPhysicalFido2 =>
                    match credential_id.and_then(|id| self.physical.get(&id)).copied() {
                        None => BoundaryDeny::MissingCredential,
                        Some(PhysicalCredentialState::Suspended) =>
                            BoundaryDeny::SuspendedCredential,
                        Some(PhysicalCredentialState::Revoked) =>
                            BoundaryDeny::RevokedCredential,
                        Some(PhysicalCredentialState::Active) =>
                            BoundaryDeny::TrustedBackendUnavailable,
                    },
            }
        };
        session.cancel_pending();
        Err(reason)
    }

    /// Test-only registry status changes exercise denial behavior without
    /// importing credentials, PRF outputs, manufacturer attestation or keys.
    #[cfg(test)]
    pub(crate) fn set_synthetic_credential(
        &mut self, credential_id: Uuid, state: PhysicalCredentialState,
    ) {
        self.physical.insert(credential_id, state);
    }
}

/// Additional compile-time gate: a V03-A adapter cannot create a trusted
/// session load token from a status flag or an alleged FIDO2 touch.
pub fn real_authenticator_authorization_available() -> bool { false }

#[cfg(test)]
#[path = "v03a_tests.rs"]
mod tests;
