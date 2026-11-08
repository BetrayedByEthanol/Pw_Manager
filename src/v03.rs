//! V03 — review-gated session and authenticator **foundation**, NOT a vault runtime.
//!
//! The default executable remains disabled. Only public VLY2 header parsing
//! is reachable as a session transition in normal builds. No ordinary build
//! can construct a LOADED session: construction from synthetic authenticated
//! metadata and independent secrets exists exclusively in unit tests until
//! V03/V04/V06 supply an audited VMK, rollback, provider and listener gate.
//!
//! In particular ReadIntent and WriteIntent are NOT authorization tokens.
//! There is NO API that releases a DEK, PRF result, entry plaintext or VMK.
//! OPEN-01/15 and G1–G3 remain blocked.
use crate::v02::{self, EntryMode, EntryTier, PublicHeader, VaultBody};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use std::time::{Duration, Instant};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Publicly observable state, not an authenticated client-access capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Closed,
    Open,
    Loaded,
    Locked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    Owner,
    IdleTimeout,
    AbsoluteLifetime,
    ScreenLock,
    Suspend,
    Hibernate,
    ListenerUnavailable,
    InvalidAuthenticatedTransition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    InvalidLimits,
    WrongPhase,
    PublicHeaderRejected,
    ListenerUnavailable,
    Expired,
    Busy,
    MissingEntry,
    InvalidEntryPolicy,
    InvalidOperation,
    UnsupportedAuthorization,
}
impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No secret, path, user input or source exception is reflected.
        let label = match self {
            Self::InvalidLimits => "invalid session safety limits",
            Self::WrongPhase => "operation not permitted in current session state",
            Self::PublicHeaderRejected => "public vault framing rejected",
            Self::ListenerUnavailable => "trusted session lifecycle listener unavailable",
            Self::Expired => "session or operation expired",
            Self::Busy => "another operation is already pending",
            Self::MissingEntry => "selected entry unavailable",
            Self::InvalidEntryPolicy => "entry access policy rejected",
            Self::InvalidOperation => "unknown or stale operation",
            Self::UnsupportedAuthorization => "trusted authenticator/approval not implemented",
        };
        f.write_str(label)
    }
}
impl std::error::Error for SessionError {}

/// Two finite timeouts, both measured by a monotonic clock. Activity may
/// renew ONLY the idle deadline; the maximum loaded lifetime never slides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLimits {
    pub inactivity: Duration,
    pub absolute: Duration,
}
impl SessionLimits {
    pub fn new(inactivity: Duration, absolute: Duration) -> Result<Self, SessionError> {
        if inactivity.is_zero() || absolute.is_zero() || inactivity >= absolute
            || absolute > Duration::from_secs(24 * 60 * 60)
        {
            return Err(SessionError::InvalidLimits);
        }
        Ok(Self { inactivity, absolute })
    }
}

/// Explicit intent only: no secret or verified-factor capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstFactor {
    MaskedVers,
    FreshEntryPassword,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderRequirement {
    VirtualNonFactor,
    FreshPhysicalFido2,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadIntent {
    pub operation_id: Uuid,
    pub entry_id: Uuid,
    pub first: FirstFactor,
    pub provider: ProviderRequirement,
    pub tier: EntryTier,
    /// Always false in V03 v0. No spoofed "authorized" result is possible.
    pub authorized: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteIntent {
    pub operation_id: Uuid,
    pub base_vault_id: Uuid,
    pub base_commit_id: Uuid,
    pub base_generation: u64,
    pub max_changes: u16,
    /// Explicit: no change set or owner approval was accepted.
    pub authorized: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicSummary {
    pub vault_id: Uuid,
    pub generation: u64,
    /// PUBLIC ONLY; no cryptographic authentication or rollback acceptance.
    pub authenticated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleEvent {
    ScreenLocked,
    Suspend,
    Hibernate,
    ListenerDisconnected,
    ListenerFailed,
    Resumed,
}

/// XOR masking adds only handling friction. A memory adversary reading both
/// shares reconstructs VERS. This representation is NOT encryption or a
/// guarantee against an attacker with process-memory access.
struct MaskedVers {
    share_a: Zeroizing<[u8; 32]>,
    share_b: Zeroizing<[u8; 32]>,
}
impl MaskedVers {
    #[cfg(test)]
    fn from_independent_secret(secret: Zeroizing<[u8; 32]>) -> Self {
        let mut share_a = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(share_a.as_mut());
        let mut share_b = Zeroizing::new([0u8; 32]);
        for i in 0..32 { share_b[i] = secret[i] ^ share_a[i]; }
        Self { share_a, share_b }
    }
    fn with_transient<R>(&mut self, f: impl FnOnce(&[u8; 32]) -> R) -> R {
        let mut plaintext = Zeroizing::new([0u8; 32]);
        for i in 0..32 { plaintext[i] = self.share_a[i] ^ self.share_b[i]; }
        // Rotate BOTH shares before invoking the closure. Any panic then
        // still drops the transient Zeroizing buffer and fresh shares remain.
        let mut fresh_a = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(fresh_a.as_mut());
        for i in 0..32 { self.share_b[i] = plaintext[i] ^ fresh_a[i]; }
        self.share_a = fresh_a;
        f(&plaintext)
    }
    fn rotate(&mut self) { self.with_transient(|_| ()); }
}

/// This software provider holds a random test seed only in LOADED. It does
/// not derive an actual PRF or claim a second possession factor.
struct VirtualProvider {
    #[allow(dead_code)]
    seed: Zeroizing<[u8; 32]>,
}
impl VirtualProvider {
    #[cfg(test)]
    fn synthetic(seed: [u8; 32]) -> Self { Self { seed: Zeroizing::new(seed) } }
}

enum Pending {
    Read { id: Uuid, expires: Instant },
    Write { id: Uuid, expires: Instant },
}
impl Pending {
    fn id(&self) -> Uuid { match self { Self::Read { id, .. } | Self::Write { id, .. } => *id } }
    fn expires(&self) -> Instant {
        match self { Self::Read { expires, .. } | Self::Write { expires, .. } => *expires }
    }
}

struct Loaded {
    header: PublicHeader,
    body: VaultBody, // authenticated metadata and still-encrypted entry records
    masked_vers: MaskedVers,
    #[allow(dead_code)]
    virtual_provider: VirtualProvider,
    started: Instant,
    last_activity: Instant,
    pending: Option<Pending>,
}

enum State {
    Closed,
    Open(PublicHeader), // untrusted public framing only
    Loaded(Box<Loaded>),
    Locked,
}

/// The state manager owns its loaded fields exclusively and intentionally
/// implements neither Clone nor Debug. It has no production load constructor.
pub struct Session {
    state: State,
    limits: SessionLimits,
    monitor_live: bool,
    last_lock_reason: Option<LockReason>,
}
impl Session {
    pub fn new(limits: SessionLimits) -> Self {
        Self { state: State::Closed, limits, monitor_live: false,
            last_lock_reason: None }
    }
    pub fn phase(&self) -> Phase {
        match self.state {
            State::Closed => Phase::Closed,
            State::Open(_) => Phase::Open,
            State::Loaded(_) => Phase::Loaded,
            State::Locked => Phase::Locked,
        }
    }
    pub fn last_lock_reason(&self) -> Option<LockReason> { self.last_lock_reason }

    /// Public header parse is unauthenticated. Never turn its slots or IDs
    /// into trusted authorities without a separate VMK authenticated load.
    pub fn inspect_public_file(&mut self, bytes: &[u8]) -> Result<PublicSummary, SessionError> {
        if !matches!(self.state, State::Closed | State::Locked) {
            return Err(SessionError::WrongPhase);
        }
        let header = v02::read_public_header(bytes)
            .map_err(|_| SessionError::PublicHeaderRejected)?;
        let summary = PublicSummary {
            vault_id: header.vault_id, generation: header.generation, authenticated: false,
        };
        self.state = State::Open(header);
        self.monitor_live = false;
        self.last_lock_reason = None;
        Ok(summary)
    }

    /// Explicit owner close drops all loaded metadata and secret buffers.
    pub fn close(&mut self) {
        self.state = State::Closed;
        self.monitor_live = false;
    }
    /// Drop all loaded material and pending intents. Not a claim that the
    /// allocator/OS cleared copies outside these owned Zeroizing buffers.
    pub fn lock(&mut self, reason: LockReason) {
        self.state = State::Locked;
        self.monitor_live = false;
        self.last_lock_reason = Some(reason);
    }
    pub fn on_lifecycle(&mut self, event: LifecycleEvent) {
        let reason = match event {
            LifecycleEvent::ScreenLocked => Some(LockReason::ScreenLock),
            LifecycleEvent::Suspend => Some(LockReason::Suspend),
            LifecycleEvent::Hibernate => Some(LockReason::Hibernate),
            LifecycleEvent::ListenerDisconnected | LifecycleEvent::ListenerFailed =>
                Some(LockReason::ListenerUnavailable),
            // Resume never resurrects a locked/unloaded session.
            LifecycleEvent::Resumed => None,
        };
        if let Some(reason) = reason { self.lock(reason); }
    }
    /// Must be called on an independent lifecycle timer by the future daemon.
    /// Every attempted secret operation checks these same limits itself.
    pub fn poll(&mut self) -> bool { self.poll_at(Instant::now()) }
    fn poll_at(&mut self, now: Instant) -> bool {
        let reason = match &self.state {
            State::Loaded(loaded) if !self.monitor_live =>
                Some(LockReason::ListenerUnavailable),
            State::Loaded(loaded)
                if now.saturating_duration_since(loaded.started) >= self.limits.absolute =>
                Some(LockReason::AbsoluteLifetime),
            State::Loaded(loaded)
                if now.saturating_duration_since(loaded.last_activity) >= self.limits.inactivity =>
                Some(LockReason::IdleTimeout),
            _ => None,
        };
        if let Some(reason) = reason {
            self.lock(reason);
            return true;
        }
        if let State::Loaded(loaded) = &mut self.state {
            if loaded.pending.as_ref().is_some_and(|p| now >= p.expires()) {
                loaded.pending = None;
                loaded.masked_vers.rotate();
            }
        }
        false
    }
    fn require_loaded(&mut self, now: Instant) -> Result<&mut Loaded, SessionError> {
        if !matches!(self.state, State::Loaded(_)) {
            return Err(SessionError::WrongPhase);
        }
        if self.poll_at(now) { return Err(SessionError::Expired); }
        match &mut self.state {
            State::Loaded(loaded) => Ok(loaded),
            _ => Err(SessionError::WrongPhase),
        }
    }
    pub fn begin_read(&mut self, entry_id: Uuid) -> Result<ReadIntent, SessionError> {
        self.begin_read_at(entry_id, Instant::now())
    }
    fn begin_read_at(&mut self, entry_id: Uuid, now: Instant)
        -> Result<ReadIntent, SessionError>
    {
        let loaded = self.require_loaded(now)?;
        if loaded.pending.is_some() { return Err(SessionError::Busy); }
        let record = loaded.body.entries.iter()
            .find(|e| e.id == entry_id && !e.tombstone)
            .ok_or(SessionError::MissingEntry)?;
        let first = match record.mode {
            EntryMode::DefaultVirtual | EntryMode::DefaultPhysical => FirstFactor::MaskedVers,
            EntryMode::CustomVirtual | EntryMode::CustomPhysical => FirstFactor::FreshEntryPassword,
        };
        let provider = match record.mode {
            EntryMode::DefaultVirtual | EntryMode::CustomVirtual =>
                ProviderRequirement::VirtualNonFactor,
            EntryMode::DefaultPhysical | EntryMode::CustomPhysical =>
                ProviderRequirement::FreshPhysicalFido2,
        };
        if record.tier == EntryTier::Isolated
            && provider != ProviderRequirement::FreshPhysicalFido2
        {
            return Err(SessionError::InvalidEntryPolicy);
        }
        // Every read creates a fresh identity; the physical branch has no
        // "previous touch" cache, and no branch has a trusted backend yet.
        let operation_id = Uuid::new_v4();
        loaded.pending = Some(Pending::Read {
            id: operation_id,
            expires: now.checked_add(Duration::from_secs(15))
                .ok_or(SessionError::InvalidLimits)?,
        });
        loaded.last_activity = now;
        Ok(ReadIntent {
            operation_id, entry_id, first, provider, tier: record.tier, authorized: false,
        })
    }
    /// A bounded, unapproved plan only. No staging, owner approval, VMK
    /// authorization, disk writes or alternative commit path exists in V03 v0.
    pub fn begin_write(&mut self, ttl: Duration, max_changes: u16)
        -> Result<WriteIntent, SessionError>
    {
        self.begin_write_at(ttl, max_changes, Instant::now())
    }
    fn begin_write_at(&mut self, ttl: Duration, max_changes: u16, now: Instant)
        -> Result<WriteIntent, SessionError>
    {
        if ttl.is_zero() || ttl > Duration::from_secs(300)
            || !(1..=64).contains(&max_changes)
        {
            return Err(SessionError::InvalidLimits);
        }
        let loaded = self.require_loaded(now)?;
        if loaded.pending.is_some() { return Err(SessionError::Busy); }
        let operation_id = Uuid::new_v4();
        loaded.pending = Some(Pending::Write {
            id: operation_id,
            expires: now.checked_add(ttl).ok_or(SessionError::InvalidLimits)?,
        });
        loaded.last_activity = now;
        Ok(WriteIntent {
            operation_id,
            base_vault_id: loaded.header.vault_id,
            base_commit_id: loaded.header.commit_id,
            base_generation: loaded.header.generation,
            max_changes, authorized: false,
        })
    }
    /// Always refuses to complete read/write authorization. The future V04/V06
    /// trusted daemon must create non-forgeable factor and owner-approval
    /// evidence; a caller-provided boolean or previously successful hardware
    /// touch must never turn this into plaintext or commit authority.
    pub fn refuse_unimplemented(&mut self, operation_id: Uuid)
        -> Result<(), SessionError>
    {
        let loaded = self.require_loaded(Instant::now())?;
        if loaded.pending.as_ref().map(Pending::id) != Some(operation_id) {
            return Err(SessionError::InvalidOperation);
        }
        loaded.pending = None;
        loaded.masked_vers.rotate();
        Err(SessionError::UnsupportedAuthorization)
    }
    pub fn cancel_pending(&mut self) {
        if let State::Loaded(loaded) = &mut self.state {
            loaded.pending = None;
            loaded.masked_vers.rotate();
        }
    }

    // IMPORTANT: this is *only* an internal synthetic transition for
    // state-machine tests. There is no equivalent production entry point;
    // real OPEN->LOADED requires an audited VMK, last-seen-head gate,
    // registered provider bootstrap and a trusted lifecycle monitor.
    #[cfg(test)]
    fn load_synthetic(&mut self, opened: v02::Opened, vers: [u8; 32],
                      provider_seed: [u8; 32], now: Instant)
        -> Result<(), SessionError>
    {
        match &self.state {
            State::Open(header) if *header == opened.header &&
                opened.body.vault_id == header.vault_id &&
                opened.body.commit_id == header.commit_id &&
                opened.body.generation == header.generation => (),
            _ => {
                self.lock(LockReason::InvalidAuthenticatedTransition);
                return Err(SessionError::WrongPhase);
            }
        }
        self.state = State::Loaded(Box::new(Loaded {
            header: opened.header,
            body: opened.body,
            masked_vers: MaskedVers::from_independent_secret(Zeroizing::new(vers)),
            virtual_provider: VirtualProvider::synthetic(provider_seed),
            started: now,
            last_activity: now,
            pending: None,
        }));
        // The test must explicitly emulate a healthy listener. No public
        // caller can declare the real lifecycle monitor healthy.
        self.monitor_live = false;
        Ok(())
    }
    #[cfg(test)]
    fn synthetic_monitor_registered(&mut self) {
        self.monitor_live = true;
    }
}
#[cfg(test)]
#[path = "v03_tests.rs"]
mod tests;
