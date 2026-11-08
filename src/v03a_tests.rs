//! Synthetic V03-A regression suite. No native D-Bus, HID, PIN or secrets.
use super::*;
use crate::v02::{self, EntryRecord, EntryMode, EntryTier, FactorPolicy,
    PublicHeader, RecoveryPolicy, Slot, SlotTarget, VaultBody, VaultMode, Vmk};
use crate::v03::{Phase, LockReason, SessionLimits};
use std::time::{Duration, Instant};

fn fixture() -> (Session, [Uuid; 4]) {
    let header = PublicHeader::genesis(VaultMode::PasswordVirtual, vec![
        Slot::pending(SlotTarget::Vmk, Uuid::nil(), FactorPolicy::VaultPasswordVirtual),
        Slot::pending(SlotTarget::Vmk, Uuid::nil(), FactorPolicy::CodeOnly),
    ]);
    let mut body = VaultBody::for_header(&header);
    let modes = [
        (EntryMode::DefaultVirtual, EntryTier::Standard),
        (EntryMode::DefaultPhysical, EntryTier::Standard),
        (EntryMode::CustomPhysical, EntryTier::Isolated),
        (EntryMode::CustomVirtual, EntryTier::Standard),
    ];
    let mut ids = [Uuid::nil(); 4];
    for (index, (mode, tier)) in modes.into_iter().enumerate() {
        let id = Uuid::new_v4();
        ids[index] = id;
        body.entries.push(EntryRecord {
            id, revision: 1, mode, tier, recovery: RecoveryPolicy::StrictNone,
            tombstone: false, title: format!("synthetic-{index}"),
            username: String::new(), origin: String::new(),
            nonce: [index as u8 + 1; 24], ciphertext: vec![0x36; 16],
            dek_slots: vec![],
        });
    }
    let vmk = Vmk::random();
    let sealed = v02::seal_file(&header, &body, &vmk).unwrap();
    let opened = v02::open_file(&sealed, &vmk).unwrap();
    let mut session = Session::new(
        SessionLimits::new(Duration::from_secs(30), Duration::from_secs(90)).unwrap());
    session.inspect_public_file(&sealed).unwrap();
    session.load_synthetic(opened, [0x11; 32], [0x22; 32], Instant::now()).unwrap();
    session.synthetic_monitor_registered();
    (session, ids)
}

#[test]
fn untrusted_monitor_never_grants_health_and_locks_on_first_check() {
    let (mut session, ids) = fixture();
    let intent = session.begin_read(ids[0]).unwrap();
    let mut monitor = LifecycleGuard::new(Duration::from_secs(5)).unwrap();
    assert_eq!(monitor.enforce(&mut session), Err(MonitorError::NotTrusted));
    assert_eq!(session.phase(), Phase::Locked);
    assert_eq!(session.last_lock_reason(), Some(LockReason::ListenerUnavailable));
    assert_eq!(AuthenticatorBoundary::new().attempt_read(
        &mut session, &intent, &VirtualNonFactorAdapter, None),
        Err(BoundaryDeny::StaleOperation));
    assert_eq!(monitor.enforce(&mut session), Err(MonitorError::NotTrusted));
    assert_eq!(session.phase(), Phase::Locked);
}

#[test]
fn synthetic_watchdog_heartbeat_expires_and_cannot_be_revived() {
    for timeout in [Duration::ZERO, Duration::from_secs(61)] {
        assert!(matches!(LifecycleGuard::new(timeout),
                         Err(MonitorError::InvalidWatchdog)));
    }
    let (mut session, _) = fixture();
    let now = Instant::now();
    let mut monitor = LifecycleGuard::new(Duration::from_secs(5)).unwrap();
    monitor.simulate_verified_source(&mut session, now);
    assert_eq!(monitor.enforce_at(&mut session, now + Duration::from_secs(4)), Ok(()));
    monitor.simulate_health_poll(now + Duration::from_secs(4));
    assert_eq!(monitor.enforce_at(&mut session, now + Duration::from_secs(8)), Ok(()));
    assert_eq!(monitor.enforce_at(&mut session, now + Duration::from_secs(9)),
               Err(MonitorError::Stale));
    assert_eq!(session.phase(), Phase::Locked);
    assert_eq!(session.last_lock_reason(), Some(LockReason::ListenerUnavailable));
    monitor.simulate_health_poll(now + Duration::from_secs(10));
    assert_eq!(monitor.enforce_at(&mut session, now + Duration::from_secs(10)),
               Err(MonitorError::NotTrusted));
}

#[test]
fn linux_logind_events_lock_even_on_unexpected_wake_or_unlock() {
    let events = [
        (LogindSafetyEvent::SessionLocked, LockReason::ScreenLock),
        (LogindSafetyEvent::SessionUnlocked, LockReason::ListenerUnavailable),
        (LogindSafetyEvent::PrepareForSleep(true), LockReason::Suspend),
        (LogindSafetyEvent::PrepareForSleep(false), LockReason::Suspend),
        (LogindSafetyEvent::PrepareForShutdown(true), LockReason::Hibernate),
        (LogindSafetyEvent::PrepareForShutdown(false), LockReason::ListenerUnavailable),
        (LogindSafetyEvent::SessionRemoved, LockReason::ListenerUnavailable),
        (LogindSafetyEvent::SubscriptionLost, LockReason::ListenerUnavailable),
        (LogindSafetyEvent::MalformedOrUnknown, LockReason::ListenerUnavailable),
    ];
    for (event, expected) in events {
        let (mut session, ids) = fixture();
        let intent = session.begin_read(ids[2]).unwrap();
        let mut monitor = LifecycleGuard::new(Duration::from_secs(5)).unwrap();
        monitor.simulate_verified_source(&mut session, Instant::now());
        monitor.handle_linux_event(&mut session, event);
        assert_eq!(session.phase(), Phase::Locked, "{event:?}");
        assert_eq!(session.last_lock_reason(), Some(expected), "{event:?}");
        assert_eq!(monitor.enforce(&mut session), Err(MonitorError::NotTrusted));
        assert_eq!(AuthenticatorBoundary::new().attempt_read(
            &mut session, &intent, &PhysicalFido2Adapter, Some(Uuid::new_v4())),
            Err(BoundaryDeny::StaleOperation));
    }
}

#[test]
fn physical_never_downgrades_to_virtual_and_mismatch_consumes_only_matching_intent() {
    let (mut session, ids) = fixture();
    let boundary = AuthenticatorBoundary::new();
    let intent = session.begin_read(ids[2]).unwrap();
    assert_eq!(intent.provider, ProviderRequirement::FreshPhysicalFido2);
    assert_eq!(boundary.attempt_read(&mut session, &intent,
               &VirtualNonFactorAdapter, None), Err(BoundaryDeny::WrongProvider));
    assert_eq!(boundary.attempt_read(&mut session, &intent,
               &PhysicalFido2Adapter, None), Err(BoundaryDeny::StaleOperation));
    let virtual_intent = session.begin_read(ids[0]).unwrap();
    assert_eq!(boundary.attempt_read(&mut session, &virtual_intent,
               &PhysicalFido2Adapter, Some(Uuid::new_v4())),
               Err(BoundaryDeny::WrongProvider));
    assert_eq!(boundary.attempt_read(&mut session, &virtual_intent,
               &VirtualNonFactorAdapter, None), Err(BoundaryDeny::StaleOperation));
    assert!(!real_authenticator_authorization_available());
}

#[test]
fn hardware_registry_states_deny_and_never_expose_an_authentication_capability() {
    let (mut session, ids) = fixture();
    let mut boundary = AuthenticatorBoundary::new();
    let id = Uuid::new_v4();
    for (state, expected) in [
        (None, BoundaryDeny::MissingCredential),
        (Some(PhysicalCredentialState::Suspended), BoundaryDeny::SuspendedCredential),
        (Some(PhysicalCredentialState::Revoked), BoundaryDeny::RevokedCredential),
        (Some(PhysicalCredentialState::Active), BoundaryDeny::TrustedBackendUnavailable),
    ] {
        if let Some(state) = state { boundary.set_synthetic_credential(id, state); }
        let intent = session.begin_read(ids[1]).unwrap();
        let result = boundary.attempt_read(&mut session, &intent,
                   &PhysicalFido2Adapter, Some(id));
        assert_eq!(result, Err(expected));
        assert!(!intent.is_authorized());
        assert_eq!(session.phase(), Phase::Loaded);
    }
    let intent = session.begin_read(ids[2]).unwrap();
    assert_eq!(boundary.attempt_read(&mut session, &intent,
               &PhysicalFido2Adapter, None), Err(BoundaryDeny::MissingCredential));
}

#[test]
fn forged_intent_fields_or_replayed_operation_are_rejected() {
    let (mut session, ids) = fixture();
    let boundary = AuthenticatorBoundary::new();
    let original = session.begin_read(ids[1]).unwrap();
    let mut spoofed = original;
    spoofed.entry_id = ids[0];
    assert_eq!(boundary.attempt_read(&mut session, &spoofed,
               &PhysicalFido2Adapter, None), Err(BoundaryDeny::StaleOperation));
    spoofed = original;
    spoofed.provider = ProviderRequirement::VirtualNonFactor;
    assert_eq!(boundary.attempt_read(&mut session, &spoofed,
               &VirtualNonFactorAdapter, None), Err(BoundaryDeny::StaleOperation));
    // Rejected forgeries do not cancel the original active operation.
    assert_eq!(boundary.attempt_read(&mut session, &original,
               &PhysicalFido2Adapter, None), Err(BoundaryDeny::MissingCredential));
    assert_eq!(boundary.attempt_read(&mut session, &original,
               &PhysicalFido2Adapter, None), Err(BoundaryDeny::StaleOperation));
}

#[test]
fn virtual_adapter_is_a_nonfactor_and_still_cannot_release_secrets() {
    let (mut session, ids) = fixture();
    let boundary = AuthenticatorBoundary::new();
    let intent = session.begin_read(ids[3]).unwrap();
    assert_eq!(intent.provider, ProviderRequirement::VirtualNonFactor);
    assert_eq!(boundary.attempt_read(&mut session, &intent,
               &VirtualNonFactorAdapter, None),
               Err(BoundaryDeny::TrustedBackendUnavailable));
    assert!(!intent.is_authorized());
    assert_eq!(session.phase(), Phase::Loaded);
    session.close();
    assert_eq!(session.phase(), Phase::Closed);
}

#[test]
fn lock_and_cancel_clear_pending_before_any_provider_can_finish() {
    let (mut session, ids) = fixture();
    let boundary = AuthenticatorBoundary::new();
    let intent = session.begin_read(ids[1]).unwrap();
    session.cancel_pending();
    assert_eq!(boundary.attempt_read(&mut session, &intent,
               &PhysicalFido2Adapter, None), Err(BoundaryDeny::StaleOperation));
    let intent = session.begin_read(ids[1]).unwrap();
    session.on_lifecycle(LifecycleEvent::Suspend);
    assert_eq!(session.phase(), Phase::Locked);
    assert_eq!(boundary.attempt_read(&mut session, &intent,
               &PhysicalFido2Adapter, None), Err(BoundaryDeny::StaleOperation));
}
