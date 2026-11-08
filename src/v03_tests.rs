//! Synthetic, offline-only state-machine regression tests. Real Vaulty
//! credentials and physical tokens are never touched by this module.
use super::*;
use crate::v02::{
    EntryRecord, FactorPolicy, Opened, RecoveryPolicy, Slot, SlotTarget, VaultMode, Vmk,
};
use std::panic::{AssertUnwindSafe, catch_unwind};

fn file_and_opened() -> (Vec<u8>, Opened, [Uuid; 5]) {
    let header = PublicHeader::genesis(VaultMode::PasswordVirtual, vec![
        Slot::pending(SlotTarget::Vmk, Uuid::nil(), FactorPolicy::VaultPasswordVirtual),
        Slot::pending(SlotTarget::Vmk, Uuid::nil(), FactorPolicy::CodeOnly),
    ]);
    let mut body = VaultBody::for_header(&header);
    let policies = [
        (EntryMode::DefaultVirtual, EntryTier::Standard),
        (EntryMode::DefaultPhysical, EntryTier::Standard),
        (EntryMode::CustomVirtual, EntryTier::Standard),
        (EntryMode::CustomPhysical, EntryTier::Standard),
        (EntryMode::CustomPhysical, EntryTier::Isolated),
    ];
    let mut ids = [Uuid::nil(); 5];
    for (index, (mode, tier)) in policies.into_iter().enumerate() {
        let id = Uuid::new_v4();
        ids[index] = id;
        // The V03 model never opens this synthetic ciphertext: no real
        // DEK/wrapping slot or credential authorization is represented.
        body.entries.push(EntryRecord {
            id, revision: 1, mode, tier, recovery: RecoveryPolicy::StrictNone,
            tombstone: false, title: format!("test-{index}"),
            username: String::new(), origin: String::new(),
            nonce: [index as u8 + 1; 24], ciphertext: vec![0x7f; 16],
            dek_slots: vec![],
        });
    }
    let vmk = Vmk::random();
    let file = crate::v02::seal_file(&header, &body, &vmk)
        .expect("synthetic V02 file");
    let opened = crate::v02::open_file(&file, &vmk).expect("synthetic V02 load");
    (file, opened, ids)
}
fn limits() -> SessionLimits {
    SessionLimits::new(Duration::from_secs(30), Duration::from_secs(90)).unwrap()
}
fn loaded_fixture() -> (Session, [Uuid; 5], Instant) {
    let now = Instant::now();
    let (file, opened, ids) = file_and_opened();
    let mut session = Session::new(limits());
    assert!(!session.inspect_public_file(&file).unwrap().authenticated);
    session.load_synthetic(opened, [9; 32], [7; 32], now).unwrap();
    session.synthetic_monitor_registered();
    (session, ids, now)
}

#[test]
fn session_limits_reject_unbounded_and_inverted_lifetimes() {
    assert_eq!(SessionLimits::new(Duration::ZERO, Duration::from_secs(1)),
        Err(SessionError::InvalidLimits));
    assert_eq!(SessionLimits::new(Duration::from_secs(10), Duration::from_secs(10)),
        Err(SessionError::InvalidLimits));
    assert_eq!(SessionLimits::new(Duration::from_secs(11), Duration::from_secs(10)),
        Err(SessionError::InvalidLimits));
    assert_eq!(SessionLimits::new(Duration::from_secs(1), Duration::from_secs(86401)),
        Err(SessionError::InvalidLimits));
    assert!(SessionLimits::new(Duration::from_secs(15), Duration::from_secs(60)).is_ok());
}

#[test]
fn public_only_open_rejects_malformed_and_never_claims_authentication() {
    let (file, _, _) = file_and_opened();
    let mut session = Session::new(limits());
    assert_eq!(session.phase(), Phase::Closed);
    assert_eq!(session.inspect_public_file(&[0u8; 4]),
        Err(SessionError::PublicHeaderRejected));
    assert_eq!(session.phase(), Phase::Closed);
    let summary = session.inspect_public_file(&file).unwrap();
    assert!(!summary.authenticated);
    assert!(!summary.vault_id.is_nil());
    assert_eq!(summary.generation, 1);
    assert_eq!(session.phase(), Phase::Open);
    assert_eq!(session.inspect_public_file(&file), Err(SessionError::WrongPhase));
    assert_eq!(session.begin_read(Uuid::new_v4()), Err(SessionError::WrongPhase));
    session.close();
    assert_eq!(session.phase(), Phase::Closed);
    session.lock(LockReason::Owner);
    assert_eq!(session.phase(), Phase::Locked);
    assert_eq!(session.last_lock_reason(), Some(LockReason::Owner));
    assert_eq!(session.inspect_public_file(&file).unwrap().authenticated, false);
    assert_eq!(session.phase(), Phase::Open);
}

#[test]
fn all_four_entry_modes_choose_only_their_explicit_provider() {
    let (mut session, ids, now) = loaded_fixture();
    let expected = [
        (FirstFactor::MaskedVers, ProviderRequirement::VirtualNonFactor, EntryTier::Standard),
        (FirstFactor::MaskedVers, ProviderRequirement::FreshPhysicalFido2, EntryTier::Standard),
        (FirstFactor::FreshEntryPassword, ProviderRequirement::VirtualNonFactor, EntryTier::Standard),
        (FirstFactor::FreshEntryPassword, ProviderRequirement::FreshPhysicalFido2, EntryTier::Standard),
        (FirstFactor::FreshEntryPassword, ProviderRequirement::FreshPhysicalFido2, EntryTier::Isolated),
    ];
    for (index, (first, provider, tier)) in expected.into_iter().enumerate() {
        let intent = session.begin_read_at(ids[index], now).unwrap();
        assert_eq!(intent.first, first);
        assert_eq!(intent.provider, provider);
        assert_eq!(intent.tier, tier);
        assert!(!intent.authorized);
        assert_eq!(session.refuse_unimplemented(intent.operation_id),
            Err(SessionError::UnsupportedAuthorization));
        assert_eq!(session.phase(), Phase::Loaded);
    }
}

#[test]
fn intent_ids_are_fresh_and_stale_or_unimplemented_operations_fail_closed() {
    let (mut session, ids, _) = loaded_fixture();
    let first = session.begin_read(ids[1]).unwrap();
    assert_eq!(first.provider, ProviderRequirement::FreshPhysicalFido2);
    assert_eq!(session.begin_read(ids[0]), Err(SessionError::Busy));
    assert_eq!(session.refuse_unimplemented(Uuid::new_v4()),
        Err(SessionError::InvalidOperation));
    assert_eq!(session.begin_read(ids[0]), Err(SessionError::Busy));
    session.cancel_pending();
    let second = session.begin_read(ids[1]).unwrap();
    assert_ne!(first.operation_id, second.operation_id);
    assert_eq!(session.refuse_unimplemented(first.operation_id),
        Err(SessionError::InvalidOperation));
    assert_eq!(session.refuse_unimplemented(second.operation_id),
        Err(SessionError::UnsupportedAuthorization));
    assert_eq!(session.refuse_unimplemented(second.operation_id),
        Err(SessionError::InvalidOperation));
    assert_eq!(session.begin_read(Uuid::new_v4()), Err(SessionError::MissingEntry));
}

#[test]
fn idle_timer_and_absolute_timer_are_independent() {
    let (mut session, ids, started) = loaded_fixture();
    // An operation at t=20 renews idle only. At t=41 no idle expiry.
    let intent = session.begin_read_at(ids[0], started + Duration::from_secs(20)).unwrap();
    session.cancel_pending();
    assert!(!session.poll_at(started + Duration::from_secs(41)));
    assert_eq!(session.phase(), Phase::Loaded);
    // No further activity: idle expiry at t=50 (last activity t=20).
    assert!(session.poll_at(started + Duration::from_secs(50)));
    assert_eq!(session.last_lock_reason(), Some(LockReason::IdleTimeout));

    let (mut session, ids, started) = loaded_fixture();
    let intent = session.begin_read_at(ids[2], started + Duration::from_secs(25)).unwrap();
    session.cancel_pending();
    let second = session.begin_read_at(ids[2], started + Duration::from_secs(50)).unwrap();
    session.cancel_pending();
    let third = session.begin_read_at(ids[2], started + Duration::from_secs(75)).unwrap();
    session.cancel_pending();
    assert_ne!(intent.operation_id, second.operation_id);
    assert_ne!(second.operation_id, third.operation_id);
    assert!(session.poll_at(started + Duration::from_secs(90)));
    assert_eq!(session.last_lock_reason(), Some(LockReason::AbsoluteLifetime));
    assert_eq!(session.begin_read(ids[2]), Err(SessionError::WrongPhase));
}

#[test]
fn listener_is_required_and_loss_always_locks_without_resumption() {
    let now = Instant::now();
    let (file, opened, ids) = file_and_opened();
    let mut session = Session::new(limits());
    session.inspect_public_file(&file).unwrap();
    session.load_synthetic(opened, [9; 32], [5; 32], now).unwrap();
    assert_eq!(session.begin_read(ids[0]), Err(SessionError::Expired));
    assert_eq!(session.phase(), Phase::Locked);
    assert_eq!(session.last_lock_reason(), Some(LockReason::ListenerUnavailable));
    session.on_lifecycle(LifecycleEvent::Resumed);
    assert_eq!(session.phase(), Phase::Locked);

    for (event, reason) in [
        (LifecycleEvent::ScreenLocked, LockReason::ScreenLock),
        (LifecycleEvent::Suspend, LockReason::Suspend),
        (LifecycleEvent::Hibernate, LockReason::Hibernate),
        (LifecycleEvent::ListenerDisconnected, LockReason::ListenerUnavailable),
        (LifecycleEvent::ListenerFailed, LockReason::ListenerUnavailable),
    ] {
        let (mut session, ids, _) = loaded_fixture();
        session.begin_read(ids[4]).unwrap();
        session.on_lifecycle(event);
        assert_eq!(session.phase(), Phase::Locked);
        assert_eq!(session.last_lock_reason(), Some(reason));
        assert_eq!(session.refuse_unimplemented(Uuid::new_v4()),
            Err(SessionError::WrongPhase));
        session.on_lifecycle(LifecycleEvent::Resumed);
        assert_eq!(session.phase(), Phase::Locked);
    }
}

#[test]
fn read_intent_expiration_cancels_it_without_extending_session_lifetime() {
    let (mut session, ids, started) = loaded_fixture();
    let first = session.begin_read_at(ids[0], started).unwrap();
    assert!(!session.poll_at(started + Duration::from_secs(30)));
    assert_eq!(session.refuse_unimplemented(first.operation_id),
        Err(SessionError::InvalidOperation));
    assert_eq!(session.phase(), Phase::Loaded);
}

#[test]
fn write_intent_is_bounded_by_ttl_cap_and_authenticated_base_but_never_commits() {
    let (mut session, ids, started) = loaded_fixture();
    assert_eq!(session.begin_write_at(Duration::ZERO, 1, started),
        Err(SessionError::InvalidLimits));
    assert_eq!(session.begin_write_at(Duration::from_secs(301), 1, started),
        Err(SessionError::InvalidLimits));
    assert_eq!(session.begin_write_at(Duration::from_secs(5), 0, started),
        Err(SessionError::InvalidLimits));
    assert_eq!(session.begin_write_at(Duration::from_secs(5), 65, started),
        Err(SessionError::InvalidLimits));
    let intent = session.begin_write_at(Duration::from_secs(5), 20, started).unwrap();
    assert!(!intent.authorized);
    assert_eq!(intent.base_generation, 1);
    assert!(!intent.base_vault_id.is_nil());
    assert!(!intent.base_commit_id.is_nil());
    assert_eq!(intent.max_changes, 20);
    assert_eq!(session.begin_read(ids[0]), Err(SessionError::Busy));
    assert!(!session.poll_at(started + Duration::from_secs(5)));
    assert_eq!(session.refuse_unimplemented(intent.operation_id),
        Err(SessionError::InvalidOperation));
    let next = session.begin_write_at(Duration::from_secs(5), 1,
        started + Duration::from_secs(6)).unwrap();
    assert_ne!(intent.operation_id, next.operation_id);
    assert_eq!(session.refuse_unimplemented(next.operation_id),
        Err(SessionError::UnsupportedAuthorization));
}

#[test]
fn masking_reconstructs_only_inside_a_bounded_closure_and_remasks() {
    let mut masked = MaskedVers::from_independent_secret(Zeroizing::new([0x5a; 32]));
    let before_a = *masked.share_a;
    let before_b = *masked.share_b;
    masked.with_transient(|secret| assert_eq!(secret, &[0x5a; 32]));
    assert_ne!(*masked.share_a, before_a);
    assert_ne!(*masked.share_b, before_b);
    assert_eq!(masked.with_transient(|secret| *secret), [0x5a; 32]);
    let old = *masked.share_a;
    let _ = catch_unwind(AssertUnwindSafe(|| {
        masked.with_transient(|secret| {
            assert_eq!(secret, &[0x5a; 32]);
            panic!("synthetic panic during read");
        });
    }));
    assert_ne!(*masked.share_a, old);
    assert_eq!(masked.with_transient(|secret| *secret), [0x5a; 32]);
}

#[test]
fn synthetic_loader_requires_matching_public_and_authenticated_file() {
    let (file, _, _) = file_and_opened();
    let (_, another_opened, _) = file_and_opened();
    let mut session = Session::new(limits());
    session.inspect_public_file(&file).unwrap();
    assert_eq!(session.load_synthetic(another_opened, [1; 32], [2; 32], Instant::now()),
        Err(SessionError::WrongPhase));
    assert_eq!(session.phase(), Phase::Locked);
    assert_eq!(session.last_lock_reason(),
        Some(LockReason::InvalidAuthenticatedTransition));
}

#[test]
fn no_session_operation_releases_a_secret_or_changes_vault() {
    let (mut session, ids, _) = loaded_fixture();
    let intent = session.begin_read(ids[4]).unwrap();
    assert_eq!(session.refuse_unimplemented(intent.operation_id),
        Err(SessionError::UnsupportedAuthorization));
    assert_eq!(session.phase(), Phase::Loaded);
    let write = session.begin_write(Duration::from_secs(10), 2).unwrap();
    assert_eq!(session.refuse_unimplemented(write.operation_id),
        Err(SessionError::UnsupportedAuthorization));
    session.close();
    assert_eq!(session.phase(), Phase::Closed);
    assert_eq!(session.begin_write(Duration::from_secs(10), 2),
        Err(SessionError::WrongPhase));
}
