use super::*;
use super::codec;
use super::storage::{self, CommitOutcome, Phase};
use std::fs;

fn specimen() -> (PublicHeader, VaultBody, Vmk, Vers, Dek) {
    let vmk_slots = vec![
        Slot::pending(SlotTarget::Vmk, Uuid::nil(), FactorPolicy::VaultPasswordVirtual),
        Slot::pending(SlotTarget::Vmk, Uuid::nil(), FactorPolicy::CodeOnly),
    ];
    let header = PublicHeader::genesis(VaultMode::PasswordVirtual, vmk_slots);
    let mut body = VaultBody::for_header(&header);
    let dek = Dek::random();
    let id = Uuid::new_v4();
    let mut entry = EntryRecord {
        id, revision: 1, mode: EntryMode::DefaultVirtual,
        tier: EntryTier::Standard, recovery: RecoveryPolicy::Shared, tombstone: false,
        title: "synthetic-bank-title".into(), username: "synthetic-user".into(),
        origin: "https://example.org".into(), nonce: [0; 24], ciphertext: vec![],
        dek_slots: vec![Slot::pending(SlotTarget::EntryDek, id, FactorPolicy::DefaultVirtual)],
    };
    seal_entry(header.vault_id, &mut entry, &dek, b"SYNTHETIC_TEST_SECRET_ONLY").unwrap();
    body.entries.push(entry);
    (header, body, Vmk::random(), Vers::random(), dek)
}
fn temp_file(label: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("vaulty-v02-{}-{}", label, Uuid::new_v4()));
    fs::create_dir(&dir).unwrap();
    let file = dir.join("vault.v2");
    (dir, file)
}
fn immutable_backups(dir: &std::path::Path, active: &std::path::Path) -> Vec<std::path::PathBuf> {
    let prefix = format!("{}.previous-", active.file_name().unwrap().to_string_lossy());
    fs::read_dir(dir).unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.file_name().unwrap().to_string_lossy().starts_with(&prefix))
        .collect()
}
fn vault_lock(active: &std::path::Path) -> std::path::PathBuf {
    active.with_file_name(format!("{}.lock", active.file_name().unwrap().to_string_lossy()))
}

#[test]
fn separated_random_roots_and_entry_payload_round_trip() {
    let (header, body, vmk, vers, dek) = specimen();
    // The VERS and DEK types are not interchangeable with VMK at compile time.
    assert_ne!(&vmk.0[..], &vers.0[..]);
    assert_ne!(&vmk.0[..], &dek.0[..]);
    assert_ne!(&vers.0[..], &dek.0[..]);
    let file = seal_file(&header, &body, &vmk).unwrap();
    assert!(!file.windows(b"synthetic-bank-title".len())
        .any(|w| w == b"synthetic-bank-title"));
    assert!(!file.windows(b"SYNTHETIC_TEST_SECRET_ONLY".len())
        .any(|w| w == b"SYNTHETIC_TEST_SECRET_ONLY"));
    let opened = open_file(&file, &vmk).unwrap();
    assert_eq!(opened.header.vault_id, header.vault_id);
    assert_eq!(opened.body.entries[0].title, "synthetic-bank-title");
    assert_eq!(open_entry(header.vault_id, &opened.body.entries[0], &dek, header.mode).unwrap().as_slice(),
        b"SYNTHETIC_TEST_SECRET_ONLY");
    assert_eq!(open_file(&file, &Vmk::random()).err(), Some(V02Error::AuthenticationFailed));
    assert_eq!(open_entry(header.vault_id, &opened.body.entries[0], &Dek::random(), header.mode).err(),
        Some(V02Error::AuthenticationFailed));
}

#[test]
fn nonce_changes_for_every_outer_and_entry_encryption() {
    let (header, body, vmk, _, dek) = specimen();
    let a = seal_file(&header, &body, &vmk).unwrap();
    let b = seal_file(&header, &body, &vmk).unwrap();
    assert_ne!(a, b);
    let pa = codec::parse_header(&a).unwrap();
    let pb = codec::parse_header(&b).unwrap();
    assert_ne!(pa.outer_nonce, pb.outer_nonce);
    let mut entry = body.entries[0].clone();
    let first = entry.nonce;
    seal_entry(header.vault_id, &mut entry, &dek, b"SYNTHETIC_TEST_SECRET_ONLY").unwrap();
    assert_ne!(entry.nonce, first);
    assert_ne!(entry.ciphertext, body.entries[0].ciphertext);
}

#[test]
fn tampering_header_and_body_fails_authenticated_open() {
    let (header, body, vmk, _, _) = specimen();
    let original = seal_file(&header, &body, &vmk).unwrap();
    let header_len = codec::parse_header(&original).unwrap().aad_header.len();
    for index in [4, 6, 8, 12, 16, 32, 56, 89, header_len - 1, header_len, original.len()-1] {
        let mut tampered = original.clone();
        tampered[index] ^= 1;
        assert!(open_file(&tampered, &vmk).is_err(), "modified byte at {index}");
    }
    // A valid but differently described route is still rejected by outer AAD.
    let mut changed = header.clone();
    changed.vmk_slots[0].state = SlotState::Disabled;
    let parsed = codec::parse_header(&original).unwrap();
    let mut fake = codec::encode_header(&changed, parsed.ciphertext.len(), &parsed.outer_nonce).unwrap();
    fake.extend_from_slice(parsed.ciphertext);
    assert_eq!(open_file(&fake, &vmk).err(), Some(V02Error::AuthenticationFailed));
}

#[test]
fn malformed_lengths_versions_and_legacy_versions_fail_closed() {
    let (header, body, vmk, _, _) = specimen();
    let original = seal_file(&header, &body, &vmk).unwrap();
    for end in 0..original.len() {
        // Limit size of test while covering all header and AEAD tail truncations.
        if end > 512 && end % 41 != 0 { continue; }
        assert!(open_file(&original[..end], &vmk).is_err());
    }
    let mut junk = original.clone();
    junk.push(0);
    assert!(open_file(&junk, &vmk).is_err());
    let mut unknown_version = original.clone();
    unknown_version[4..6].copy_from_slice(&77u16.to_le_bytes());
    assert_eq!(classify_file(&unknown_version).err(), Some(V02Error::UnsupportedVersion));
    let mut extreme = original.clone();
    extreme[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(classify_file(&extreme).is_err());
    assert_eq!(classify_file(b"VLT1binary-prototype").err(), Some(V02Error::MigrationRequired));
    assert_eq!(classify_file(br#"{"version":1}"#).err(), Some(V02Error::MigrationRequired));
    assert!(classify_file(b"unrecognized").is_err());
}

#[test]
fn isolated_and_hardware_policy_restrictions_are_structural() {
    let (mut header, mut body, vmk, _, dek) = specimen();
    let e = &mut body.entries[0];
    e.mode = EntryMode::DefaultPhysical;
    e.tier = EntryTier::Isolated;
    assert!(seal_file(&header, &body, &vmk).is_err()); // stale virtual DEK slot
    body.entries[0].dek_slots[0].factors = FactorPolicy::DefaultPhysical;
    // ciphertext was bound to original virtual policy; structural check passes,
    // but trying that DEK with changed policy must fail AEAD.
    let b = seal_file(&header, &body, &vmk).unwrap();
    let opened = open_file(&b, &vmk).unwrap();
    assert_eq!(open_entry(header.vault_id, &opened.body.entries[0], &dek, header.mode).err(),
        Some(V02Error::AuthenticationFailed)); // wrong bound policy, correct original DEK
    let id = body.entries[0].id;
    body.entries[0].dek_slots.push(Slot::pending(
        SlotTarget::EntryDek, id, FactorPolicy::CodeOnly
    ));
    assert!(seal_file(&header, &body, &vmk).is_err());
    body.entries[0].dek_slots.pop();
    body.entries[0].recovery = RecoveryPolicy::StrictNone;
    body.entries[0].dek_slots.push(Slot::pending(
        SlotTarget::EntryDek, id, FactorPolicy::CodePhysical
    ));
    assert!(seal_file(&header, &body, &vmk).is_err()); // STRICT_NONE
    header.mode = VaultMode::PasswordPhysical;
    // The synthetic conversion must not retain code-only virtual bootstrap.
    header.bootstrap_slots.clear();
    header.vmk_slots = vec![
        Slot::pending(SlotTarget::Vmk, Uuid::nil(), FactorPolicy::VaultPasswordPhysical),
        Slot::pending(SlotTarget::Vmk, Uuid::nil(), FactorPolicy::CodePassword),
        Slot::pending(SlotTarget::Vmk, Uuid::nil(), FactorPolicy::CodePhysical),
    ];
    body.entries[0].dek_slots.retain(|s| !s.factors.is_recovery());
    assert!(seal_file(&header, &body, &vmk).is_ok());
    header.vmk_slots.push(Slot::pending(
        SlotTarget::Vmk, Uuid::nil(), FactorPolicy::CodeOnly
    ));
    assert!(seal_file(&header, &body, &vmk).is_err()); // no hardware code-only VMK
}

#[test]
fn successor_binds_predecessor_and_demands_revisioned_tombstone() {
    let (header, body, vmk, _, _) = specimen();
    let original = seal_file(&header, &body, &vmk).unwrap();
    let failed = prepare_successor(&original, &vmk, |body| {
        body.entries.clear(); Ok(())
    });
    assert!(failed.is_err());
    let failed = prepare_successor(&original, &vmk, |body| {
        body.entries[0].title.push('X'); Ok(())
    });
    assert!(failed.is_err());
    let successor = prepare_successor(&original, &vmk, |body| {
        let entry = &mut body.entries[0];
        entry.revision += 1;
        entry.tombstone = true;
        entry.ciphertext.clear();
        entry.dek_slots.clear();
        entry.nonce = [0u8;24];
        Ok(())
    }).unwrap();
    let opened = open_file(&successor, &vmk).unwrap();
    assert_eq!(opened.header.generation, 2);
    assert_eq!(opened.header.predecessor_hash, *blake3::hash(&original).as_bytes());
    assert_eq!(opened.body.entries[0].revision, 2);
    assert!(opened.body.entries[0].tombstone);
    assert!(prepare_successor(&successor, &vmk, |body| {
        body.entries[0].tombstone = false;
        body.entries[0].revision += 1;
        Ok(())
    }).is_err());
}

#[test]
fn strict_decoding_rejects_duplicate_metadata_ids_and_unrecognized_slots() {
    let (header, mut body, vmk, _, _) = specimen();
    let repeated = body.entries[0].clone();
    body.entries.push(repeated);
    assert!(seal_file(&header, &body, &vmk).is_err());
    body.entries.pop();
    body.vers_slots.push(Slot::pending(SlotTarget::Vers, Uuid::nil(), FactorPolicy::CodeOnly));
    body.provider_seed_slots.push(body.vers_slots[0].clone());
    assert!(seal_file(&header, &body, &vmk).is_err());
    body.provider_seed_slots.pop();
    body.vers_slots[0].state = SlotState::Verified;
    assert!(seal_file(&header, &body, &vmk).is_err()); // claims verified without AEAD envelope
    body.vers_slots.clear();
    let original = seal_file(&header, &body, &vmk).unwrap();
    let mut malformed = original.clone();
    let slot_count_index = 16 + 16 + 16 + 8 + 32 + 24 + 1;
    malformed[slot_count_index..slot_count_index+2].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(open_file(&malformed, &vmk).is_err());
}

#[test]
fn fuzz_like_mutations_never_panic_or_return_unverified_plaintext() {
    let (header, body, vmk, _, _) = specimen();
    let original = seal_file(&header, &body, &vmk).unwrap();
    for i in 0..500usize {
        let mut data = original.clone();
        let pos = i.wrapping_mul(104729) % data.len();
        data[pos] ^= ((i % 253) + 1) as u8;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| open_file(&data, &vmk)));
        assert!(outcome.is_ok(), "decode panic at {pos}");
        assert!(outcome.unwrap().is_err(), "unauthenticated mutation accepted");
    }
}

#[test]
fn authenticated_base_comparison_conflict_preserves_both_encrypted_versions() {
    let (header, body, vmk, _, _) = specimen();
    let original = seal_file(&header, &body, &vmk).unwrap();
    let next_a = prepare_successor(&original, &vmk, |body| {
        body.clients.push(ClientRecord {id: Uuid::new_v4(), public_identity: [1;32], revoked:false});
        Ok(())
    }).unwrap();
    let next_b = prepare_successor(&original, &vmk, |body| {
        body.clients.push(ClientRecord {id: Uuid::new_v4(), public_identity: [2;32], revoked:false});
        Ok(())
    }).unwrap();
    let (dir, path) = temp_file("conflict");
    fs::write(&path, &original).unwrap();
    assert_eq!(storage::commit_candidate(&path, &original, &next_a, &vmk).unwrap(),
        CommitOutcome::Committed);
    let result = storage::commit_candidate(&path, &original, &next_b, &vmk).unwrap();
    let conflict = match result {
        CommitOutcome::ConflictPreserved(p) => p,
        _ => panic!("expected preserved encrypted conflict"),
    };
    assert_eq!(fs::read(&path).unwrap(), next_a);
    assert_eq!(fs::read(&conflict).unwrap(), next_b);
    let backups = immutable_backups(&dir, &path);
    assert_eq!(backups.len(), 1);
    assert_eq!(fs::read(&backups[0]).unwrap(), original);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn storage_pre_and_post_replace_faults_and_symlink_rejection() {
    let (header, body, vmk, _, _) = specimen();
    let original = seal_file(&header, &body, &vmk).unwrap();
    let next = prepare_successor(&original, &vmk, |_| Ok(())).unwrap();
    for phase in [Phase::AfterTempSync, Phase::AfterBackupSync, Phase::BeforeReplace,
        Phase::AfterReplace, Phase::AfterParentSync] {
        let (dir, path) = temp_file("fault");
        fs::write(&path, &original).unwrap();
        let err = storage::commit_with_checkpoint(&path, &original, &next, &vmk, |p| {
            if p == phase { Err(V02Error::Invalid("injected test fault")) }
            else { Ok(()) }
        }).err();
        assert!(err.is_some());
        if matches!(phase, Phase::AfterReplace | Phase::AfterParentSync) {
            assert_eq!(fs::read(&path).unwrap(), next);
        } else {
            assert_eq!(fs::read(&path).unwrap(), original);
        }
        assert!(!vault_lock(&path).exists());
        fs::remove_dir_all(dir).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let (dir, path) = temp_file("symlink");
        let victim = dir.join("unrelated");
        fs::write(&victim, &original).unwrap();
        symlink(&victim, &path).unwrap();
        assert!(storage::commit_candidate(&path, &original, &next, &vmk).is_err());
        assert_eq!(fs::read(victim).unwrap(), original);
        fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn virtual_seed_bootstrap_is_preload_and_authenticated_not_inner_only() {
    let (mut header, body, vmk, _, _) = specimen();
    assert_eq!(header.bootstrap_slots.len(), 2);
    assert!(header.bootstrap_slots.iter().any(|s| s.factors == FactorPolicy::CodeOnly));
    let file = seal_file(&header, &body, &vmk).unwrap();
    let parsed = codec::parse_header(&file).unwrap();
    assert_eq!(parsed.header.bootstrap_slots.len(), 2);
    // The bootstrap slots are public encrypted envelopes (currently pending);
    // no virtual-provider seed is present or derived in this candidate.
    header.bootstrap_slots[0].state = SlotState::Disabled;
    let mut forged = codec::encode_header(
        &header, parsed.ciphertext.len(), &parsed.outer_nonce
    ).unwrap();
    forged.extend_from_slice(parsed.ciphertext);
    assert_eq!(open_file(&forged, &vmk).err(), Some(V02Error::AuthenticationFailed));
    header.bootstrap_slots.pop();
    assert!(seal_file(&header, &body, &vmk).is_err());
}
#[test]
fn hardware_vault_requires_both_recovery_envelope_descriptors() {
    let (mut header, body, vmk, _, _) = specimen();
    header.mode = VaultMode::PasswordPhysical;
    header.vmk_slots = vec![
        Slot::pending(SlotTarget::Vmk, Uuid::nil(), FactorPolicy::VaultPasswordPhysical),
        Slot::pending(SlotTarget::Vmk, Uuid::nil(), FactorPolicy::CodePassword),
    ];
    header.bootstrap_slots.clear();
    assert!(seal_file(&header, &body, &vmk).is_err());
    header.vmk_slots.push(Slot::pending(
        SlotTarget::Vmk, Uuid::nil(), FactorPolicy::CodePhysical
    ));
    // Structurally representable, but ALL factor states are still PENDING;
    // no provisioned/verified hardware recovery is claimed.
    assert!(seal_file(&header, &body, &vmk).is_ok());
}

#[test]
fn final_commit_revalidates_transitions_even_for_directly_sealed_candidates() {
    // prepare_successor prevents invalid transitions, but seal_file is an
    // independent public primitive: the disk writer must check again.
    let (header, body, vmk, _, _) = specimen();
    let original = seal_file(&header, &body, &vmk).unwrap();

    let raw_candidate = |previous: &[u8], edit: fn(&mut VaultBody)| {
        let opened = open_file(previous, &vmk).unwrap();
        let mut h = opened.header;
        let mut b = opened.body;
        h.generation += 1;
        h.predecessor_hash = *blake3::hash(previous).as_bytes();
        h.commit_id = Uuid::new_v4();
        b.generation = h.generation;
        b.predecessor_hash = h.predecessor_hash;
        b.commit_id = h.commit_id;
        edit(&mut b);
        seal_file(&h, &b, &vmk).unwrap()
    };
    fn remove_without_tombstone(b: &mut VaultBody) { b.entries.clear(); }
    fn mutate_without_revision(b: &mut VaultBody) {
        b.entries[0].title.push_str("-modified");
    }
    fn new_entry_with_wrong_initial_revision(b: &mut VaultBody) {
        let mut added = b.entries[0].clone();
        added.id = Uuid::new_v4();
        added.revision = 2;
        added.dek_slots = vec![Slot::pending(
            SlotTarget::EntryDek, added.id, FactorPolicy::DefaultVirtual
        )];
        b.entries.push(added);
    }
    for invalid in [
        remove_without_tombstone as fn(&mut VaultBody),
        mutate_without_revision,
        new_entry_with_wrong_initial_revision,
    ] {
        let next = raw_candidate(&original, invalid);
        let (dir, path) = temp_file("invalid-transition");
        fs::write(&path, &original).unwrap();
        assert!(storage::commit_candidate(&path, &original, &next, &vmk).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(!vault_lock(&path).exists());
        fs::remove_dir_all(dir).unwrap();
    }

    // Tombstone revival needs a real tombstone predecessor.
    let deleted = prepare_successor(&original, &vmk, |b| {
        let entry = &mut b.entries[0];
        entry.revision += 1;
        entry.tombstone = true;
        entry.ciphertext.clear();
        entry.nonce = [0; 24];
        entry.dek_slots.clear();
        Ok(())
    }).unwrap();
    let (dir, path) = temp_file("revived");
    fs::write(&path, &deleted).unwrap();
    let original_entry = body.entries[0].clone();
    let revived = {
        let opened = open_file(&deleted, &vmk).unwrap();
        let mut h = opened.header;
        let mut b = opened.body;
        h.generation += 1;
        h.predecessor_hash = *blake3::hash(&deleted).as_bytes();
        h.commit_id = Uuid::new_v4();
        b.generation = h.generation;
        b.predecessor_hash = h.predecessor_hash;
        b.commit_id = h.commit_id;
        b.entries[0] = original_entry;
        b.entries[0].revision = 3;
        seal_file(&h, &b, &vmk).unwrap()
    };
    assert!(storage::commit_candidate(&path, &deleted, &revived, &vmk).is_err());
    assert_eq!(fs::read(&path).unwrap(), deleted);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn aggregate_body_size_rejected_before_oversized_serialization() {
    // 17 individually valid 1 MiB ciphertexts exceed the 16 MiB aggregate
    // body limit. The encoder must preflight their sizes before copying.
    let (header, _, vmk, _, _) = specimen();
    let mut body = VaultBody::for_header(&header);
    for _ in 0..17 {
        let id = Uuid::new_v4();
        body.entries.push(EntryRecord {
            id, revision: 1, mode: EntryMode::DefaultVirtual,
            tier: EntryTier::Standard, recovery: RecoveryPolicy::Shared,
            tombstone: false, title: String::new(), username: String::new(),
            origin: String::new(), nonce: [17u8; 24],
            ciphertext: vec![9u8; super::model::MAX_ENTRY_BYTES],
            dek_slots: vec![Slot::pending(
                SlotTarget::EntryDek, id, FactorPolicy::DefaultVirtual
            )],
        });
    }
    assert_eq!(codec::encode_body(&body, &header).err(), Some(V02Error::TooLarge));
    assert_eq!(seal_file(&header, &body, &vmk).err(), Some(V02Error::TooLarge));
}

#[test]
fn full_basename_sidecars_do_not_overwrite_another_active_vault() {
    let (header, body, vmk, _, _) = specimen();
    let original = seal_file(&header, &body, &vmk).unwrap();
    let next = prepare_successor(&original, &vmk, |_| Ok(())).unwrap();

    let (dir, first) = temp_file("sidecar-collision");
    let second = dir.join("vault.previous"); // formerly collided with vault.v2 backup
    fs::write(&first, &original).unwrap();
    fs::write(&second, b"UNRELATED_ENCRYPTED_FILE_SENTINEL").unwrap();

    assert_eq!(storage::commit_candidate(&first, &original, &next, &vmk).unwrap(),
        CommitOutcome::Committed);
    assert_eq!(fs::read(&second).unwrap(), b"UNRELATED_ENCRYPTED_FILE_SENTINEL");
    let first_backups = immutable_backups(&dir, &first);
    assert_eq!(first_backups.len(), 1);
    assert_eq!(fs::read(&first_backups[0]).unwrap(), original);

    // vault.previous must also be a valid *independent* active vault filename.
    fs::write(&second, &original).unwrap();
    assert_eq!(storage::commit_candidate(&second, &original, &next, &vmk).unwrap(),
        CommitOutcome::Committed);
    assert_eq!(fs::read(&first).unwrap(), next);
    assert_eq!(fs::read(&second).unwrap(), next);
    let second_backups = immutable_backups(&dir, &second);
    assert_eq!(second_backups.len(), 1);
    assert_eq!(fs::read(&second_backups[0]).unwrap(), original);
    assert_ne!(first_backups[0], second_backups[0]);

    // An active path inside the sidecar namespace is never accepted.
    let illegal = dir.join("vault.v2.previous-pretend");
    fs::write(&illegal, &original).unwrap();
    assert!(storage::commit_candidate(&illegal, &original, &next, &vmk).is_err());
    assert_eq!(fs::read(&illegal).unwrap(), original);

    // A second commit preserves the earlier immutable backup; it does not
    // rename a fixed previous slot over another file.
    let newer = prepare_successor(&next, &vmk, |_| Ok(())).unwrap();
    assert_eq!(storage::commit_candidate(&first, &next, &newer, &vmk).unwrap(),
        CommitOutcome::Committed);
    let snapshots = immutable_backups(&dir, &first);
    assert_eq!(snapshots.len(), 2);
    assert!(snapshots.iter().any(|p| fs::read(p).unwrap() == original));
    assert!(snapshots.iter().any(|p| fs::read(p).unwrap() == next));
    assert_eq!(fs::read(&second).unwrap(), next);
    fs::remove_dir_all(dir).unwrap();
}
