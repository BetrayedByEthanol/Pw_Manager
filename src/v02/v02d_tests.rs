//! V02-D review gap regression tests. Security conclusions require an
//! independent OPEN-01/OPEN-15 review; passing synthetic tests is NOT approval.
use super::*;

fn descriptor(vault_mode: VaultMode, target: SlotTarget, route: FactorPolicy) -> Descriptor {
    use FactorPolicy as F;
    let physical = matches!(route, F::VaultPasswordPhysical | F::DefaultPhysical
        | F::CustomPhysical | F::CodePhysical);
    let virtual_route = matches!(route, F::VaultPasswordVirtual | F::DefaultVirtual
        | F::CustomVirtual)
        && !(target == SlotTarget::ProviderSeed && vault_mode == VaultMode::PasswordVirtual);
    let provider = if physical {
        ProviderBinding::Physical {
            credential_id: b"fictional-review-token".to_vec(),
            rp_id_hash: [12;32], prf_salt:[13;32],
            scope:PrfScope::EntrySlotPurpose, up_required:true, uv_required:true,
        }
    } else if virtual_route {
        ProviderBinding::Virtual {
            provider_id:Uuid::new_v4(), purpose_hash:[15;32],
        }
    } else { ProviderBinding::None };
    let mode = match route {
        F::DefaultPhysical | F::CodePhysical => EntryMode::DefaultPhysical,
        F::CustomPhysical => EntryMode::CustomPhysical,
        F::CustomVirtual => EntryMode::CustomVirtual,
        _ => EntryMode::DefaultVirtual,
    };
    let entry = (target == SlotTarget::EntryDek).then_some(EntryProtection {
        mode, tier:EntryTier::Standard, recovery:RecoveryPolicy::Shared,
    });
    Descriptor {
        protocol_version:PROTOCOL_CANDIDATE_VERSION,
        vault_id:Uuid::new_v4(), slot_id:Uuid::new_v4(),
        target, target_id:if target==SlotTarget::EntryDek {
            Uuid::new_v4()
        } else {Uuid::nil()},
        vault_mode, route, entry, password:matches!(route,
            F::VaultPasswordPhysical | F::VaultPasswordVirtual | F::CodePassword
            | F::CustomVirtual | F::CustomPhysical)
            .then(|| PasswordParameters {
                salt:[9;16], memory_kib:8192, passes:2, lanes:1,
            }),
        provider,
    }
}
fn test_factors<'a>(single:bool, a:&'a [u8;32], b:&'a [u8;32]) -> Components<'a> {
    if single {Components::Single(a)}
    else {Components::Combined{first:a,second:b}}
}

#[test]
fn candidate_route_matrix_is_explicit_and_factor_count_is_not_substitutable() {
    use FactorPolicy as F;
    let cases = [
        (VaultMode::PasswordVirtual,SlotTarget::Vmk,F::VaultPasswordVirtual,false),
        (VaultMode::PasswordPhysical,SlotTarget::Vmk,F::VaultPasswordPhysical,false),
        (VaultMode::PasswordVirtual,SlotTarget::Vmk,F::CodeOnly,true),
        (VaultMode::PasswordPhysical,SlotTarget::Vmk,F::CodePassword,false),
        (VaultMode::PasswordPhysical,SlotTarget::Vmk,F::CodePhysical,false),
        (VaultMode::PasswordVirtual,SlotTarget::ProviderSeed,F::VaultPasswordVirtual,true),
        (VaultMode::PasswordVirtual,SlotTarget::ProviderSeed,F::CodeOnly,true),
        (VaultMode::PasswordVirtual,SlotTarget::EntryDek,F::DefaultVirtual,false),
        (VaultMode::PasswordPhysical,SlotTarget::EntryDek,F::DefaultPhysical,false),
        (VaultMode::PasswordVirtual,SlotTarget::EntryDek,F::CustomPhysical,false),
        (VaultMode::PasswordVirtual,SlotTarget::EntryDek,F::CodePhysical,false),
    ];
    let a=[0x18;32];let b=[0x29;32];let secret=[0x42;32];
    for (i, (mode,target,route,single)) in cases.into_iter().enumerate() {
        let d=descriptor(mode,target,route);
        assert!(d.validate().is_ok(),"valid candidate route {i}");
        let env=seal_candidate(d,test_factors(single,&a,&b),&secret).unwrap();
        assert_eq!(*open_candidate(&env,test_factors(single,&a,&b)).unwrap(),secret);
        assert!(open_candidate(&env,test_factors(!single,&a,&b)).is_err(),
            "wrong factor count accepted for route {i}");
        assert!(open_candidate(&env,test_factors(single,&[0x19;32],&b)).is_err(),
            "wrong first component accepted for route {i}");
        if !single {
            assert!(open_candidate(&env,test_factors(false,&b,&a)).is_err(),
                "swapped components accepted for route {i}");
        }
    }
}
#[test]
fn invalid_route_matrix_cannot_be_sealed_with_synthetic_inputs() {
    use FactorPolicy as F;
    let invalid = [
        (VaultMode::PasswordPhysical,SlotTarget::Vmk,F::CodeOnly),
        (VaultMode::PasswordPhysical,SlotTarget::ProviderSeed,F::CodeOnly),
        (VaultMode::PasswordVirtual,SlotTarget::Vmk,F::CodePhysical),
        (VaultMode::PasswordVirtual,SlotTarget::Vers,F::CodePassword),
        (VaultMode::PasswordPhysical,SlotTarget::Vers,F::DefaultPhysical),
        (VaultMode::PasswordPhysical,SlotTarget::EntryDek,F::VaultPasswordPhysical),
        (VaultMode::PasswordVirtual,SlotTarget::EntryDek,F::VaultPasswordVirtual),
    ];
    let a=[1;32];let b=[2;32];
    for (i,(mode,target,route)) in invalid.into_iter().enumerate() {
        let d=descriptor(mode,target,route);
        assert!(d.validate().is_err(),"forbidden route {i} validated");
        assert!(seal_candidate(d,test_factors(false,&a,&b),&[3;32]).is_err(),
            "forbidden route {i} sealed");
    }
    let mut isolated=descriptor(VaultMode::PasswordVirtual,SlotTarget::EntryDek,F::DefaultVirtual);
    isolated.entry.as_mut().unwrap().tier=EntryTier::Isolated;
    assert!(isolated.validate().is_err(),"software Isolated normal forbidden");

    let mut strict=descriptor(VaultMode::PasswordVirtual,SlotTarget::EntryDek,F::CodePhysical);
    strict.entry.as_mut().unwrap().tier=EntryTier::Isolated;
    strict.entry.as_mut().unwrap().recovery=RecoveryPolicy::StrictNone;
    assert!(strict.validate().is_err(),"STRICT_NONE Isolated recovery forbidden");

    let mut no_device=descriptor(VaultMode::PasswordPhysical,SlotTarget::EntryDek,F::CodePhysical);
    no_device.entry.as_mut().unwrap().tier=EntryTier::Isolated;
    no_device.provider=ProviderBinding::None;
    assert!(no_device.validate().is_err(),"missing physical binding");
}
#[test]
fn key_schedule_domains_separate_slots_targets_and_recovery_from_normal() {
    use FactorPolicy as F;
    let a=[0x31;32];let b=[0x44;32];
    let normal=descriptor(VaultMode::PasswordPhysical,SlotTarget::Vmk,F::VaultPasswordPhysical);
    let (normal_key,normal_mac,_)=schedule(&normal,test_factors(false,&a,&b)).unwrap();
    assert_ne!(*normal_key,*normal_mac,"KEK and MAC key share material");
    let mut slot=normal.clone();slot.slot_id=Uuid::new_v4();
    let mut vault=normal.clone();vault.vault_id=Uuid::new_v4();
    let mut vers=normal.clone();vers.target=SlotTarget::Vers;
    let mut recovery=descriptor(VaultMode::PasswordPhysical,SlotTarget::Vmk,F::CodePhysical);
    recovery.vault_id=normal.vault_id;recovery.slot_id=normal.slot_id;
    let mut components=vec![*normal_key];
    for d in [&slot,&vault,&vers,&recovery] {
        assert!(d.validate().is_ok());
        let (k,m,_)=schedule(d,test_factors(false,&a,&b)).unwrap();
        assert_ne!(*k,*normal_key);
        assert_ne!(*m,*normal_mac);
        assert!(!components.contains(&*k));
        components.push(*k);
    }
    // Root and bootstrap keys are cryptographically distinct even if the
    // *same* synthetic recovery code is handed to both routes.
    let vmk=descriptor(VaultMode::PasswordVirtual,SlotTarget::Vmk,F::CodeOnly);
    let mut seed=vmk.clone();seed.target=SlotTarget::ProviderSeed;
    let (vmk_key,_,_)=schedule(&vmk,test_factors(true,&a,&b)).unwrap();
    let (seed_key,_,_)=schedule(&seed,test_factors(true,&a,&b)).unwrap();
    assert_ne!(*vmk_key,*seed_key);
}
#[test]
fn physical_descriptor_is_not_an_assertion_or_a_fresh_device_proof() {
    // This test documents an UNRESOLVED security gap, not a passing hardware
    // guarantee: arbitrary caller-supplied 32-byte bytestrings can unwrap the
    // internal candidate without a FIDO2 assertion or user verification.
    // No production path may invoke these primitives until OPEN-15 closes.
    let d=descriptor(VaultMode::PasswordPhysical,SlotTarget::Vmk,
        FactorPolicy::VaultPasswordPhysical);
    let a=[0x65;32];let fake_prf=[0x9c;32];let secret=[0x28;32];
    let env=seal_candidate(d,Components::Combined{first:&a,second:&fake_prf},&secret).unwrap();
    assert_eq!(*open_candidate(&env,
        Components::Combined{first:&a,second:&fake_prf}).unwrap(),secret);
}
