//! V02-E pre-approval regression suite. Runs in the private V02-B test
//! harness; never asserts real hardware provenance, OPEN-01 or OPEN-15 approval.
use super::*;
use crate::v02::{model::route_is_allowed, EntryRecord, Slot};

fn fake_descriptor(mode: VaultMode, target: SlotTarget, route: FactorPolicy,
    entry: Option<(EntryMode, EntryTier, RecoveryPolicy)>) -> Descriptor
{
    let physical = matches!(route, FactorPolicy::VaultPasswordPhysical
        | FactorPolicy::DefaultPhysical | FactorPolicy::CustomPhysical | FactorPolicy::CodePhysical);
    let password = matches!(route, FactorPolicy::VaultPasswordVirtual
        | FactorPolicy::VaultPasswordPhysical | FactorPolicy::CustomVirtual
        | FactorPolicy::CustomPhysical | FactorPolicy::CodePassword);
    let virtual_route = matches!(route, FactorPolicy::VaultPasswordVirtual
        | FactorPolicy::DefaultVirtual | FactorPolicy::CustomVirtual)
        && !(target == SlotTarget::ProviderSeed && mode == VaultMode::PasswordVirtual
            && route == FactorPolicy::VaultPasswordVirtual);
    let provider = if physical {
        ProviderBinding::Physical {
            credential_id: b"synthetic-credential".to_vec(), rp_id_hash:[3;32],
            prf_salt:[4;32], scope: PrfScope::EntrySlotPurpose,
            up_required:true, uv_required:true,
        }
    } else if virtual_route {
        ProviderBinding::Virtual { provider_id:Uuid::new_v4(), purpose_hash:[7;32] }
    } else { ProviderBinding::None };
    Descriptor {
        protocol_version: PROTOCOL_CANDIDATE_VERSION, vault_id:Uuid::new_v4(),
        slot_id:Uuid::new_v4(), target,
        target_id:if target == SlotTarget::EntryDek { Uuid::new_v4() } else {Uuid::nil()},
        vault_mode:mode, route,
        entry:entry.map(|(mode,tier,recovery)| EntryProtection {mode,tier,recovery}),
        password:password.then_some(PasswordParameters{
            salt:[9;16],memory_kib:8192,passes:2,lanes:1,
        }),
        provider,
    }
}
fn fake_entry(d:&Descriptor) -> EntryRecord {
    let e=d.entry.expect("entry policy");
    EntryRecord {
        id:d.target_id, revision:1, mode:e.mode, tier:e.tier, recovery:e.recovery,
        tombstone:false, title:"synthetic-title".to_string(),
        username:"synthetic-username".to_string(),
        origin:"https://example.test".to_string(), nonce:[6;24],
        ciphertext:vec![2;32],
        dek_slots:vec![Slot::pending(SlotTarget::EntryDek,d.target_id,d.route)],
    }
}
#[test]
fn all_model_and_descriptor_route_permutations_agree() {
    let modes=[VaultMode::PasswordVirtual,VaultMode::PasswordPhysical];
    let roots=[SlotTarget::Vmk,SlotTarget::Vers,SlotTarget::ProviderSeed];
    let factors=[
        FactorPolicy::VaultPasswordVirtual,FactorPolicy::VaultPasswordPhysical,
        FactorPolicy::CodeOnly,FactorPolicy::CodePassword,FactorPolicy::CodePhysical,
        FactorPolicy::DefaultVirtual,FactorPolicy::DefaultPhysical,
        FactorPolicy::CustomVirtual,FactorPolicy::CustomPhysical,
    ];
    let entry_modes=[EntryMode::DefaultVirtual,EntryMode::DefaultPhysical,
        EntryMode::CustomVirtual,EntryMode::CustomPhysical];
    let tiers=[EntryTier::Standard,EntryTier::Isolated];
    let recoveries=[RecoveryPolicy::Shared,RecoveryPolicy::Group,
        RecoveryPolicy::Independent,RecoveryPolicy::StrictNone];
    let mut checked=0;
    for mode in modes {
        for route in factors {
            for target in roots {
                let d=fake_descriptor(mode,target,route,None);
                let expected=route_is_allowed(mode,target,route,None);
                let model=Slot::pending(target,Uuid::nil(),route).validate(mode).is_ok();
                assert_eq!(model,expected,"VLY2 root model {mode:?}/{target:?}/{route:?}");
                assert_eq!(d.validate().is_ok(),expected,
                    "key-slot descriptor {mode:?}/{target:?}/{route:?}");
                checked+=1;
            }
            for em in entry_modes {
                for tier in tiers {
                    for recovery in recoveries {
                        let policy=(em,tier,recovery);
                        let d=fake_descriptor(mode,SlotTarget::EntryDek,route,Some(policy));
                        let expected=route_is_allowed(mode,SlotTarget::EntryDek,route,Some(policy));
                        let model=fake_entry(&d).validate(mode).is_ok();
                        assert_eq!(model,expected,
                            "VLY2 DEK {mode:?}/{route:?}/{em:?}/{tier:?}/{recovery:?}");
                        assert_eq!(d.validate().is_ok(),expected,
                            "key-slot DEK {mode:?}/{route:?}/{em:?}/{tier:?}/{recovery:?}");
                        checked+=1;
                    }
                }
            }
        }
    }
    assert_eq!(checked,2*9*(3+4*2*4));
}
#[test]
fn f1_weaker_standard_recovery_is_explicitly_not_yet_owner_approved() {
    // Preserve the v0.4.5 structural allowance, but DO NOT count the
    // following candidate round trips as owner authorization. V04 must
    // require separate consent/assurance report before creating such slots.
    for em in [EntryMode::DefaultPhysical,EntryMode::CustomPhysical,
        EntryMode::CustomVirtual]
    {
        let d=fake_descriptor(VaultMode::PasswordVirtual,SlotTarget::EntryDek,
            FactorPolicy::CodeOnly, Some((em,EntryTier::Standard,RecoveryPolicy::Shared)));
        assert!(d.validate().is_ok());
        let code=[7u8;32];
        let wrapped=seal_candidate(d,Components::Single(&code), &[9u8;32]).unwrap();
        assert_eq!(*open_candidate(&wrapped,Components::Single(&code)).unwrap(),[9u8;32]);
    }
    let isolated=fake_descriptor(VaultMode::PasswordVirtual,SlotTarget::EntryDek,
        FactorPolicy::CodeOnly,Some((EntryMode::DefaultPhysical,EntryTier::Isolated,
            RecoveryPolicy::Shared)));
    assert!(isolated.validate().is_err());
}
#[test]
fn f3_f4_hardware_scope_and_uv_remain_unverified_provenance() {
    // These two results intentionally document OPEN-15 gaps, not accepted
    // runtime guarantees. A declared scope/UV bit is not verified FIDO2.
    let mut d=fake_descriptor(VaultMode::PasswordPhysical,SlotTarget::EntryDek,
        FactorPolicy::DefaultPhysical,Some((EntryMode::DefaultPhysical,
            EntryTier::Isolated,RecoveryPolicy::StrictNone)));
    assert!(d.validate().is_ok());
    if let ProviderBinding::Physical {uv_required,..}=&mut d.provider {
        *uv_required=false;
    }
    assert!(d.validate().is_ok(),"UV policy is still OPEN-15, not universally true");
    let other=fake_descriptor(VaultMode::PasswordPhysical,SlotTarget::EntryDek,
        FactorPolicy::DefaultPhysical,Some((EntryMode::DefaultPhysical,
            EntryTier::Isolated,RecoveryPolicy::StrictNone)));
    let (ProviderBinding::Physical{prf_salt:s,..},
         ProviderBinding::Physical{prf_salt:o,..})=(&d.provider,&other.provider)
        else {panic!("not physical")};
    assert_eq!(s,o,"free candidate salt is not yet enforced to be unique");
}
#[test]
fn future_version_binds_origin_username_and_title_without_reinterpreting_vly2() {
    let d=fake_descriptor(VaultMode::PasswordVirtual,SlotTarget::EntryDek,
        FactorPolicy::DefaultVirtual, Some((EntryMode::DefaultVirtual,
            EntryTier::Standard,RecoveryPolicy::Shared)));
    let record=fake_entry(&d);
    let vault=d.vault_id;
    let current=crate::v02::entry_aad(vault,&record);
    let future=crate::v02::entry_binding_candidate::entry_aad_vnext(vault,&record).unwrap();
    assert_ne!(current,future,"a new AAD domain/version is required");
    // This fixed synthetic nonce exists ONLY for the isolated test; no active
    // writer uses it, and vNext has no supported persisted wire format.
    let key=[0x31u8;32];let nonce=[8u8;24];
    let cipher=XChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext=cipher.encrypt(XNonce::from_slice(&nonce),
        Payload{msg:b"synthetic-secret",aad:&future}).unwrap();
    let try_open=|r:&EntryRecord,vid:Uuid| {
        let aad=crate::v02::entry_binding_candidate::entry_aad_vnext(vid,r).unwrap();
        cipher.decrypt(XNonce::from_slice(&nonce),Payload{msg:&ciphertext,aad:&aad})
    };
    assert_eq!(try_open(&record,vault).unwrap(), b"synthetic-secret");
    for which in 0..7 {
        let mut altered=record.clone();let mut vid=vault;
        match which {
            0=>altered.origin="https://attacker.test".to_string(),
            1=>altered.username="substituted-user".to_string(),
            2=>altered.title="substituted-title".to_string(),
            3=>altered.revision+=1,
            4=>altered.id=Uuid::new_v4(),
            5=>altered.mode=EntryMode::DefaultPhysical,
            _=>vid=Uuid::new_v4(),
        }
        assert!(try_open(&altered,vid).is_err(),"vNext metadata mutation {which}");
        if which==0 {
            // Existing VLY2 currently trusts VMK metadata, but lacks a
            // separate entry-DEK origin binding. No silent retrofit is safe.
            assert_eq!(crate::v02::entry_aad(vault,&altered),current);
        }
    }
    let mut too_large=record.clone();
    too_large.origin="x".repeat(4097);
    assert!(crate::v02::entry_binding_candidate::entry_aad_vnext(vault,&too_large).is_err());
}
