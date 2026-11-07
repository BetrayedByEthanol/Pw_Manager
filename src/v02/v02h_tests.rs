//! V02-H Rust side of independently authored Python V3RV wire vectors.
//! Zero key operations. Both sides check byte-for-byte *untrusted* framing.
use super::*;
use sha2::{Digest, Sha256};

fn id(n:u8)->Uuid{Uuid::from_bytes([n;16])}
fn hex(bytes:&[u8])->String{
    bytes.iter().map(|n|format!("{n:02x}")).collect::<String>()
}
fn from_hex(s:&str)->Vec<u8>{
    assert_eq!(s.len()%2,0);
    s.as_bytes().chunks_exact(2).map(|x|{
        u8::from_str_radix(std::str::from_utf8(x).unwrap(),16).unwrap()
    }).collect()
}

/// Hand-written Rust specimens deliberately separate from Python's
/// independently encoded reference. This is *not* independent crypto.
fn specimen(name:&str)->UntrustedEnvelope{
    let mut x=UntrustedEnvelope{
        descriptor:Descriptor{
            vault_id:id(1),slot_id:id(2),target:SlotTarget::EntryDek,
            target_id:id(3),vault_mode:VaultMode::PasswordVirtual,
            route:FactorPolicy::CodePhysical,
            entry:Some(EntryPolicy{mode:EntryMode::DefaultPhysical,
                tier:EntryTier::Isolated,recovery:RecoveryPolicy::Independent}),
            purpose:Purpose::Recovery,
            recovery_scope:Some(RecoveryScope{kind:ScopeKind::Entry,owner:id(3)}),
            ancestor:None,
            password:None,
            provider:Provider::Physical{
                credential:b"synthetic-credential".to_vec(),
                rp_id_hash:[6;32],prf_salt:[7;32],scope:2,up:true,uv:true
            },
        },
        nonce:[12;24],ciphertext:[20;WRAPPED_KEY_CT],commitment:[30;32],
    };
    let index=match name{
        "isolated_independent"=>0,
        "standard_weaker_recovery"=>{
            x.descriptor.slot_id=id(5);
            x.descriptor.entry=Some(EntryPolicy{mode:EntryMode::DefaultPhysical,
                tier:EntryTier::Standard,recovery:RecoveryPolicy::Shared});
            x.descriptor.route=FactorPolicy::CodeOnly;
            x.descriptor.recovery_scope=Some(RecoveryScope{kind:ScopeKind::Vault,owner:id(1)});
            x.descriptor.provider=Provider::None;
            1
        },
        "virtual_vmk_normal"=>{
            x.descriptor.slot_id=id(6);
            x.descriptor.target=SlotTarget::Vmk;
            x.descriptor.target_id=Uuid::nil();
            x.descriptor.route=FactorPolicy::VaultPasswordVirtual;
            x.descriptor.entry=None;
            x.descriptor.purpose=Purpose::Normal;
            x.descriptor.recovery_scope=None;
            x.descriptor.password=Some(PasswordKdf{
                encoding:1,salt:[9;16],memory_kib:65536,passes:3,lanes:1
            });
            x.descriptor.provider=Provider::Virtual{
                id:id(7),purpose_hash:[8;32]
            };
            2
        },
        "custom_physical_normal"=>{
            x.descriptor.slot_id=id(8);
            x.descriptor.target_id=id(9);
            x.descriptor.vault_mode=VaultMode::PasswordPhysical;
            x.descriptor.route=FactorPolicy::CustomPhysical;
            x.descriptor.entry=Some(EntryPolicy{mode:EntryMode::CustomPhysical,
                tier:EntryTier::Standard,recovery:RecoveryPolicy::Shared});
            x.descriptor.purpose=Purpose::Normal;
            x.descriptor.recovery_scope=None;
            x.descriptor.password=Some(PasswordKdf{
                encoding:1,salt:[10;16],memory_kib:65536,passes:3,lanes:1
            });
            x.descriptor.provider=Provider::Physical{
                credential:b"custom-credential".to_vec(),
                rp_id_hash:[6;32],prf_salt:[11;32],scope:2,up:true,uv:true
            };
            3
        },
        "isolated_group_recovery"=>{
            x.descriptor.slot_id=id(10);
            x.descriptor.target_id=id(11);
            x.descriptor.vault_mode=VaultMode::PasswordPhysical;
            x.descriptor.entry=Some(EntryPolicy{mode:EntryMode::DefaultPhysical,
                tier:EntryTier::Isolated,recovery:RecoveryPolicy::Group});
            x.descriptor.recovery_scope=Some(RecoveryScope{kind:ScopeKind::Group,owner:id(4)});
            x.descriptor.provider=Provider::Physical{
                credential:b"group-credential".to_vec(),
                rp_id_hash:[6;32],prf_salt:[12;32],scope:2,up:true,uv:false
            };
            4
        },
        _=>panic!("unknown frozen V02-H fixture {name}"),
    };
    x.nonce=[12+index;24];
    x.ciphertext=[20+index;WRAPPED_KEY_CT];
    x.commitment=[30+index;32];
    x
}

#[test]
fn v02h_frozen_independent_python_wire_and_context_vectors_match(){
    let source=include_str!("../../tools/v02_verifier/fixtures/v02h_wire_vectors.txt");
    let mut count=0;
    for line in source.lines().filter(|line|!line.is_empty()){
        let fields=line.split('|').collect::<Vec<_>>();
        assert_eq!(fields.len(),4,"bad frozen fixture fields");
        let x=specimen(fields[0]);
        let wire=from_hex(fields[1]);
        assert_eq!(x.encode().unwrap(),wire,"Rust/Python bytes disagree: {}",fields[0]);
        let parsed=UntrustedEnvelope::decode(&wire).unwrap();
        assert_eq!(parsed,x);
        assert_eq!(hex(&Sha256::digest(x.slot_context().unwrap())),
            fields[2],"slot-context SHA differs: {}",fields[0]);
        assert_eq!(hex(&Sha256::digest(x.commitment_context().unwrap())),
            fields[3],"commitment input SHA differs: {}",fields[0]);
        assert!(crate::v02::classify_file(&wire).is_err(),"never interpret V3RV as VLY2");
        count+=1;
    }
    assert_eq!(count,5,"frozen review-only fixture coverage changed");
}

#[test]
fn v02h_deterministic_hostile_byte_mutations_are_canonical_or_rejected(){
    // No time-based randomness, no real hardware, and no hidden secret inputs.
    // A syntactically valid altered ciphertext or descriptor is STILL
    // unauthenticated and may be accepted by a *parser*.
    let base=specimen("isolated_independent").encode().unwrap();
    let mut seed:u64=0x6022_2026_1107_0015;
    for i in 0..4096 {
        seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;
        let pos=(seed as usize)%base.len();
        let bit=1u8<<((seed>>16)%8);
        let mut wire=base.clone();
        wire[pos]^=bit;
        if i%11==0 {wire.truncate(pos);}
        if i%19==0 {wire.extend_from_slice(&[1,2,3]);}
        if let Ok(decoded)=UntrustedEnvelope::decode(&wire){
            assert_eq!(decoded.encode().unwrap(),wire,
                "accepted non-canonical hostile wire iteration {i}");
            assert!(crate::v02::classify_file(&wire).is_err());
        }
    }
}
