//! V02-C reproducibility and adversarial tests for the UNAPPROVED V02-B
//! internal candidate. Cross-library KATs are synthetic; no external audit,
//! physical-device evidence or production unlock behavior is implied.
use super::*;
use std::fmt::Write as _;

const VECTORS: &str = include_str!("../../tools/v02_verifier/fixtures/v02c_kats.txt");
const ARGON2ID_KAT: &str = "cb6636e19e33f61e6317f98d09e11a5f3ca42487b2db1c39f6e63a730cada520";

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes { write!(&mut s, "{b:02x}").unwrap(); }
    s
}
fn uuid(value: &str) -> Uuid { Uuid::parse_str(value).unwrap() }

fn fixture_descriptor(case: usize) -> Descriptor {
    use FactorPolicy as F;
    let (target, vault_mode, route, entry, password, provider) = match case {
        0 => (SlotTarget::Vmk, VaultMode::PasswordPhysical, F::VaultPasswordPhysical, None, true, 2),
        1 => (SlotTarget::EntryDek, VaultMode::PasswordVirtual, F::DefaultVirtual,
            Some(EntryProtection { mode:EntryMode::DefaultVirtual, tier:EntryTier::Standard,
                recovery:RecoveryPolicy::Shared }), false, 1),
        2 => (SlotTarget::Vmk, VaultMode::PasswordVirtual, F::CodeOnly, None, false, 0),
        3 => (SlotTarget::ProviderSeed, VaultMode::PasswordVirtual,
            F::VaultPasswordVirtual, None, true, 0),
        4 => (SlotTarget::EntryDek, VaultMode::PasswordVirtual, F::CodePhysical,
            Some(EntryProtection { mode:EntryMode::DefaultPhysical, tier:EntryTier::Isolated,
                recovery:RecoveryPolicy::Shared }), false, 2),
        5 => (SlotTarget::Vmk, VaultMode::PasswordPhysical, F::CodePassword, None, true, 0),
        _ => panic!("unrecognized frozen fixture"),
    };
    let provider = match provider {
        0 => ProviderBinding::None,
        1 => ProviderBinding::Virtual {
            provider_id:uuid("55555555-5555-4555-8555-555555555555"),
            purpose_hash:[17;32],
        },
        2 => ProviderBinding::Physical {
            credential_id:b"credential-A".to_vec(),
            rp_id_hash:[7;32],
            prf_salt:[9;32],
            scope:PrfScope::EntrySlotPurpose,
            up_required:true, uv_required:true,
        },
        _ => unreachable!(),
    };
    Descriptor {
        protocol_version:PROTOCOL_CANDIDATE_VERSION,
        vault_id:uuid("11111111-1111-4111-8111-111111111111"),
        slot_id:uuid(&format!("33333333-3333-4333-8333-{:012x}", case+1)),
        target, target_id:if target==SlotTarget::EntryDek {
            uuid("22222222-2222-4222-8222-222222222222")
        } else { Uuid::nil() },
        vault_mode, route, entry,
        password:password.then_some(PasswordParameters {
            salt:[3;16], memory_kib:8192, passes:2, lanes:1,
        }),
        provider,
    }
}
fn fixture_material(case: usize) -> ([u8;32], Option<[u8;32]>, [u8;32]) {
    let (a,b,key) = match case {
        0 => (21,Some(34),99),
        1 => (42,Some(43),44),
        2 => (63,None,82),
        3 => (4,None,10),
        4 => (11,Some(12),13),
        5 => (1,Some(2),9),
        _ => unreachable!(),
    };
    ([a;32], b.map(|n| [n;32]), [key;32])
}
fn derive<'a>(d:&Descriptor, first:&'a [u8;32], second:Option<&'a [u8;32]>)
    -> Result<(Zeroizing<[u8;32]>, Zeroizing<[u8;32]>, Vec<u8>), V02Error>
{
    match second {
        Some(second) => schedule(d,Components::Combined{first,second}),
        None => schedule(d,Components::Single(first)),
    }
}
fn unwrap<'a>(env:&CandidateEnvelope, first:&'a [u8;32],
    second:Option<&'a [u8;32]>) -> Result<Zeroizing<[u8;32]>, V02Error>
{
    match second {
        Some(second) => open_candidate(env,Components::Combined{first,second}),
        None => open_candidate(env,Components::Single(first)),
    }
}
fn sealed(case:usize) -> CandidateEnvelope {
    let d=fixture_descriptor(case);
    let (first,second,secret)=fixture_material(case);
    match second.as_ref() {
        Some(s) => seal_candidate(d,Components::Combined{first:&first,second:s},&secret).unwrap(),
        None => seal_candidate(d,Components::Single(&first),&secret).unwrap(),
    }
}

#[test]
fn cross_library_frozen_transcript_hkdf_xchacha_and_hmac_known_answers() {
    // These bytes were produced with a distinct Python hashlib/hmac HKDF
    // implementation and libsodium XChaCha20-Poly1305, NOT by the Rust DUT.
    let mut checked=0;
    for (case,line) in VECTORS.lines().filter(|line|
        !line.trim().is_empty() && !line.starts_with('#')).enumerate()
    {
        let fields:Vec<_>=line.split_ascii_whitespace().collect();
        assert_eq!(fields.len(),6,"malformed frozen KAT row {case}");
        let names=["physical_vmk_normal","virtual_default_entry",
            "code_only_password_vmk","preload_seed_password",
            "password_vault_isolated_recovery","hardware_code_password_admin"];
        assert_eq!(fields[0], names[case]);
        let d=fixture_descriptor(case);
        let (first,second,secret)=fixture_material(case);
        let (wrap,mac,transcript)=derive(&d,&first,second.as_ref()).unwrap();
        assert_eq!(hex(&Sha256::digest(&transcript)),fields[1],"descriptor {case}");
        assert_eq!(hex(&*wrap),fields[2],"HKDF wrap {case}");
        assert_eq!(hex(&*mac),fields[3],"HKDF MAC {case}");
        let nonce=[case as u8+1;24]; // deterministic KAT only; NEVER production nonce
        let cipher=XChaCha20Poly1305::new(Key::from_slice(&*wrap));
        let ciphertext=cipher.encrypt(XNonce::from_slice(&nonce),
            Payload{msg:&secret,aad:&transcript}).unwrap();
        assert_eq!(hex(&ciphertext),fields[4],"XChaCha AEAD {case}");
        let tag=commitment_tag(&mac,&transcript,&nonce,&ciphertext).unwrap();
        assert_eq!(hex(&tag),fields[5],"candidate HMAC {case}");
        let env=CandidateEnvelope {
            descriptor:d, nonce, ciphertext, candidate_commitment:tag,
        };
        assert_eq!(*unwrap(&env,&first,second.as_ref()).unwrap(),secret);
        let mut altered=first;altered[0]^=1;
        assert!(unwrap(&env,&altered,second.as_ref()).is_err(),"wrong factor {case}");
        if let Some(mut other)=second {
            other[0]^=1;
            assert!(unwrap(&env,&first,Some(&other)).is_err(),"wrong PRF {case}");
        } else {
            assert!(unwrap(&env,&first,Some(&[0u8;32])).is_err(),"factor-insertion {case}");
        }
        checked+=1;
    }
    assert_eq!(checked,6,"all externally generated fixture cases must be present");
}
#[test]
fn argon2id_cross_library_kat_and_cost_preflight() {
    let p=PasswordParameters{salt:[3;16],memory_kib:8192,passes:2,lanes:1};
    assert_eq!(hex(&*password_component(b"synthetic password",&p).unwrap()),ARGON2ID_KAT);
    for bad in [0,8191,262145,u32::MAX] {
        let mut q=p.clone();q.memory_kib=bad;
        assert!(password_component(b"test",&q).is_err());
    }
    for bad in [0,1,9,u32::MAX] {
        let mut q=p.clone();q.passes=bad;
        assert!(password_component(b"test",&q).is_err());
    }
    for bad in [0,5,u32::MAX] {
        let mut q=p.clone();q.lanes=bad;
        assert!(password_component(b"test",&q).is_err());
    }
    let mut q=p.clone();q.salt=[0;16];
    assert!(password_component(b"test",&q).is_err());
    assert!(password_component(&vec![b'x';1025],&p).is_err());
}
#[test]
fn ciphertext_nonce_and_commitment_byte_mutations_are_rejected() {
    let a=sealed(0);
    let (first,second,_)=fixture_material(0);
    for pos in 0..a.ciphertext.len() {
        let mut corrupted=CandidateEnvelope {
            descriptor:a.descriptor.clone(), nonce:a.nonce,
            ciphertext:a.ciphertext.clone(),
            candidate_commitment:a.candidate_commitment,
        };
        corrupted.ciphertext[pos]^=1;
        assert!(unwrap(&corrupted,&first,second.as_ref()).is_err(),
            "ciphertext altered at {pos}");
    }
    for pos in 0..24 {
        let mut corrupted=CandidateEnvelope {
            descriptor:a.descriptor.clone(), nonce:a.nonce,
            ciphertext:a.ciphertext.clone(),
            candidate_commitment:a.candidate_commitment,
        };
        corrupted.nonce[pos]^=1;
        assert!(unwrap(&corrupted,&first,second.as_ref()).is_err(),
            "nonce altered at {pos}");
    }
    for pos in 0..32 {
        let mut corrupted=CandidateEnvelope {
            descriptor:a.descriptor.clone(), nonce:a.nonce,
            ciphertext:a.ciphertext.clone(),
            candidate_commitment:a.candidate_commitment,
        };
        corrupted.candidate_commitment[pos]^=1;
        assert!(unwrap(&corrupted,&first,second.as_ref()).is_err(),
            "HMAC altered at {pos}");
    }
    let mut corrupted=a;
    corrupted.ciphertext.pop();
    assert!(unwrap(&corrupted,&first,second.as_ref()).is_err());
}
#[test]
fn changing_each_hardware_kdf_and_scope_field_never_opens_the_original_slot() {
    let a=sealed(0);
    let (first,second,_)=fixture_material(0);
    let mut variants=Vec::new();
    let mut d=a.descriptor.clone();d.vault_id=Uuid::new_v4();variants.push(d);
    let mut d=a.descriptor.clone();d.slot_id=Uuid::new_v4();variants.push(d);
    let mut d=a.descriptor.clone();d.vault_mode=VaultMode::PasswordVirtual;variants.push(d);
    let mut d=a.descriptor.clone();d.target=SlotTarget::Vers;variants.push(d);
    let mut d=a.descriptor.clone();d.route=FactorPolicy::CodePhysical;variants.push(d);
    let mut d=a.descriptor.clone();d.protocol_version+=1;variants.push(d);
    let mut d=a.descriptor.clone();d.password.as_mut().unwrap().salt[0]^=1;variants.push(d);
    let mut d=a.descriptor.clone();d.password.as_mut().unwrap().memory_kib+=1024;variants.push(d);
    let mut d=a.descriptor.clone();d.password.as_mut().unwrap().passes+=1;variants.push(d);
    let mut d=a.descriptor.clone();d.password.as_mut().unwrap().lanes+=1;variants.push(d);
    let mut d=a.descriptor.clone();d.password=None;variants.push(d);
    let mut d=a.descriptor.clone();
    if let ProviderBinding::Physical{ref mut credential_id,..}=d.provider {
        credential_id[0]^=1;
    };variants.push(d);
    let mut d=a.descriptor.clone();
    if let ProviderBinding::Physical{ref mut rp_id_hash,..}=d.provider {rp_id_hash[0]^=1;};
    variants.push(d);
    let mut d=a.descriptor.clone();
    if let ProviderBinding::Physical{ref mut prf_salt,..}=d.provider {prf_salt[0]^=1;};
    variants.push(d);
    let mut d=a.descriptor.clone();
    if let ProviderBinding::Physical{ref mut scope,..}=d.provider {
        *scope=PrfScope::VaultCredentialPurpose;
    };variants.push(d);
    let mut d=a.descriptor.clone();
    if let ProviderBinding::Physical{ref mut uv_required,..}=d.provider {
        *uv_required=false;
    };variants.push(d);
    let mut d=a.descriptor.clone();
    if let ProviderBinding::Physical{ref mut up_required,..}=d.provider {
        *up_required=false;
    };variants.push(d);
    let mut d=a.descriptor.clone();d.provider=ProviderBinding::None;variants.push(d);
    for (i, descriptor) in variants.into_iter().enumerate() {
        let candidate=CandidateEnvelope {
            descriptor,nonce:a.nonce,ciphertext:a.ciphertext.clone(),
            candidate_commitment:a.candidate_commitment,
        };
        assert!(unwrap(&candidate,&first,second.as_ref()).is_err(),
            "altered binding {i} accepted");
    }
}
#[test]
fn entry_policy_binding_and_cross_slot_reuse_rejected() {
    let original=sealed(1);
    let (first,second,_)=fixture_material(1);
    let mut altered=original.descriptor.clone();
    altered.target_id=Uuid::new_v4();
    let reject=CandidateEnvelope { descriptor:altered,nonce:original.nonce,
        ciphertext:original.ciphertext.clone(),
        candidate_commitment:original.candidate_commitment };
    assert!(unwrap(&reject,&first,second.as_ref()).is_err());
    let mut altered=original.descriptor.clone();
    altered.entry.as_mut().unwrap().tier=EntryTier::Isolated;
    let reject=CandidateEnvelope { descriptor:altered,nonce:original.nonce,
        ciphertext:original.ciphertext.clone(),
        candidate_commitment:original.candidate_commitment };
    assert!(unwrap(&reject,&first,second.as_ref()).is_err());
    let mut altered=original.descriptor.clone();
    altered.entry.as_mut().unwrap().recovery=RecoveryPolicy::Independent;
    let reject=CandidateEnvelope { descriptor:altered,nonce:original.nonce,
        ciphertext:original.ciphertext.clone(),
        candidate_commitment:original.candidate_commitment };
    assert!(unwrap(&reject,&first,second.as_ref()).is_err());
    let mut altered=original.descriptor.clone();
    if let ProviderBinding::Virtual{ref mut purpose_hash,..}=altered.provider {
        purpose_hash[0]^=1;
    }
    let reject=CandidateEnvelope { descriptor:altered,nonce:original.nonce,
        ciphertext:original.ciphertext.clone(),
        candidate_commitment:original.candidate_commitment };
    assert!(unwrap(&reject,&first,second.as_ref()).is_err());
    let mut altered=original.descriptor.clone();
    if let ProviderBinding::Virtual{ref mut provider_id,..}=altered.provider {
        *provider_id=Uuid::new_v4();
    }
    let reject=CandidateEnvelope { descriptor:altered,nonce:original.nonce,
        ciphertext:original.ciphertext.clone(),
        candidate_commitment:original.candidate_commitment };
    assert!(unwrap(&reject,&first,second.as_ref()).is_err());
    let alternate=sealed(1); // second valid envelope but different random nonce
    let crossed=CandidateEnvelope {
        descriptor:original.descriptor,nonce:alternate.nonce,
        ciphertext:original.ciphertext,
        candidate_commitment:alternate.candidate_commitment,
    };
    assert!(unwrap(&crossed,&first,second.as_ref()).is_err());
}
