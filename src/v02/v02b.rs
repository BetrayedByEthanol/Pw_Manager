//! V02-B *experimental*, internal-only factor/slot crypto protocol prototype.
//!
//! This module is intentionally NOT linked to VLY2 Slot or a daemon/CLI. Inputs
//! are 32-byte test components; there is no hardware attestation, owner approval,
//! prompt, recovery-code collection or VERIFIED transition. OPEN-01 and OPEN-15
//! independent review MUST precede production use and final wire decisions.
//!
//! A draft HMAC over AEAD ciphertext is a candidate key-binding check, NOT a
//! cryptographic proof of a committing-AEAD construction.
#![allow(dead_code)]

use super::{EntryMode, EntryTier, FactorPolicy, RecoveryPolicy, SlotTarget, V02Error, VaultMode};
use argon2::{Algorithm, Argon2, Params, Version};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"Vaulty/V02-B/REVIEW-ONLY/slot/v1";
const MAX_DESCRIPTOR: usize = 1024;
pub(crate) const PROTOCOL_CANDIDATE_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PasswordParameters {
    pub salt: [u8; 16],
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
}
impl PasswordParameters {
    /// Explicit, bounded review/test configuration, NOT a production default.
    pub(crate) fn validate(&self) -> Result<(), V02Error> {
        if self.salt == [0; 16]
            || !(8192..=262144).contains(&self.memory_kib)
            || !(2..=8).contains(&self.passes)
            || !(1..=4).contains(&self.lanes)
            || self.memory_kib < 8 * self.lanes
        {
            return Err(V02Error::Invalid("candidate password KDF parameters"));
        }
        Ok(())
    }
}

/// Argon2id v0x13 pre-derivation for candidate tests; caller owns and wipes
/// the original password bytes. This function does NOT authenticate the user.
pub(crate) fn password_component(
    password: &[u8], cfg: &PasswordParameters,
) -> Result<Zeroizing<[u8; 32]>, V02Error> {
    cfg.validate()?;
    if password.is_empty() || password.len() > 1024 {
        return Err(V02Error::Invalid("candidate password input length"));
    }
    let params = Params::new(cfg.memory_kib, cfg.passes, cfg.lanes, Some(32))
        .map_err(|_| V02Error::Invalid("candidate argon2 parameters"))?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, &cfg.salt, &mut *out)
        .map_err(|_| V02Error::AuthenticationFailed)?;
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrfScope { VaultCredentialPurpose, EntrySlotPurpose }

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProviderBinding {
    None,
    Virtual {
        provider_id: Uuid,
        purpose_hash: [u8; 32],
    },
    Physical {
        credential_id: Vec<u8>,
        rp_id_hash: [u8; 32],
        prf_salt: [u8; 32],
        scope: PrfScope,
        up_required: bool,
        uv_required: bool,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EntryProtection {
    pub mode: EntryMode,
    pub tier: EntryTier,
    pub recovery: RecoveryPolicy,
}

/// Public-like *untrusted* route parameters. All fields bind into the
/// candidate authenticated transcript, but do not prove their own validity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Descriptor {
    pub protocol_version: u16,
    pub vault_id: Uuid,
    pub slot_id: Uuid,
    pub target: SlotTarget,
    pub target_id: Uuid,
    pub vault_mode: VaultMode,
    pub route: FactorPolicy,
    pub entry: Option<EntryProtection>,
    pub password: Option<PasswordParameters>,
    pub provider: ProviderBinding,
}
impl Descriptor {
    fn is_recovery(&self) -> bool {
        matches!(self.route, FactorPolicy::CodeOnly | FactorPolicy::CodePassword | FactorPolicy::CodePhysical)
    }
    fn requires_password(&self) -> bool {
        matches!(self.route, FactorPolicy::VaultPasswordVirtual | FactorPolicy::VaultPasswordPhysical
            | FactorPolicy::CodePassword | FactorPolicy::CustomVirtual | FactorPolicy::CustomPhysical)
    }
    fn bootstrap_single_password(&self) -> bool {
        self.target == SlotTarget::ProviderSeed
            && self.vault_mode == VaultMode::PasswordVirtual
            && self.route == FactorPolicy::VaultPasswordVirtual
    }
    fn single_component(&self) -> bool {
        self.route == FactorPolicy::CodeOnly || self.bootstrap_single_password()
    }
    fn validate(&self) -> Result<(), V02Error> {
        use FactorPolicy as F;
        if self.protocol_version != PROTOCOL_CANDIDATE_VERSION {
            return Err(V02Error::UnsupportedVersion);
        }
        if self.vault_id.is_nil() || self.slot_id.is_nil()
            || (self.target == SlotTarget::EntryDek) != !self.target_id.is_nil() {
            return Err(V02Error::Invalid("candidate slot target identity"));
        }
        if self.requires_password() != self.password.is_some() {
            return Err(V02Error::Invalid("candidate password parameters absent or unexpected"));
        }
        if let Some(p) = &self.password { p.validate()?; }
        if self.vault_mode == VaultMode::PasswordPhysical && self.route == F::CodeOnly {
            return Err(V02Error::Invalid("hardware-vault code-only route forbidden"));
        }
        match self.target {
            SlotTarget::Vmk | SlotTarget::Vers | SlotTarget::ProviderSeed => {
                if self.entry.is_some() {
                    return Err(V02Error::Invalid("entry policy on non-entry target"));
                }
                let permitted = match self.vault_mode {
                    VaultMode::PasswordVirtual =>
                        matches!(self.route, F::VaultPasswordVirtual | F::CodeOnly),
                    VaultMode::PasswordPhysical =>
                        matches!(self.route, F::VaultPasswordPhysical | F::CodePassword | F::CodePhysical),
                };
                if !permitted {
                    return Err(V02Error::Invalid("candidate root recovery route"));
                }
            }
            SlotTarget::EntryDek => {
                let e = self.entry.ok_or(V02Error::Invalid("missing entry policy"))?;
                let normal = match e.mode {
                    EntryMode::DefaultVirtual => F::DefaultVirtual,
                    EntryMode::DefaultPhysical => F::DefaultPhysical,
                    EntryMode::CustomVirtual => F::CustomVirtual,
                    EntryMode::CustomPhysical => F::CustomPhysical,
                };
                if !self.is_recovery() && self.route != normal {
                    return Err(V02Error::Invalid("entry normal route mismatch"));
                }
                if self.is_recovery() && e.recovery == RecoveryPolicy::StrictNone {
                    return Err(V02Error::Invalid("STRICT_NONE forbids recovery"));
                }
                if e.tier == EntryTier::Isolated {
                    if !matches!(e.mode, EntryMode::DefaultPhysical | EntryMode::CustomPhysical)
                        || !matches!(self.route, F::DefaultPhysical | F::CustomPhysical | F::CodePhysical) {
                        return Err(V02Error::Invalid("ISOLATED needs hardware on all DEK routes"));
                    }
                }
                if self.is_recovery() {
                    let allowed = match self.vault_mode {
                        // Password-only metadata uses code-only recovery; an
                        // ISOLATED entry in that same vault may still have a
                        // separately provisioned code+physical DEK route.
                        VaultMode::PasswordVirtual =>
                            matches!(self.route, F::CodeOnly | F::CodePhysical),
                        VaultMode::PasswordPhysical =>
                            matches!(self.route, F::CodePassword | F::CodePhysical),
                    };
                    if !allowed {
                        return Err(V02Error::Invalid("unapproved entry recovery route"));
                    }
                }
            }
        }
        let physical = matches!(self.route, F::VaultPasswordPhysical | F::CodePhysical
            | F::DefaultPhysical | F::CustomPhysical);
        let virtual_route = matches!(self.route, F::VaultPasswordVirtual
            | F::DefaultVirtual | F::CustomVirtual) && !self.bootstrap_single_password();
        match &self.provider {
            ProviderBinding::None if physical || virtual_route =>
                return Err(V02Error::Invalid("missing required provider binding")),
            ProviderBinding::None => {},
            ProviderBinding::Virtual { provider_id, purpose_hash } if virtual_route => {
                if provider_id.is_nil() || *purpose_hash == [0;32] {
                    return Err(V02Error::Invalid("invalid virtual provider scope"));
                }
            }
            ProviderBinding::Physical {
                credential_id, rp_id_hash, prf_salt, scope, up_required, ..
            } if physical => {
                if credential_id.is_empty() || credential_id.len() > 128
                    || *rp_id_hash == [0;32] || *prf_salt == [0;32] || !*up_required {
                    return Err(V02Error::Invalid("invalid physical provider scope"));
                }
                if self.entry.is_some_and(|e| e.tier == EntryTier::Isolated)
                    && *scope != PrfScope::EntrySlotPurpose {
                    return Err(V02Error::Invalid("isolated slot requires entry-scoped PRF"));
                }
            }
            _ => return Err(V02Error::Invalid("provider and factor mismatch")),
        }
        Ok(())
    }
    fn transcript(&self) -> Result<Vec<u8>, V02Error> {
        self.validate()?;
        let mut out = Vec::with_capacity(400);
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(&self.protocol_version.to_be_bytes());
        out.extend_from_slice(self.vault_id.as_bytes());
        out.extend_from_slice(self.slot_id.as_bytes());
        out.push(self.target as u8);
        out.extend_from_slice(self.target_id.as_bytes());
        out.push(self.vault_mode as u8);
        out.push(self.route as u8);
        match self.entry {
            None => out.push(0),
            Some(e) => {
                out.extend_from_slice(&[1, e.mode as u8, e.tier as u8, e.recovery as u8]);
            }
        }
        match &self.password {
            None => out.push(0),
            Some(p) => {
                out.push(1);
                out.extend_from_slice(&p.salt);
                out.extend_from_slice(&p.memory_kib.to_be_bytes());
                out.extend_from_slice(&p.passes.to_be_bytes());
                out.extend_from_slice(&p.lanes.to_be_bytes());
                out.extend_from_slice(b"argon2id-v0x13");
            }
        }
        match &self.provider {
            ProviderBinding::None => out.push(0),
            ProviderBinding::Virtual { provider_id, purpose_hash } => {
                out.push(1);
                out.extend_from_slice(provider_id.as_bytes());
                out.extend_from_slice(purpose_hash);
            }
            ProviderBinding::Physical { credential_id, rp_id_hash, prf_salt,
                scope, up_required, uv_required } => {
                out.push(2);
                out.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
                out.extend_from_slice(credential_id);
                out.extend_from_slice(rp_id_hash);
                out.extend_from_slice(prf_salt);
                out.push(match scope {
                    PrfScope::VaultCredentialPurpose => 1,
                    PrfScope::EntrySlotPurpose => 2,
                });
                out.extend_from_slice(&[u8::from(*up_required), u8::from(*uv_required)]);
            }
        }
        if out.len() > MAX_DESCRIPTOR { return Err(V02Error::TooLarge); }
        Ok(out)
    }
}

/// Values furnished by a **test harness**, not certified factor provenance.
/// The route/target dictates whether one or two 32-byte components are needed.
pub(crate) enum Components<'a> {
    Single(&'a [u8;32]),
    Combined { first: &'a [u8;32], second: &'a [u8;32] },
}
fn schedule(
    desc: &Descriptor, factors: Components<'_>,
) -> Result<(Zeroizing<[u8;32]>, Zeroizing<[u8;32]>, Vec<u8>), V02Error> {
    let transcript = desc.transcript()?;
    let mut ikm = Zeroizing::new(Vec::with_capacity(100));
    ikm.extend_from_slice(DOMAIN);
    match (desc.single_component(), factors) {
        (true, Components::Single(value)) => {
            ikm.push(1);
            ikm.extend_from_slice(value);
        }
        (false, Components::Combined { first, second }) => {
            ikm.push(2);
            ikm.extend_from_slice(first);
            ikm.extend_from_slice(second);
        }
        _ => return Err(V02Error::Invalid("candidate factor recipe mismatch")),
    }
    let salt = Sha256::digest(&transcript);
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut wrap = Zeroizing::new([0u8;32]);
    let mut commitment = Zeroizing::new([0u8;32]);
    hk.expand(b"Vaulty/V02-B/review-only/wrap-key", &mut *wrap)
        .map_err(|_| V02Error::Invalid("candidate HKDF expand wrap"))?;
    hk.expand(b"Vaulty/V02-B/review-only/commitment-key", &mut *commitment)
        .map_err(|_| V02Error::Invalid("candidate HKDF expand commitment"))?;
    Ok((wrap, commitment, transcript))
}

pub(crate) struct CandidateEnvelope {
    pub descriptor: Descriptor,
    pub nonce: [u8;24],
    pub ciphertext: Vec<u8>,
    pub candidate_commitment: [u8;32],
}
fn commitment_tag(
    key: &[u8;32], transcript: &[u8], nonce: &[u8;24], ciphertext: &[u8],
) -> Result<[u8;32], V02Error> {
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(key)
        .map_err(|_| V02Error::Invalid("candidate MAC key"))?;
    mac.update(DOMAIN);
    mac.update(b"/mac-v1");
    mac.update(&(transcript.len() as u32).to_be_bytes());
    mac.update(transcript);
    mac.update(nonce);
    mac.update(&(ciphertext.len() as u32).to_be_bytes());
    mac.update(ciphertext);
    let mut out = [0u8;32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    Ok(out)
}
fn check_commitment(
    key: &[u8;32], transcript: &[u8], nonce: &[u8;24],
    ciphertext: &[u8], tag: &[u8;32],
) -> Result<(), V02Error> {
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(key)
        .map_err(|_| V02Error::Invalid("candidate MAC key"))?;
    mac.update(DOMAIN);
    mac.update(b"/mac-v1");
    mac.update(&(transcript.len() as u32).to_be_bytes());
    mac.update(transcript);
    mac.update(nonce);
    mac.update(&(ciphertext.len() as u32).to_be_bytes());
    mac.update(ciphertext);
    mac.verify_slice(tag).map_err(|_| V02Error::AuthenticationFailed)
}

/// Output remains UNVERIFIED even after a synthetic local round trip. Never
/// feed this envelope into VLY2 or treat it as a usable recovery slot.
pub(crate) fn seal_candidate(
    descriptor: Descriptor, factors: Components<'_>, key_material: &[u8;32],
) -> Result<CandidateEnvelope, V02Error> {
    let (wrap, commit, transcript) = schedule(&descriptor, factors)?;
    let mut nonce = [0u8;24];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&*wrap));
    let ciphertext = cipher.encrypt(XNonce::from_slice(&nonce),
        Payload { msg: key_material, aad: &transcript })
        .map_err(|_| V02Error::AuthenticationFailed)?;
    let tag = commitment_tag(&commit, &transcript, &nonce, &ciphertext)?;
    Ok(CandidateEnvelope { descriptor, nonce, ciphertext, candidate_commitment: tag })
}
pub(crate) fn open_candidate(
    envelope: &CandidateEnvelope, factors: Components<'_>,
) -> Result<Zeroizing<[u8;32]>, V02Error> {
    if envelope.nonce == [0;24] || envelope.ciphertext.len() != 48 {
        return Err(V02Error::Invalid("candidate slot nonce/length"));
    }
    let (wrap, commitment, transcript) = schedule(&envelope.descriptor, factors)?;
    check_commitment(&commitment, &transcript, &envelope.nonce,
        &envelope.ciphertext, &envelope.candidate_commitment)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&*wrap));
    let plaintext = Zeroizing::new(cipher.decrypt(XNonce::from_slice(&envelope.nonce),
        Payload { msg: &envelope.ciphertext, aad: &transcript })
        .map_err(|_| V02Error::AuthenticationFailed)?);
    if plaintext.len() != 32 {
        return Err(V02Error::Invalid("candidate plaintext key length"));
    }
    let mut key = Zeroizing::new([0u8;32]);
    key.copy_from_slice(&plaintext);
    Ok(key)
}

#[cfg(test)]
#[path = "v02c_tests.rs"]
mod conformance;

#[cfg(test)]
mod tests {
    use super::*;
    fn params() -> PasswordParameters {
        PasswordParameters { salt: [3;16], memory_kib:8192, passes:2, lanes:1 }
    }
    fn virtual_binding() -> ProviderBinding {
        ProviderBinding::Virtual { provider_id: Uuid::new_v4(), purpose_hash: [17;32] }
    }
    fn physical_binding(scope: PrfScope) -> ProviderBinding {
        ProviderBinding::Physical { credential_id:b"credential-A".to_vec(),
            rp_id_hash:[7;32], prf_salt:[9;32], scope, up_required:true, uv_required:true }
    }
    fn desc(target: SlotTarget, route: FactorPolicy, vault_mode: VaultMode) -> Descriptor {
        let password = matches!(route, FactorPolicy::VaultPasswordVirtual | FactorPolicy::VaultPasswordPhysical
            | FactorPolicy::CodePassword | FactorPolicy::CustomVirtual | FactorPolicy::CustomPhysical)
            .then(params);
        let provider = match route {
            FactorPolicy::VaultPasswordVirtual | FactorPolicy::DefaultVirtual |
            FactorPolicy::CustomVirtual if target != SlotTarget::ProviderSeed => virtual_binding(),
            FactorPolicy::VaultPasswordPhysical | FactorPolicy::CodePhysical |
            FactorPolicy::DefaultPhysical | FactorPolicy::CustomPhysical =>
                physical_binding(PrfScope::EntrySlotPurpose),
            _ => ProviderBinding::None,
        };
        let entry = (target == SlotTarget::EntryDek).then_some(EntryProtection {
            mode: match route {
                FactorPolicy::DefaultPhysical | FactorPolicy::CodePhysical =>
                    EntryMode::DefaultPhysical,
                FactorPolicy::CustomPhysical => EntryMode::CustomPhysical,
                FactorPolicy::CustomVirtual => EntryMode::CustomVirtual,
                _ => EntryMode::DefaultVirtual,
            },
            tier: EntryTier::Standard, recovery: RecoveryPolicy::Shared,
        });
        Descriptor { protocol_version: PROTOCOL_CANDIDATE_VERSION,
            vault_id:Uuid::new_v4(), slot_id:Uuid::new_v4(), target,
            target_id:if target == SlotTarget::EntryDek {Uuid::new_v4()} else {Uuid::nil()},
            vault_mode, route, entry, password, provider }
    }
    #[test]
    fn password_component_is_deterministic_and_bounded() {
        let p=params();
        let a=password_component(b"synthetic password", &p).unwrap();
        let b=password_component(b"synthetic password", &p).unwrap();
        assert_eq!(*a,*b);
        assert_ne!(*a, *password_component(b"other", &p).unwrap());
        let mut weak=p.clone();weak.memory_kib=1;assert!(password_component(b"x",&weak).is_err());
        weak=p.clone();weak.passes=100;assert!(password_component(b"x",&weak).is_err());
        weak=p.clone();weak.salt=[0;16];assert!(password_component(b"x",&weak).is_err());
        assert!(password_component(b"",&p).is_err());
    }
    #[test]
    fn combined_route_roundtrip_rejects_wrong_factors_and_substitution() {
        let d=desc(SlotTarget::Vmk,FactorPolicy::VaultPasswordPhysical,VaultMode::PasswordPhysical);
        let first=[21;32];let second=[34;32];let wrong=[35;32];let secret=[99;32];
        let a=seal_candidate(d.clone(),Components::Combined{first:&first,second:&second},&secret).unwrap();
        let b=seal_candidate(d,Components::Combined{first:&first,second:&second},&secret).unwrap();
        assert_ne!(a.nonce,b.nonce);
        assert_ne!(a.ciphertext,b.ciphertext);
        assert_eq!(*open_candidate(&a,Components::Combined{first:&first,second:&second}).unwrap(),secret);
        assert!(open_candidate(&a,Components::Combined{first:&wrong,second:&second}).is_err());
        assert!(open_candidate(&a,Components::Combined{first:&first,second:&wrong}).is_err());
        assert!(open_candidate(&a,Components::Single(&first)).is_err());
        let mut changed=a;
        changed.descriptor.slot_id=Uuid::new_v4();
        assert!(open_candidate(&changed,Components::Combined{first:&first,second:&second}).is_err());
        changed.descriptor=b.descriptor;
        changed.nonce=[7;24];
        assert!(open_candidate(&changed,Components::Combined{first:&first,second:&second}).is_err());
        changed.nonce=b.nonce;
        changed.candidate_commitment=[0;32];
        assert!(open_candidate(&changed,Components::Combined{first:&first,second:&second}).is_err());
    }
    #[test]
    fn code_only_only_in_password_vault_and_requires_single_component() {
        let d=desc(SlotTarget::Vmk,FactorPolicy::CodeOnly,VaultMode::PasswordVirtual);
        let code=[63;32];let fake=[64;32];let secret=[82;32];
        let env=seal_candidate(d.clone(),Components::Single(&code),&secret).unwrap();
        assert_eq!(*open_candidate(&env,Components::Single(&code)).unwrap(),secret);
        assert!(open_candidate(&env,Components::Single(&fake)).is_err());
        assert!(seal_candidate(d,Components::Combined{first:&code,second:&fake},&secret).is_err());
        let d=desc(SlotTarget::Vmk,FactorPolicy::CodeOnly,VaultMode::PasswordPhysical);
        assert!(seal_candidate(d,Components::Single(&code),&secret).is_err());
    }
    #[test]
    fn physical_bindings_require_pinned_fields_and_reject_mutations() {
        let d=desc(SlotTarget::Vmk,FactorPolicy::VaultPasswordPhysical,VaultMode::PasswordPhysical);
        let first=[1;32];let second=[2;32];
        let env=seal_candidate(d,Components::Combined{first:&first,second:&second},&[3;32]).unwrap();
        let mut mutated=env;
        if let ProviderBinding::Physical{ref mut prf_salt,..}=mutated.descriptor.provider {
            *prf_salt=[2;32];
        }
        assert!(open_candidate(&mutated,Components::Combined{first:&first,second:&second}).is_err());
        if let ProviderBinding::Physical{ref mut up_required,..}=mutated.descriptor.provider {
            *up_required=false;
        }
        assert!(open_candidate(&mutated,Components::Combined{first:&first,second:&second}).is_err());
    }
    #[test]
    fn isolated_is_physical_even_without_recovery() {
        let mut d=desc(SlotTarget::EntryDek,FactorPolicy::DefaultPhysical,VaultMode::PasswordPhysical);
        d.entry.as_mut().unwrap().tier=EntryTier::Isolated;
        d.entry.as_mut().unwrap().recovery=RecoveryPolicy::StrictNone;
        assert!(d.validate().is_ok());
        d.route=FactorPolicy::DefaultVirtual;d.provider=virtual_binding();
        assert!(d.validate().is_err());
        d.route=FactorPolicy::CodePhysical;d.provider=physical_binding(PrfScope::EntrySlotPurpose);
        assert!(d.validate().is_err()); // STRICT_NONE recovery disabled
        d.entry.as_mut().unwrap().recovery=RecoveryPolicy::Shared;
        assert!(d.validate().is_ok());
        d.provider=physical_binding(PrfScope::VaultCredentialPurpose);
        assert!(d.validate().is_err());
        d.provider=ProviderBinding::None;
        assert!(d.validate().is_err());
        d.route=FactorPolicy::CodePassword;
        assert!(d.validate().is_err());
    }
    #[test]
    fn provider_seed_bootstrap_password_only_avoids_virtual_circularity() {
        let d=desc(SlotTarget::ProviderSeed,FactorPolicy::VaultPasswordVirtual,VaultMode::PasswordVirtual);
        assert!(matches!(d.provider,ProviderBinding::None));
        let pwd=[4;32];let seed=[10;32];
        let env=seal_candidate(d,Components::Single(&pwd),&seed).unwrap();
        assert_eq!(*open_candidate(&env,Components::Single(&pwd)).unwrap(),seed);
        let d=desc(SlotTarget::ProviderSeed,FactorPolicy::CodeOnly,VaultMode::PasswordVirtual);
        let code=[8;32];
        let backup=seal_candidate(d,Components::Single(&code),&seed).unwrap();
        assert_eq!(*open_candidate(&backup,Components::Single(&code)).unwrap(),seed);
        assert!(open_candidate(&backup,Components::Single(&pwd)).is_err());
    }
    #[test]
    fn password_only_vault_can_recover_isolated_entry_with_code_and_physical() {
        let mut d=desc(SlotTarget::EntryDek,FactorPolicy::CodePhysical,
            VaultMode::PasswordVirtual);
        d.entry.as_mut().unwrap().tier=EntryTier::Isolated;
        d.entry.as_mut().unwrap().recovery=RecoveryPolicy::Shared;
        d.provider=physical_binding(PrfScope::EntrySlotPurpose);
        assert!(d.validate().is_ok());
        let code=[11;32];let hardware=[12;32];let secret=[13;32];
        let env=seal_candidate(d,Components::Combined{
            first:&code,second:&hardware},&secret).unwrap();
        assert_eq!(*open_candidate(&env,Components::Combined{
            first:&code,second:&hardware}).unwrap(),secret);
        assert!(open_candidate(&env,Components::Single(&code)).is_err());
    }
    #[test]
    fn version_policy_and_password_metadata_cannot_be_silently_downgraded() {
        let d=desc(SlotTarget::Vmk,FactorPolicy::VaultPasswordVirtual,VaultMode::PasswordVirtual);
        let a=[7;32];let b=[8;32];let secret=[9;32];
        let e=seal_candidate(d,Components::Combined{first:&a,second:&b},&secret).unwrap();
        let mut x=e;
        x.descriptor.protocol_version+=1;
        assert!(open_candidate(&x,Components::Combined{first:&a,second:&b}).is_err());
        x.descriptor.protocol_version=PROTOCOL_CANDIDATE_VERSION;
        x.descriptor.password.as_mut().unwrap().memory_kib=8192+1024;
        assert!(open_candidate(&x,Components::Combined{first:&a,second:&b}).is_err());
        x.descriptor.password=None;
        assert!(open_candidate(&x,Components::Combined{first:&a,second:&b}).is_err());
    }
    #[test]
    fn code_plus_password_and_hardware_admin_routes_are_distinct() {
        let code=[1;32];let password=[2;32];let prf=[3;32];
        let a=desc(SlotTarget::Vmk,FactorPolicy::CodePassword,VaultMode::PasswordPhysical);
        let b=desc(SlotTarget::Vmk,FactorPolicy::CodePhysical,VaultMode::PasswordPhysical);
        assert!(seal_candidate(a,Components::Combined{first:&code,second:&password},&[9;32]).is_ok());
        assert!(seal_candidate(b,Components::Combined{first:&code,second:&prf},&[9;32]).is_ok());
        let bad=desc(SlotTarget::Vmk,FactorPolicy::CodeOnly,VaultMode::PasswordPhysical);
        assert!(seal_candidate(bad,Components::Single(&code),&[9;32]).is_err());
    }
}
