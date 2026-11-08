//! V02-I REVIEW-ONLY FIDO2 PRF context and CTAP salt proposal.
//!
//! Compiled ONLY with tests. Produces PUBLIC PRF *inputs*, not PRF secrets.
//! No credential enrollment, authenticator assertion, UV/UP verification,
//! cryptographic slot, trusted owner consent, READY state or hardware access.
//! OPEN-15/OPEN-01 and owner UV/batching decisions remain BLOCKED.
use super::{EntryTier, SlotTarget, V02Error};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const DOMAIN: &[u8] = b"Vaulty/V02-I/REVIEW-ONLY/prf-input/v1";
const WEBAUTHN_PREFIX: &[u8] = b"WebAuthn PRF\0";
const VERSION: u16 = 1;
const MAX_CREDENTIAL: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Purpose { Normal = 1, Recovery = 2 }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scope { Vault = 1, Entry = 3 }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Assurance { UvRequired = 1, TouchOnlyProposed = 2 }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Transport { WebAuthnPrf, NativeCtapHmacSecret }

/// Describes only a proposed, public evaluation point. The credential ID is
/// NOT verified by this struct and a SHA256 digest proves no hardware usage.
#[derive(Clone, Debug, Eq, PartialEq)]
struct PrfInput {
    vault_id: Uuid,
    slot_id: Uuid,
    target: SlotTarget,
    target_id: Uuid,
    purpose: Purpose,
    entry_tier: Option<EntryTier>,
    scope: Scope,
    scope_owner: Uuid,
    credential_id: Vec<u8>,
    rp_id_hash: [u8; 32],
    assurance: Assurance,
}

impl PrfInput {
    fn validate(&self) -> Result<(), V02Error> {
        if self.vault_id.is_nil() || self.slot_id.is_nil()
            || self.credential_id.is_empty() || self.credential_id.len() > MAX_CREDENTIAL
            || self.rp_id_hash == [0; 32]
        {
            return Err(V02Error::Invalid("review PRF input identity"));
        }
        match self.target {
            SlotTarget::EntryDek => {
                if self.target_id.is_nil() || self.entry_tier.is_none()
                    || self.scope != Scope::Entry
                    || self.scope_owner != self.target_id
                {
                    return Err(V02Error::Invalid("entry PRF scope must be per entry"));
                }
            }
            _ => {
                if !self.target_id.is_nil() || self.entry_tier.is_some()
                    || self.scope != Scope::Vault
                    || self.scope_owner != self.vault_id
                {
                    return Err(V02Error::Invalid("non-entry PRF scope must be vault root"));
                }
            }
        }
        Ok(())
    }

    /// Exact REVIEW-ONLY preimage for a browser `prf.eval.first` evaluation.
    /// Domain || u16be(version) || vault[16] || slot[16] || target[u8] ||
    /// target_id[16] || purpose[u8] || tier[u8, 0 for root] ||
    /// scope[u8] || scope_owner[16] || credential_len[u16be] ||
    /// credential_id || RP_ID_SHA256[32] || assurance[u8].
    fn browser_input(&self) -> Result<Vec<u8>, V02Error> {
        self.validate()?;
        let mut out = Vec::with_capacity(DOMAIN.len() + 111 + self.credential_id.len());
        out.extend_from_slice(DOMAIN);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(self.vault_id.as_bytes());
        out.extend_from_slice(self.slot_id.as_bytes());
        out.push(self.target as u8);
        out.extend_from_slice(self.target_id.as_bytes());
        out.push(self.purpose as u8);
        out.push(self.entry_tier.map_or(0, |tier| tier as u8));
        out.push(self.scope as u8);
        out.extend_from_slice(self.scope_owner.as_bytes());
        out.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.credential_id);
        out.extend_from_slice(&self.rp_id_hash);
        out.push(self.assurance as u8);
        Ok(out)
    }

    /// Compatibility salt candidate for native CTAP hmac-secret (32 bytes).
    /// W3C WebAuthn PRF first hashes `"WebAuthn PRF" || 0x00 || eval.first`.
    /// Hashing that same preimage permits a *hypothesized* interoperable UV
    /// output. Actual result equivalence requires OPEN-15 real hardware tests.
    fn ctap_salt(&self) -> Result<[u8; 32], V02Error> {
        let input = self.browser_input()?;
        let mut h = Sha256::new();
        h.update(WEBAUTHN_PREFIX);
        h.update(&input);
        Ok(h.finalize().into())
    }

    /// A WebAuthn PRF output is based on UV; a claimed UP-only WebAuthn PRF
    /// cannot be silently interpreted as CTAP's non-UV hmac-secret branch.
    fn validate_transport(&self, transport: Transport) -> Result<(), V02Error> {
        self.validate()?;
        if transport == Transport::WebAuthnPrf
            && self.assurance != Assurance::UvRequired
        {
            return Err(V02Error::Invalid("WebAuthn PRF requires UV-backed branch"));
        }
        // Native UV/UP claims are NOT proven by this policy or this return.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> Uuid { Uuid::from_bytes([n; 16]) }
    fn sample() -> PrfInput {
        PrfInput {
            vault_id: id(1),
            slot_id: id(2),
            target: SlotTarget::EntryDek,
            target_id: id(3),
            purpose: Purpose::Normal,
            entry_tier: Some(EntryTier::Isolated),
            scope: Scope::Entry,
            scope_owner: id(3),
            credential_id: b"synthetic-main".to_vec(),
            rp_id_hash: [7; 32],
            assurance: Assurance::UvRequired,
        }
    }

    #[test]
    fn distinct_isolated_entries_or_slots_do_not_reuse_prf_salt() {
        let a = sample();
        let mut b = a.clone();
        b.target_id = id(4); b.scope_owner = id(4);
        assert_ne!(a.ctap_salt().unwrap(), b.ctap_salt().unwrap());
        let mut b = a.clone(); b.slot_id = id(4);
        assert_ne!(a.ctap_salt().unwrap(), b.ctap_salt().unwrap());
        let mut b = a.clone(); b.vault_id = id(4);
        assert_ne!(a.ctap_salt().unwrap(), b.ctap_salt().unwrap());
        let mut b = a.clone(); b.purpose = Purpose::Recovery;
        assert_ne!(a.ctap_salt().unwrap(), b.ctap_salt().unwrap());
        let mut b = a.clone(); b.rp_id_hash = [8;32];
        assert_ne!(a.ctap_salt().unwrap(), b.ctap_salt().unwrap());
    }

    #[test]
    fn separately_enrolled_backup_key_needs_an_independent_slot() {
        let a = sample();
        let mut b = a.clone();
        b.slot_id = id(8);
        b.credential_id = b"synthetic-backup".to_vec();
        assert_ne!(a.ctap_salt().unwrap(), b.ctap_salt().unwrap());
        assert_ne!(a.browser_input().unwrap(), b.browser_input().unwrap());
        // Token registration alone cannot seal b's entry DEK route:
        // there is no key operation or READY transition in this module.
    }

    #[test]
    fn binding_wrong_scope_or_missing_identifiers_fails_closed() {
        let mut a = sample();
        a.scope = Scope::Vault;
        assert!(a.validate().is_err());
        let mut a = sample();
        a.scope_owner = id(99);
        assert!(a.validate().is_err());
        let mut a = sample();
        a.target_id = Uuid::nil();
        assert!(a.validate().is_err());
        let mut a = sample();
        a.credential_id.clear();
        assert!(a.validate().is_err());
        let mut a = sample();
        a.credential_id = vec![1;129];
        assert!(a.validate().is_err());
        let mut a = sample();
        a.rp_id_hash = [0;32];
        assert!(a.validate().is_err());
        let mut a = sample();
        a.target = SlotTarget::Vmk;
        assert!(a.validate().is_err());
    }

    #[test]
    fn root_context_is_vault_scoped_but_not_a_dek_credential() {
        let mut a = sample();
        a.target = SlotTarget::Vmk; a.target_id = Uuid::nil();
        a.entry_tier = None; a.scope = Scope::Vault; a.scope_owner = a.vault_id;
        assert!(a.validate().is_ok());
        assert_ne!(sample().ctap_salt().unwrap(), a.ctap_salt().unwrap());
        a.scope_owner = id(9);
        assert!(a.validate().is_err());
    }

    #[test]
    fn uv_required_and_touch_only_have_distinct_salts_and_transport_contracts() {
        let uv = sample();
        let mut touch = uv.clone();
        touch.assurance = Assurance::TouchOnlyProposed;
        assert_ne!(uv.ctap_salt().unwrap(), touch.ctap_salt().unwrap());
        assert!(uv.validate_transport(Transport::WebAuthnPrf).is_ok());
        assert!(touch.validate_transport(Transport::WebAuthnPrf).is_err());
        assert!(touch.validate_transport(Transport::NativeCtapHmacSecret).is_ok());
        // The native result only means *parseable policy*, not approved UP-only
        // access, successful UV, fresh UP, a verified PRF or a registered key.
    }

    #[test]
    fn group_recovery_code_scope_cannot_change_isolated_prf_target() {
        let a = sample();
        let mut b = a.clone();
        b.purpose = Purpose::Recovery;
        assert_ne!(a.ctap_salt().unwrap(), b.ctap_salt().unwrap());
        // A GROUP recovery code may be shared under v0.4.5. The physical
        // *entry PRF* must still remain scoped to the individual DEK target.
        b.scope = Scope::Vault;
        assert!(b.validate().is_err());
    }

    #[test]
    fn candidate_context_is_stable_for_same_slot_not_random_per_read() {
        let a = sample();
        assert_eq!(a.browser_input().unwrap(), a.browser_input().unwrap());
        assert_eq!(a.ctap_salt().unwrap(), a.ctap_salt().unwrap());
        // Fresh physical operation each read is still REQUIRED by S1/S2;
        // stable inputs are needed to reproduce existing encrypted envelopes.
        assert!(a.browser_input().unwrap().starts_with(DOMAIN));
    }

    #[test]
    fn frozen_independently_encoded_python_vectors_match() {
        let fixtures = include_str!("../../tools/v02_verifier/fixtures/v02i_prf_vectors.txt");
        let mut count = 0;
        for line in fixtures.lines() {
            let fields: Vec<_> = line.split('|').collect();
            assert_eq!(fields.len(), 3);
            let mut sample = sample();
            match fields[0] {
                "isolated-main" => {},
                "isolated-entry-b" => { sample.target_id = id(4); sample.scope_owner = id(4); },
                "isolated-backup" => { sample.slot_id = id(8); sample.credential_id = b"synthetic-backup".to_vec(); },
                "isolated-recovery" => { sample.purpose = Purpose::Recovery; },
                "isolated-touch" => { sample.assurance = Assurance::TouchOnlyProposed; },
                "vault-vmk" => { sample.target = SlotTarget::Vmk; sample.target_id = Uuid::nil();
                    sample.entry_tier = None; sample.scope = Scope::Vault; sample.scope_owner = id(1); },
                other => panic!("unknown V02-I review case {other}"),
            }
            let context = sample.browser_input().unwrap();
            let ctap = sample.ctap_salt().unwrap();
            assert_eq!(hex(&context), fields[1], "PRF browser preimage mismatch: {}", fields[0]);
            assert_eq!(hex(&ctap), fields[2], "CTAP PRF salt mismatch: {}", fields[0]);
            count += 1;
        }
        assert_eq!(count, 6);
    }
    fn hex(input: &[u8]) -> String {
        input.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
