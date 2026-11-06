//! V02 candidate encrypted single-file format. NOT a finalized wire standard.
//! The application executable is disabled. OPEN-01/OPEN-15 must approve key
//! commitments, factor combiner, PRF transcript and final slot wire encoding.
//! No password/hardware/recovery factor is accepted by this module.
#![allow(dead_code)]
use argon2::password_hash::rand_core::{OsRng, RngCore};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use std::collections::HashSet;
use std::fmt;
use uuid::Uuid;
use zeroize::Zeroizing;

pub(super) const MAGIC: &[u8; 4] = b"VLY2";
pub(super) const VERSION: u16 = 2;
pub(super) const OUTER_DOMAIN: &[u8] = b"Vaulty/V02/candidate/outer/v0";
pub(super) const ENTRY_DOMAIN: &[u8] = b"Vaulty/V02/candidate/entry/v0";
pub(super) const MAX_FILE: usize = MAX_BODY + MAX_HEADER + 16;
pub(super) const MAX_HEADER: usize = 65536;
pub(super) const MAX_BODY: usize = 16 * 1024 * 1024;
pub(super) const MAX_ENTRIES: usize = 1024;
pub(super) const MAX_SLOTS: usize = 256;
pub(super) const MAX_SLOT_BYTES: usize = 1024;
pub(super) const MAX_ENTRY_BYTES: usize = 1024 * 1024;
pub(super) const MAX_CLIENTS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V02Error {
    Invalid(&'static str),
    TooLarge,
    UnsupportedVersion,
    MigrationRequired,
    AuthenticationFailed,
    Conflict,
}
impl fmt::Display for V02Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(s) => write!(f, "invalid V02 record: {s}"),
            Self::TooLarge => write!(f, "V02 size/count bound exceeded"),
            Self::UnsupportedVersion => write!(f, "unsupported V02 version"),
            Self::MigrationRequired => write!(f, "legacy vault requires separately authorized migration"),
            Self::AuthenticationFailed => write!(f, "V02 authenticated decrypt rejected"),
            Self::Conflict => write!(f, "V02 authenticated ancestry conflict"),
        }
    }
}
impl std::error::Error for V02Error {}

/// Three independently random key classes. No VMK-to-VERS/DEK derivation.
/// Secret wrappers zeroize on Drop, are intentionally not Clone/Debug, and do
/// NOT implement any production unlock, password or physical PRF transcript.
pub struct Vmk(pub(super) Zeroizing<[u8; 32]>);
pub struct Vers(pub(super) Zeroizing<[u8; 32]>);
pub struct Dek(pub(super) Zeroizing<[u8; 32]>);
fn random_key() -> Zeroizing<[u8; 32]> {
    let mut value = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *value);
    value
}
pub(super) fn random_nonce() -> [u8; 24] {
    let mut bytes = [0u8; 24];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
impl Vmk {
    pub fn random() -> Self { Self(random_key()) }
    pub(super) fn key(&self) -> &[u8; 32] { &self.0 }
}
impl Vers { pub fn random() -> Self { Self(random_key()) } }
impl Dek {
    pub fn random() -> Self { Self(random_key()) }
    pub(super) fn key(&self) -> &[u8; 32] { &self.0 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VaultMode { PasswordVirtual = 1, PasswordPhysical = 2 }
impl TryFrom<u8> for VaultMode {
    type Error = V02Error;
    fn try_from(n: u8) -> Result<Self, Self::Error> {
        match n { 1 => Ok(Self::PasswordVirtual), 2 => Ok(Self::PasswordPhysical),
            _ => Err(V02Error::Invalid("unknown vault mode")) }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryMode {
    DefaultVirtual = 1, DefaultPhysical = 2, CustomVirtual = 3, CustomPhysical = 4
}
impl EntryMode {
    pub(super) fn physical(self) -> bool { matches!(self, Self::DefaultPhysical | Self::CustomPhysical) }
    fn normal_factor(self) -> FactorPolicy {
        match self {
            Self::DefaultVirtual => FactorPolicy::DefaultVirtual,
            Self::DefaultPhysical => FactorPolicy::DefaultPhysical,
            Self::CustomVirtual => FactorPolicy::CustomVirtual,
            Self::CustomPhysical => FactorPolicy::CustomPhysical,
        }
    }
}
impl TryFrom<u8> for EntryMode {
    type Error = V02Error;
    fn try_from(n: u8) -> Result<Self, Self::Error> {
        match n { 1 => Ok(Self::DefaultVirtual), 2 => Ok(Self::DefaultPhysical),
            3 => Ok(Self::CustomVirtual), 4 => Ok(Self::CustomPhysical),
            _ => Err(V02Error::Invalid("unknown entry mode")) }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryTier { Standard = 1, Isolated = 2 }
impl TryFrom<u8> for EntryTier {
    type Error = V02Error;
    fn try_from(n: u8) -> Result<Self, Self::Error> {
        match n { 1 => Ok(Self::Standard), 2 => Ok(Self::Isolated),
            _ => Err(V02Error::Invalid("unknown entry tier")) }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecoveryPolicy { Shared = 1, Group = 2, Independent = 3, StrictNone = 4 }
impl TryFrom<u8> for RecoveryPolicy {
    type Error = V02Error;
    fn try_from(n: u8) -> Result<Self, Self::Error> {
        match n { 1 => Ok(Self::Shared), 2 => Ok(Self::Group),
            3 => Ok(Self::Independent), 4 => Ok(Self::StrictNone),
            _ => Err(V02Error::Invalid("unknown recovery policy")) }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SlotTarget { Vmk = 1, Vers = 2, EntryDek = 3, ProviderSeed = 4 }
impl TryFrom<u8> for SlotTarget {
    type Error = V02Error;
    fn try_from(n: u8) -> Result<Self, Self::Error> {
        match n { 1 => Ok(Self::Vmk), 2 => Ok(Self::Vers),
            3 => Ok(Self::EntryDek), 4 => Ok(Self::ProviderSeed),
            _ => Err(V02Error::Invalid("unknown key target")) }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FactorPolicy {
    VaultPasswordVirtual = 1, VaultPasswordPhysical = 2,
    CodeOnly = 3, CodePassword = 4, CodePhysical = 5,
    DefaultVirtual = 6, DefaultPhysical = 7,
    CustomVirtual = 8, CustomPhysical = 9,
}
impl FactorPolicy {
    pub(super) fn is_recovery(self) -> bool {
        matches!(self, Self::CodeOnly | Self::CodePassword | Self::CodePhysical)
    }
    fn physical(self) -> bool {
        matches!(self, Self::VaultPasswordPhysical | Self::CodePhysical |
            Self::DefaultPhysical | Self::CustomPhysical)
    }
}
impl TryFrom<u8> for FactorPolicy {
    type Error = V02Error;
    fn try_from(n: u8) -> Result<Self, Self::Error> {
        match n { 1 => Ok(Self::VaultPasswordVirtual), 2 => Ok(Self::VaultPasswordPhysical),
            3 => Ok(Self::CodeOnly), 4 => Ok(Self::CodePassword),
            5 => Ok(Self::CodePhysical), 6 => Ok(Self::DefaultVirtual),
            7 => Ok(Self::DefaultPhysical), 8 => Ok(Self::CustomVirtual),
            9 => Ok(Self::CustomPhysical), _ => Err(V02Error::Invalid("unknown factor policy")) }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SlotState { Pending = 1, SealedUnverified = 2, Verified = 3, Disabled = 4 }
impl TryFrom<u8> for SlotState {
    type Error = V02Error;
    fn try_from(n: u8) -> Result<Self, Self::Error> {
        match n { 1 => Ok(Self::Pending), 2 => Ok(Self::SealedUnverified),
            3 => Ok(Self::Verified), 4 => Ok(Self::Disabled),
            _ => Err(V02Error::Invalid("unknown slot status")) }
    }
}

/// Opaque wrapper description, never proof that a factor is available.
/// No production constructor can transition to Verified before V04.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    pub id: Uuid,
    pub target: SlotTarget,
    pub target_id: Uuid,
    pub factors: FactorPolicy,
    pub state: SlotState,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}
impl Slot {
    pub fn pending(target: SlotTarget, target_id: Uuid, factors: FactorPolicy) -> Self {
        Self { id: Uuid::new_v4(), target, target_id, factors,
            state: SlotState::Pending, nonce: [0; 24], ciphertext: Vec::new() }
    }
    pub(super) fn validate(&self, vault_mode: VaultMode) -> Result<(), V02Error> {
        if self.id.is_nil() { return Err(V02Error::Invalid("nil slot id")); }
        if (self.target == SlotTarget::EntryDek) != !self.target_id.is_nil() {
            return Err(V02Error::Invalid("key slot target id mismatch"));
        }
        if vault_mode == VaultMode::PasswordPhysical && self.factors == FactorPolicy::CodeOnly {
            return Err(V02Error::Invalid("code-only hardware vault route forbidden"));
        }
        match self.state {
            SlotState::Pending | SlotState::Disabled => {
                if !self.ciphertext.is_empty() || self.nonce != [0u8; 24] {
                    return Err(V02Error::Invalid("pending/disabled slot contains ciphertext"));
                }
            }
            SlotState::Verified | SlotState::SealedUnverified => {
                if self.ciphertext.len() != 48 || self.nonce == [0u8; 24] {
                    return Err(V02Error::Invalid("slot envelope length or nonce"));
                }
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicHeader {
    pub vault_id: Uuid,
    pub commit_id: Uuid,
    pub generation: u64,
    pub predecessor_hash: [u8; 32], // hash of preceding complete encrypted file
    pub mode: VaultMode,
    pub vmk_slots: Vec<Slot>,
    /// Pre-load provider-seed envelopes, outside VMK encryption to avoid
    /// the virtual-provider/VMK bootstrap circularity (OPEN-02).
    pub bootstrap_slots: Vec<Slot>,
}
impl PublicHeader {
    pub fn genesis(mode: VaultMode, vmk_slots: Vec<Slot>) -> Self {
        Self { vault_id: Uuid::new_v4(), commit_id: Uuid::new_v4(),
            generation: 1, predecessor_hash: [0u8; 32], mode, vmk_slots,
            bootstrap_slots: if mode == VaultMode::PasswordVirtual {
                vec![
                    Slot::pending(SlotTarget::ProviderSeed, Uuid::nil(),
                        FactorPolicy::VaultPasswordVirtual),
                    Slot::pending(SlotTarget::ProviderSeed, Uuid::nil(),
                        FactorPolicy::CodeOnly),
                ]
            } else { Vec::new() },
        }
    }
    fn validate(&self) -> Result<(), V02Error> {
        if self.vault_id.is_nil() || self.commit_id.is_nil() || self.generation == 0 {
            return Err(V02Error::Invalid("missing vault/commit id or generation"));
        }
        if (self.generation == 1) != (self.predecessor_hash == [0u8;32]) {
            return Err(V02Error::Invalid("invalid authenticated predecessor"));
        }
        if self.vmk_slots.len() > MAX_SLOTS || self.bootstrap_slots.len() > MAX_SLOTS {
            return Err(V02Error::TooLarge);
        }
        let mut ids = HashSet::new();
        for slot in &self.vmk_slots {
            slot.validate(self.mode)?;
            if slot.target != SlotTarget::Vmk || !ids.insert(slot.id) {
                return Err(V02Error::Invalid("invalid VMK header slots"));
            }
            let allowed = match self.mode {
                VaultMode::PasswordVirtual => matches!(slot.factors,
                    FactorPolicy::VaultPasswordVirtual | FactorPolicy::CodeOnly),
                VaultMode::PasswordPhysical => matches!(slot.factors,
                    FactorPolicy::VaultPasswordPhysical |
                    FactorPolicy::CodePassword | FactorPolicy::CodePhysical),
            };
            if !allowed { return Err(V02Error::Invalid("invalid vault-level route")); }
        }
        // The specification requires both hardware administrative recovery
        // ceremonies to be provisionable. Descriptors may remain PENDING,
        // which is NOT a verified recovery path and cannot unlock anything.
        let has = |factors: FactorPolicy| self.vmk_slots.iter().any(|s| s.factors == factors);
        match self.mode {
            VaultMode::PasswordVirtual if !has(FactorPolicy::VaultPasswordVirtual)
                || !has(FactorPolicy::CodeOnly) =>
                return Err(V02Error::Invalid("password-only required VMK slots missing")),
            VaultMode::PasswordPhysical if !has(FactorPolicy::VaultPasswordPhysical)
                || !has(FactorPolicy::CodePassword) || !has(FactorPolicy::CodePhysical) =>
                return Err(V02Error::Invalid("hardware recovery descriptors incomplete")),
            _ => {}
        }
        for slot in &self.bootstrap_slots {
            slot.validate(self.mode)?;
            if slot.target != SlotTarget::ProviderSeed || !ids.insert(slot.id) {
                return Err(V02Error::Invalid("invalid public bootstrap slot"));
            }
            let allowed = match self.mode {
                VaultMode::PasswordVirtual => matches!(slot.factors,
                    FactorPolicy::VaultPasswordVirtual | FactorPolicy::CodeOnly),
                VaultMode::PasswordPhysical => matches!(slot.factors,
                    FactorPolicy::VaultPasswordPhysical |
                    FactorPolicy::CodePassword | FactorPolicy::CodePhysical),
            };
            if !allowed { return Err(V02Error::Invalid("invalid bootstrap factor policy")); }
        }
        if self.mode == VaultMode::PasswordVirtual {
            let has_seed = |factor: FactorPolicy| self.bootstrap_slots.iter()
                .any(|s| s.factors == factor);
            if !has_seed(FactorPolicy::VaultPasswordVirtual)
                || !has_seed(FactorPolicy::CodeOnly) {
                return Err(V02Error::Invalid("missing pre-load seed normal/recovery slots"));
            }
        }
        // A pending route is NOT an active route. This candidate never declares
        // coverage READY; actual factor derivation, sealing and verification
        // remain V04/OPEN-01/15 work.
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryRecord {
    pub id: Uuid,
    pub revision: u64,
    pub mode: EntryMode,
    pub tier: EntryTier,
    pub recovery: RecoveryPolicy,
    pub tombstone: bool,
    pub title: String,
    pub username: String,
    pub origin: String,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>, // independently AEAD-encrypted under entry DEK
    pub dek_slots: Vec<Slot>,
}
impl EntryRecord {
    pub(super) fn validate(&self, vault_mode: VaultMode) -> Result<(), V02Error> {
        if self.id.is_nil() || self.revision == 0 {
            return Err(V02Error::Invalid("entry id/revision"));
        }
        if self.tier == EntryTier::Isolated && !self.mode.physical() {
            return Err(V02Error::Invalid("ISOLATED requires physical normal access"));
        }
        if self.title.len() > 2048 || self.username.len() > 2048 || self.origin.len() > 4096 {
            return Err(V02Error::TooLarge);
        }
        if self.tombstone {
            if !self.ciphertext.is_empty() || self.nonce != [0u8; 24]
                || !self.dek_slots.is_empty() {
                return Err(V02Error::Invalid("tombstone contains key/ciphertext"));
            }
        } else if self.ciphertext.len() < 16 || self.ciphertext.len() > MAX_ENTRY_BYTES
            || self.nonce == [0u8; 24] {
            return Err(V02Error::Invalid("entry ciphertext or nonce"));
        }
        if self.dek_slots.len() > MAX_SLOTS { return Err(V02Error::TooLarge); }
        let mut ids = HashSet::new();
        for slot in &self.dek_slots {
            slot.validate(vault_mode)?;
            if slot.target != SlotTarget::EntryDek || slot.target_id != self.id
                || !ids.insert(slot.id) {
                return Err(V02Error::Invalid("entry slot scope/duplicate"));
            }
            if self.tier == EntryTier::Isolated && !slot.factors.physical() {
                return Err(V02Error::Invalid("ISOLATED software-only DEK route"));
            }
            if self.recovery == RecoveryPolicy::StrictNone && slot.factors.is_recovery() {
                return Err(V02Error::Invalid("STRICT_NONE recovery route"));
            }
            if !slot.factors.is_recovery() && slot.factors != self.mode.normal_factor() {
                return Err(V02Error::Invalid("normal factor inconsistent with entry mode"));
            }
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRecord {
    pub id: Uuid,
    pub public_identity: [u8; 32],
    pub revoked: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultBody {
    pub vault_id: Uuid,
    pub commit_id: Uuid,
    pub generation: u64,
    pub predecessor_hash: [u8; 32],
    pub vers_slots: Vec<Slot>,
    pub provider_seed_slots: Vec<Slot>,
    pub entries: Vec<EntryRecord>,
    pub clients: Vec<ClientRecord>,
}
impl VaultBody {
    pub fn for_header(header: &PublicHeader) -> Self {
        Self { vault_id: header.vault_id, commit_id: header.commit_id,
            generation: header.generation, predecessor_hash: header.predecessor_hash,
            vers_slots: vec![], provider_seed_slots: vec![], entries: vec![], clients: vec![] }
    }
    pub(super) fn validate(&self, header: &PublicHeader) -> Result<(), V02Error> {
        if self.vault_id != header.vault_id || self.commit_id != header.commit_id
            || self.generation != header.generation
            || self.predecessor_hash != header.predecessor_hash {
            return Err(V02Error::Invalid("public/body authenticated ancestry mismatch"));
        }
        if self.entries.len() > MAX_ENTRIES || self.vers_slots.len() > MAX_SLOTS
            || self.provider_seed_slots.len() > MAX_SLOTS || self.clients.len() > MAX_CLIENTS {
            return Err(V02Error::TooLarge);
        }
        let mut ids: HashSet<Uuid> = header.vmk_slots.iter()
            .chain(header.bootstrap_slots.iter()).map(|s| s.id).collect();
        for slot in self.vers_slots.iter().chain(self.provider_seed_slots.iter()) {
            slot.validate(header.mode)?;
            if !ids.insert(slot.id) { return Err(V02Error::Invalid("duplicate secret slot")); }
        }
        if self.vers_slots.iter().any(|s| s.target != SlotTarget::Vers)
            || self.provider_seed_slots.iter().any(|s| s.target != SlotTarget::ProviderSeed) {
            return Err(V02Error::Invalid("VERS/provider slot scope"));
        }
        let mut entries = HashSet::new();
        for item in &self.entries {
            item.validate(header.mode)?;
            if !entries.insert(item.id) { return Err(V02Error::Invalid("duplicate entry id")); }
            for slot in &item.dek_slots {
                if !ids.insert(slot.id) { return Err(V02Error::Invalid("duplicate global slot id")); }
            }
        }
        let mut clients = HashSet::new();
        for client in &self.clients {
            if client.id.is_nil() || !clients.insert(client.id) {
                return Err(V02Error::Invalid("duplicate/nil client id"));
            }
        }
        Ok(())
    }
}
