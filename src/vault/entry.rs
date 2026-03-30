use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use crate::vault::error::VaultError;

pub struct VaultyEntry {
    pub entry_length: u32,
    pub wrapped_key: [u8; 48],
    pub domain_tag: String,
    pub entry_type: EntryType, //pw, passkey
    pub nonce: [u8; 24],
    pub wrapping_nonce: [u8; 24],
    pub version: u16,
    pub entry_id: Uuid,
    pub payload: Vec<u8>,
    pub target: String,
    pub is_default: bool,
    pub created_at: u64,
    pub updated_at: u64,
}

pub struct VaultAAD {
    pub entry_id: Uuid,
    pub entry_type: EntryType, //pw, passkey
    pub domain_tag: String,
    pub version: u16,
    pub vault_id: Uuid
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryType {
    Password = 1,
    Passkey = 2,
}

impl TryFrom<u8> for EntryType {
    type Error = VaultError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(EntryType::Password),
            2 => Ok(EntryType::Passkey),
            _ => Err(VaultError::ParseError),
        }
    }
}


impl VaultAAD {
    pub fn from(entry: VaultyEntry, uuid: Uuid) -> Self {
        VaultAAD {
            entry_id: entry.entry_id,
            entry_type: entry.entry_type,
            domain_tag: entry.domain_tag,
            version: entry.version,
            vault_id: uuid,
        }
    }
}

impl VaultyEntry {
    pub fn new() -> Self {
        let now: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let slf= VaultyEntry{
            entry_length: 0,
            wrapped_key: [0; 48],
            domain_tag: "".to_string(),
            entry_type: EntryType::Password,
            nonce: [0; 24],
            wrapping_nonce: [0; 24],
            version: 0x0100,
            entry_id: Uuid::new_v4(),
            payload: vec![],
            target: "".to_string(),
            is_default: true,
            created_at: now,
            updated_at: now,
        };
        return slf;
    }

    pub fn serialize(&self) -> Result<Vec<u8>, VaultError> {
        let mut data: Vec<u8> = vec![];


        return Ok(data);
    }

    pub fn deserialize(data: &Vec<u8>) -> Result<(Self, usize), VaultError> {
        let mut entry = VaultyEntry::new();
        let mut idx: usize = 0;

        return Ok((entry, idx));
    }
}