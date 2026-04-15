use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;
use crate::vault::error::VaultError;
use crate::vault::payload::{PasswordEntry, TypeEntry};

pub struct VaultyEntry {
    pub entry_length: u32,
    pub wrapped_key: [u8; 48],
    pub domain_tag: String,
    pub domain_tag_length: u16,
    pub entry_type: EntryType, //pw, passkey
    pub nonce: [u8; 24], // nonce for wrapping payload
    pub salt: [u8; 32],
    pub wrapping_nonce: [u8; 24], // nonce for wrapping key
    pub version: u16,
    pub entry_id: Uuid,
    pub payload: Vec<u8>,
    pub payload_length: u16,
    pub target: String,
    pub target_length: u16,
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

impl VaultAAD {
    pub(crate) fn to_aad_bytes(&self) -> Vec<u8> {
        return vec![];
    }
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
    pub fn from(entry: &VaultyEntry, uuid: Uuid) -> Self {
        VaultAAD {
            entry_id: entry.entry_id,
            entry_type: entry.entry_type,
            domain_tag: entry.domain_tag.clone(),
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
            domain_tag_length: 0,
            entry_type: EntryType::Password,
            nonce: [0; 24],
            salt: [0; 32],
            wrapping_nonce: [0; 24],
            version: 0x0100,
            entry_id: Uuid::new_v4(),
            payload: vec![],
            payload_length: 0,
            target: "".to_string(),
            target_length: 0,
            is_default: true,
            created_at: now,
            updated_at: now,
        };
        return slf;
    }

    pub fn get_entry(&self, password: &SecretString) -> Rc<dyn TypeEntry> {
        Rc::new(PasswordEntry {
            title: "".to_string(),
            username: None,
            password: SecretString::from(String::from("asdasd")),
            urls: vec![],
            notes: None,
        })
    }

    pub fn print_entry(&self) {
        let entry = self.get_entry(&SecretString::from(String::from("adas")));
        let cast_entry = entry.as_any().downcast_ref::<PasswordEntry>().unwrap();
        println!("{:}",cast_entry.password.expose_secret());
    }

    pub fn set_entry(&mut self, title: String, username: String, password: SecretString, url: String) {

    }

    pub fn serialize(&self) -> Result<Vec<u8>, VaultError> {
        let mut data: Vec<u8> = vec![];
        data.extend_from_slice(&self.entry_length.to_le_bytes());
        data.extend_from_slice(&self.wrapped_key);
        data.extend_from_slice(&self.wrapping_nonce);
        data.extend_from_slice(&self.domain_tag_length.to_le_bytes());
        if self.domain_tag.len() != usize::from(self.domain_tag_length) {
            panic!("Serialized domain tag length does not match domain tag length");
        }
        data.extend_from_slice(self.domain_tag.as_bytes());
        data.extend_from_slice(&self.nonce);
        data.extend_from_slice(&self.salt);
        data.push(self.entry_type as u8);
        data.extend_from_slice(&self.version.to_le_bytes());
        data.extend_from_slice(self.entry_id.as_bytes());
        data.extend_from_slice(&self.payload_length.to_le_bytes());
        if self.payload.len() != usize::from(self.payload_length) {
            panic!("Serialized payload length does not match payload length");
        }
        data.extend(&self.payload);
        data.extend_from_slice(&self.target_length.to_le_bytes());
        data.extend_from_slice(self.target.as_bytes());
        data.push(if self.is_default { 1 } else { 0 });
        data.extend_from_slice(&self.created_at.to_le_bytes());
        data.extend_from_slice(&self.updated_at.to_le_bytes());
        if data.len() != self.entry_length as usize {
            panic!("Serialized entry length does not match entry length");
        }
        return Ok(data);
    }

    pub fn deserialize(data: &Vec<u8>) -> Result<(Self, usize), VaultError> {
        let mut entry = VaultyEntry::new();
        let mut idx: usize = 0;

        return Ok((entry, idx));
    }
}