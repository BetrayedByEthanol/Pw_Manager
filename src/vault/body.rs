use std::error::Error;
use uuid::Uuid;
use crate::vault::error::VaultError;
use crate::vault::entry::{EntryType, VaultyEntry};
use crate::vault::payload::PasswordEntry;

pub struct VaultyBody {
    version: u16,
    pub(crate) entries_count: u16,
    pub(crate) entries: Vec<VaultyEntry>,
    pub(crate) authorized_clients_count: u16,
    pub(crate) authorized_clients: Vec<u8>,
}

impl VaultyBody {
    pub fn new() -> Self {
        Self {
            version: 0x0100,
            entries_count: 0,
            entries: vec![],
            authorized_clients_count: 0,
            authorized_clients: vec![],
        }
    }


    pub fn serialize(&self) -> Result<Vec<u8>, VaultError> {
        let mut data: Vec<u8> = vec![];
        data.extend_from_slice(&self.version.to_le_bytes());
        data.extend_from_slice(&self.entries_count.to_le_bytes());
        for entry in self.entries.iter() {
            let entry_data = entry.serialize()?;
            data.extend(&entry_data);
        }
        data.extend_from_slice(&self.authorized_clients_count.to_le_bytes());
        data.extend(&self.authorized_clients);
        return Ok(data);
    }
    pub fn deserialize(data: &Vec<u8>) -> Result<(Self, usize), Box<dyn Error>> {
        let mut body = VaultyBody::new();
        let mut idx: usize = 0;
        body.version = u16::from_le_bytes(data[idx..idx + 2].try_into()?);
        idx += 2;
        body.entries_count = u16::from_le_bytes(data[idx..idx + 2].try_into()?);
        idx += 2;
        let mut entries: Vec<VaultyEntry> = vec![];
        for _ in 0..body.entries_count {
            let entry_len: u32 = u32::from_le_bytes(data[idx..idx + 4].try_into()?);
            idx += 4;
            let wrapped_key: [u8; 48] = data[idx..idx + 48].try_into()?;
            idx += 48;
            let wrapping_nonce: [u8; 24] = data[idx..idx + 24].try_into()?;
            idx += 24;
            let domain_tag_len: u16 = u16::from_le_bytes(data[idx..idx + 2].try_into()?);
            idx += 2;
            let domain_tag = String::from_utf8(data[idx..idx + usize::from(domain_tag_len)].to_vec())?;
            idx += usize::from(domain_tag_len);
            let nonce: [u8; 24] = data[idx..idx + 24].try_into()?;
            idx += 24;
            let salt: [u8; 32] = data[idx..idx + 32].try_into()?;
            idx += 32;
            let entry_type = EntryType::try_from(data[idx])?;
            idx += 1;
            let version: u16 = u16::from_le_bytes(data[idx..idx + 2].try_into()?);
            idx += 2;
            let entry_id: Uuid = Uuid::from_bytes(data[idx..idx+16].try_into()?);
            idx += 16;
            let payload_len: u16 = u16::from_le_bytes(data[idx..idx + 2].try_into()?);
            idx += 2;
            let payload: Vec<u8> = data[idx..idx + usize::from(payload_len)].to_vec();
            idx += usize::from(payload_len);
            let target_len: u16 = u16::from_le_bytes(data[idx..idx + 2].try_into()?);
            idx += 2;
            let target = String::from_utf8(data[idx..idx + usize::from(target_len)].to_vec())?;
            idx += usize::from(target_len);
            let is_default: bool = data[idx] != 0;
            idx += 1;
            let created_at: u64 = u64::from_le_bytes(data[idx..idx + 8].try_into()?);
            idx += 8;
            let updated_at: u64 = u64::from_le_bytes(data[idx..idx + 8].try_into()?);
            idx += 8;

            let entry = VaultyEntry {
                entry_length: entry_len,
                wrapped_key: wrapped_key,
                domain_tag: domain_tag,
                domain_tag_length: domain_tag_len,
                entry_type: entry_type,
                nonce: nonce,
                salt: salt,
                wrapping_nonce: wrapping_nonce,
                version: version,
                entry_id: entry_id,
                payload: payload,
                payload_length: payload_len,
                target: target,
                target_length: target_len,
                is_default: is_default,
                created_at: created_at,
                updated_at: updated_at,
            };
            entries.push(entry);
        }
        body.entries = entries;
        body.authorized_clients_count = u16::from_le_bytes(data[idx..idx + 2].try_into()?);
        idx += 2;
        for _ in 0..body.authorized_clients_count {

        }
        let authorized_clients: Vec<u8> = vec![];
        body.authorized_clients = authorized_clients;

        return Ok((body, idx));
    }
}