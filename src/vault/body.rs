//! Bounded, strict decoder for the legacy body. No trusted-client policy yet.
use std::error::Error;
use uuid::Uuid;
use crate::vault::error::VaultError;
use crate::vault::entry::{EntryType, VaultyEntry};

pub struct VaultyBody {
    version: u16,
    pub(crate) entries_count: u16,
    pub(crate) entries: Vec<VaultyEntry>,
    pub(crate) authorized_clients_count: u16,
    pub(crate) authorized_clients: Vec<u8>,
}

fn read<const N: usize>(data: &[u8], at: &mut usize) -> Result<[u8; N], VaultError> {
    let end = at.checked_add(N).ok_or(VaultError::TooLarge)?;
    let slice = data.get(*at..end).ok_or(VaultError::ParseError)?;
    *at = end;
    slice.try_into().map_err(VaultError::Slice)
}
fn read_segment<'a>(data: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], VaultError> {
    let end = at.checked_add(n).ok_or(VaultError::TooLarge)?;
    let slice = data.get(*at..end).ok_or(VaultError::ParseError)?;
    *at = end;
    Ok(slice)
}

impl VaultyBody {
    pub fn new() -> Self {
        Self { version: 0x0100, entries_count: 0, entries: vec![],
               authorized_clients_count: 0, authorized_clients: vec![] }
    }
    pub fn serialize(&self) -> Result<Vec<u8>, VaultError> {
        // Derive counts from the vectors; never persist a stale mutable count.
        let count: u16 = self.entries.len().try_into().map_err(|_| VaultError::TooLarge)?;
        if self.authorized_clients_count != 0 || !self.authorized_clients.is_empty() {
            return Err(VaultError::ParseError); // legacy registry encoding is not defined
        }
        let mut data = Vec::new();
        data.extend_from_slice(&self.version.to_le_bytes());
        data.extend_from_slice(&count.to_le_bytes());
        for entry in &self.entries { data.extend_from_slice(&entry.serialize()?); }
        data.extend_from_slice(&0u16.to_le_bytes()); // no clients supported in V01
        Ok(data)
    }
    pub fn deserialize(data: &Vec<u8>) -> Result<(Self, usize), Box<dyn Error>> {
        let mut at = 0usize;
        let version = u16::from_le_bytes(read::<2>(data, &mut at)?);
        if version != 0x0100 { return Err(VaultError::ParseError.into()); }
        let count = u16::from_le_bytes(read::<2>(data, &mut at)?);
        // Entries have a minimum encoded size; bound counts before allocating.
        if count as usize > data.len() / 100 { return Err(VaultError::ParseError.into()); }
        let mut entries = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let start = at;
            let entry_len = u32::from_le_bytes(read::<4>(data, &mut at)?);
            let wrapped_key = read::<48>(data, &mut at)?;
            let wrapping_nonce = read::<24>(data, &mut at)?;
            let domain_tag_len = u16::from_le_bytes(read::<2>(data, &mut at)?);
            let domain_tag = String::from_utf8(read_segment(data, &mut at, domain_tag_len as usize)?.to_vec())?;
            let nonce = read::<24>(data, &mut at)?;
            let salt = read::<32>(data, &mut at)?;
            let entry_type = EntryType::try_from(read::<1>(data, &mut at)?[0])?;
            let version = u16::from_le_bytes(read::<2>(data, &mut at)?);
            if version != 0x0100 { return Err(VaultError::ParseError.into()); }
            let entry_id = Uuid::from_bytes(read::<16>(data, &mut at)?);
            let payload_len = u16::from_le_bytes(read::<2>(data, &mut at)?);
            let payload = read_segment(data, &mut at, payload_len as usize)?.to_vec();
            let target_len = u16::from_le_bytes(read::<2>(data, &mut at)?);
            let target = String::from_utf8(read_segment(data, &mut at, target_len as usize)?.to_vec())?;
            let flag = read::<1>(data, &mut at)?[0];
            if flag > 1 { return Err(VaultError::ParseError.into()); }
            let created_at = u64::from_le_bytes(read::<8>(data, &mut at)?);
            let updated_at = u64::from_le_bytes(read::<8>(data, &mut at)?);
            if at - start != entry_len as usize { return Err(VaultError::LengthMismatch.into()); }
            entries.push(VaultyEntry {
                entry_length: entry_len, wrapped_key, wrapping_nonce,
                domain_tag_length: domain_tag_len, domain_tag, entry_type,
                nonce, salt, version, entry_id, payload_length: payload_len,
                payload, target_length: target_len, target, is_default: flag == 1,
                created_at, updated_at
            });
        }
        let client_count = u16::from_le_bytes(read::<2>(data, &mut at)?);
        // The old format has no length-delimited client records: never silently
        // discard them and never treat unknown client bytes as authorized.
        if client_count != 0 || at != data.len() { return Err(VaultError::ParseError.into()); }
        Ok((Self {
            version, entries_count: count, entries,
            authorized_clients_count: 0, authorized_clients: Vec::new(),
        }, at))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deletion_round_trip_count_is_derived() {
        let mut body = VaultyBody::new();
        body.entries.push(VaultyEntry::new(0));
        body.entries.push(VaultyEntry::new(1));
        body.entries_count = 99; // stale state is not serialized
        let raw = body.serialize().unwrap();
        let (mut restored, n) = VaultyBody::deserialize(&raw).unwrap();
        assert_eq!(n, raw.len());
        assert_eq!(restored.entries.len(), 2);
        restored.entries.remove(0);
        let raw = restored.serialize().unwrap();
        let (loaded, _) = VaultyBody::deserialize(&raw).unwrap();
        assert_eq!(loaded.entries_count, 1);
    }
    #[test]
    fn truncated_and_extra_bytes_are_rejected() {
        let body = VaultyBody::new();
        let mut raw = body.serialize().unwrap();
        for size in 0..raw.len() {
            assert!(VaultyBody::deserialize(&raw[..size].to_vec()).is_err());
        }
        raw.push(1);
        assert!(VaultyBody::deserialize(&raw).is_err());
    }
    #[test]
    fn unknown_client_registry_is_rejected() {
        let mut raw = VaultyBody::new().serialize().unwrap();
        raw[4] = 1;
        assert!(VaultyBody::deserialize(&raw).is_err());
    }
}
