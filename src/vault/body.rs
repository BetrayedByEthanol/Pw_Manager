use crate::vault::error::VaultError;
use crate::vault::entry::VaultyEntry;

pub struct VaultyBody {
    version: u16,
    entries_count: u16,
    entries: Vec<VaultyEntry>,
    authorized_clients_count: u16,
    authorized_clients: Vec<u8>,
}

impl VaultyBody {
    pub fn new() -> Self {
        Self {
            version: 0,
            entries_count: 0,
            entries: vec![],
            authorized_clients_count: 0,
            authorized_clients: vec![],
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, VaultError> {
        return Ok(vec![]);
    }
    pub fn deserialize(&self, data: &Vec<u8>) -> Result<(Self, usize), VaultError> {
        return Ok((Self::new(), 0));
    }
}