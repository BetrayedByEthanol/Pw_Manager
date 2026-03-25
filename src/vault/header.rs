use std::time::{SystemTime, UNIX_EPOCH};

use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct VaultyHeader {
    pub magic: [u8; 4],
    pub version: u16,
    pub header_len: u32,

    pub kdf: KdfSection,
    pub wrapping: WrappingSection,
    pub fido2: Option<Fido2Section>,    
    pub cipher: CipherSection,
    pub metadata: MetadataSection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KdfId {
    Argon2id = 1,
}

#[derive(Debug, Clone)]
pub struct KdfSection {
    pub version: u16,
    pub id: KdfId,
    pub salt: [u8; 16],
    pub memory_cost_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub output_len: u16,
}

#[derive(Debug, Clone)]
pub struct WrappingSection {
    pub version: u16,
    pub wrapped_master_key: [u8; 48],
    pub nonce: [u8; 24],
}


#[derive(Debug, Clone)]
pub struct Fido2Section {
    pub version: u16,
    pub credentials: Vec<Fido2Credential>,
}

#[derive(Debug, Clone)]
pub struct Fido2Credential {
    pub credential_id: Vec<u8>,
    pub rp_id: String,
    pub prf_salt: [u8; 32],   
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub hmac_secret_enabled: bool,
    pub label: Option<String>,
    pub wrapped_wrapping_key: [u8; 48],
    pub wrap_nonce: [u8; 24],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherId {
    XChaCha20Poly1305 = 1,
}

#[derive(Debug, Clone)]
pub struct CipherSection {
    pub version: u16,
    pub id: CipherId,
    pub nonce_size: u16,
    pub tag_size: u16,
}

#[derive(Debug, Clone)]
pub struct MetadataSection {
    pub version: u16,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
    pub vault_id: Uuid,
}

impl VaultyHeader {
    pub fn new() -> Self {
        let now: u64 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut slf = Self { magic: [0x56, 0x4C, 0x54, 0x31], 
            version: 0x0100, 
            header_len: 0, 
            kdf: KdfSection { 
                version: 0x0100, 
                id: KdfId::Argon2id, 
                salt: [0; 16], 
                memory_cost_kib: 65536, 
                time_cost: 3, 
                parallelism: 2, 
                output_len: 32 
            }, 
            wrapping: WrappingSection { 
                version: 0x0100, 
                wrapped_master_key: [0; 48],  
                nonce: [0; 24]
            }, 
            fido2: Some(Fido2Section {
                version: 0x0100,
                credentials: vec![]
            }), 
            cipher: CipherSection { 
                version: 0x0100, 
                id: CipherId::XChaCha20Poly1305, 
                nonce_size: 24, 
                tag_size: 16 
            }, 
            metadata: MetadataSection { 
                version: 0x0100, 
                created_at_unix: now, 
                updated_at_unix: now, 
                vault_id: Uuid::new_v4()
            } 
        };
        return slf;
        // return VaultyHeader
    }
}