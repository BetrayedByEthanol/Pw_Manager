use std::array::TryFromSliceError;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use crate::vault::error::VaultError;
use blake3::Hasher;
use crate::obfuscate::{obfuscate, unobfuscate};

#[derive(Debug, Clone)]
pub struct VaultyHeader {
    pub magic: [u8; 4],
    pub version: u16,
    pub header_len: u32, // drop for AAD

    pub kdf: KdfSection,
    pub wrapping: WrappingSection,
    pub fido2: Fido2Section,
    pub cipher: CipherSection,
    pub metadata: MetadataSection, // drop for AAD
    pub hash: [u8; 32], // drop for AAD
}

pub struct AADHeader {
    pub magic: [u8; 4],
    pub version: u16,

    pub kdf: KdfSection,
    pub cipher: CipherSection,
    pub vault_id: Uuid,
}


impl AADHeader {
    pub fn from(header: &VaultyHeader) -> Self {
        AADHeader {
            magic: header.magic.clone(),
            version: header.version.clone(),
            kdf: header.kdf.clone(),
            cipher: header.cipher.clone(),
            vault_id: header.metadata.vault_id.clone(),
        }
    }
    pub fn to_aad_bytes(&self) -> Vec<u8> {
        let mut data: Vec<u8> = vec![];
        data.extend_from_slice(&self.magic);
        data.extend_from_slice(&self.version.to_le_bytes());

        //Kdf Section
        data.extend_from_slice(&self.kdf.version.to_le_bytes());
        data.push(self.kdf.id as u8);
        data.extend_from_slice(&self.kdf.salt);
        data.extend_from_slice(&self.kdf.memory_cost_kib.to_le_bytes());
        data.extend_from_slice(&self.kdf.time_cost.to_le_bytes());
        data.extend_from_slice(&self.kdf.parallelism.to_le_bytes());

        data.extend_from_slice(&self.cipher.version.to_le_bytes());
        data.push(self.cipher.id as u8);
        data.extend_from_slice(&self.cipher.nonce_size.to_le_bytes());
        data.extend_from_slice(&self.cipher.tag_size.to_le_bytes());

        data.extend_from_slice(self.vault_id.as_bytes());
        return data;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KdfId {
    Argon2id = 1,
}

impl TryFrom<u8> for KdfId {
    type Error = VaultError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(KdfId::Argon2id),
            _ => Err(VaultError::ParseError),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KdfSection {
    pub version: u16,
    pub id: KdfId,
    pub salt: [u8; 32],
    pub memory_cost_kib: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}

#[derive(Debug, Clone)]
pub struct WrappingSection {
    pub version: u16,
    pub wrapped_master_key: [u8; 48],
    pub master_nonce: [u8; 24],
    pub wrapping_nonce: [u8; 24],
}

#[derive(Debug, Clone)]
pub struct Fido2Section {
    pub version: u16,
    pub credential_count: u16,
    pub derive_input: [u8; 32],
    pub credentials: Vec<Fido2Credential>,
}

#[derive(Debug, Clone)]
pub struct Fido2Credential {
    pub credential_length: u32,
    pub credential_id: Vec<u8>,
    pub credential_id_length: u16,
    pub rp_id_length: u16,
    pub rp_id: String,
    pub public_key_length: u16,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub derive_key: [u8; 48],
    pub derive_nonce: [u8; 24],
    pub wrapped_wrapping_key: [u8; 48],
    pub wrap_nonce: [u8; 24],
    pub kdf_salt: [u8; 32],
    pub prf_input: [u8; 32],
    pub derive_salt: [u8; 32]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherId {
    XChaCha20Poly1305 = 1,
}

impl TryFrom<u8> for CipherId {
    type Error = VaultError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(CipherId::XChaCha20Poly1305),
            _ => Err(VaultError::ParseError),
        }
    }
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
    pub fn new(now: u64) -> Self {

        let slf = Self {
            magic: [0x56, 0x4C, 0x54, 0x31],
            version: 0x0100,
            header_len: 0,
            kdf: KdfSection {
                version: 0x0100,
                id: KdfId::Argon2id,
                salt: [0; 32],
                memory_cost_kib: 65536,
                time_cost: 3,
                parallelism: 2,
            },
            wrapping: WrappingSection {
                version: 0x0100,
                wrapped_master_key: [0; 48],
                wrapping_nonce: [0; 24],
                master_nonce: [0; 24],
            },
            fido2: Fido2Section {
                version: 0x0100,
                credential_count: 0,
                derive_input: [0; 32],
                credentials: vec![],
            },
            cipher: CipherSection {
                version: 0x0100,
                id: CipherId::XChaCha20Poly1305,
                nonce_size: 24,
                tag_size: 16,
            },
            metadata: MetadataSection {
                version: 0x0100,
                created_at_unix: now,
                updated_at_unix: now,
                vault_id: Uuid::new_v4(),
            },
            hash: [0; 32],
        };
        return slf;
        // return VaultyHeader
    }

    pub fn serialize(&self) -> Result<Vec<u8>, VaultError> {
        let mut data: Vec<u8> = vec![];
        data.extend_from_slice(&self.magic);
        data.extend_from_slice(&self.version.to_le_bytes());
        let header_len_index: usize = data.len();
        data.extend_from_slice(&self.header_len.to_le_bytes());

        //Kdf Section
        data.extend_from_slice(&self.kdf.version.to_le_bytes());
        data.push(self.kdf.id as u8);
        data.extend_from_slice(&self.kdf.salt);
        data.extend_from_slice(&self.kdf.memory_cost_kib.to_le_bytes());
        data.extend_from_slice(&self.kdf.time_cost.to_le_bytes());
        data.extend_from_slice(&self.kdf.parallelism.to_le_bytes());

        //Wrapping
        data.extend_from_slice(&self.wrapping.version.to_le_bytes());
        data.extend_from_slice(&self.wrapping.wrapped_master_key);
        data.extend_from_slice(&self.wrapping.master_nonce);
        data.extend_from_slice(&self.wrapping.wrapping_nonce);

        //fido2
        data.extend_from_slice(&self.fido2.version.to_le_bytes());
        data.extend_from_slice(&self.fido2.derive_input);
        data.extend_from_slice(&self.fido2.credential_count.to_le_bytes());
        for cred in self.fido2.credentials.iter() {
            let credendial_len_index: usize = data.len();
            data.extend_from_slice(&cred.credential_length.to_le_bytes());
            let cred_id_len: u16 = cred
                .credential_id
                .len()
                .try_into()
                .map_err(|_| VaultError::TooLarge)?;
            if cred_id_len != cred.credential_id_length {
                return Err(VaultError::LengthMismatch);
            }
            data.extend_from_slice(&cred_id_len.to_le_bytes());
            data.extend(&cred.credential_id);
            let rp_id_len: u16 = cred
                .rp_id
                .len()
                .try_into()
                .map_err(|_| VaultError::TooLarge)?;
            if rp_id_len != cred.rp_id_length {
                return Err(VaultError::LengthMismatch);
            }
            data.extend_from_slice(&rp_id_len.to_le_bytes());
            data.extend(obfuscate(&cred.rp_id));
            let pub_key_len: u16 = cred
                .public_key
                .len()
                .try_into()
                .map_err(|_| VaultError::TooLarge)?;
            if pub_key_len != cred.public_key_length {
                return Err(VaultError::LengthMismatch);
            }
            data.extend_from_slice(&pub_key_len.to_le_bytes());
            data.extend(&cred.public_key);
            data.extend_from_slice(&cred.sign_count.to_le_bytes());
            data.extend(&cred.wrapped_wrapping_key);
            data.extend(&cred.wrap_nonce);

            data.extend_from_slice(&cred.derive_key);
            data.extend_from_slice(&cred.derive_nonce);
            data.extend_from_slice(&cred.kdf_salt);
            data.extend_from_slice(&cred.prf_input);
            data.extend_from_slice(&cred.derive_salt);

            //If ?
            let credential_size: u32 = (data.len() - credendial_len_index)
                .try_into()
                .map_err(|_| VaultError::TooLarge)?;
            data[credendial_len_index..credendial_len_index + 4]
                .copy_from_slice(&credential_size.to_le_bytes());

        }

        //cipher
        data.extend_from_slice(&self.cipher.version.to_le_bytes());
        data.push(self.cipher.id as u8);
        data.extend_from_slice(&self.cipher.nonce_size.to_le_bytes());
        data.extend_from_slice(&self.cipher.tag_size.to_le_bytes());

        //meta
        data.extend_from_slice(&self.metadata.version.to_le_bytes());
        data.extend_from_slice(&self.metadata.created_at_unix.to_le_bytes());
        data.extend_from_slice(&self.metadata.updated_at_unix.to_le_bytes());

        data.extend(self.metadata.vault_id.as_bytes());




        let mut header_length: u32 = data.len().try_into().map_err(|_| VaultError::TooLarge)? ;
        header_length += 32;
        //if length

        data[header_len_index..header_len_index + 4].copy_from_slice(&header_length.to_le_bytes());

        let mut hasher = Hasher::new();
        hasher.update(&data);
        let hash: [u8; 32] = hasher.finalize().into();
        println!("Hash: {:?}", hash);
        data.extend(&hash);

        return Ok(data);
    }

    pub fn deserialize(data: &Vec<u8>) -> Result<(Self, usize), Box<dyn std::error::Error>> {
        let now: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        let mut header = VaultyHeader::new(now);
        let mut idx: usize = 0;
        header.magic.copy_from_slice(&data[idx..idx + 4]);
        idx += 4;

        header.version = u16::from_le_bytes(
            data[idx..idx + 2]
                .try_into()
                .map_err(|e: TryFromSliceError| VaultError::Slice(e))?,
        );
        idx += 2;

        header.header_len = u32::from_le_bytes(
            data[idx..idx + 4]
                .try_into()
                .map_err(|e: TryFromSliceError| VaultError::Slice(e))?,
        );
        idx += 4;

        //Kdf
        let kdf_ver = u16::from_le_bytes(
            data[idx..idx + 2]
                .try_into()
                .map_err(|e: TryFromSliceError| VaultError::Slice(e))?,
        );
        idx += 2;
        let kdf_id: KdfId = KdfId::try_from(data[idx])?;
        idx += 1;
        let kdf_salt: [u8; 32] = data[idx..idx + 32]
            .try_into()
            .map_err(|e| VaultError::Slice(e))?;
        idx += 32;
        let kdf_memory = u32::from_le_bytes(
            data[idx..idx + 4]
                .try_into()
                .map_err(|e: TryFromSliceError| VaultError::Slice(e))?,
        );
        idx += 4;
        let kdf_time = u32::from_le_bytes(
            data[idx..idx + 4]
                .try_into()
                .map_err(|e: TryFromSliceError| VaultError::Slice(e))?,
        );
        idx += 4;
        let kdf_parallelism = u32::from_le_bytes(
            data[idx..idx + 4]
                .try_into()
                .map_err(|e: TryFromSliceError| VaultError::Slice(e))?,
        );
        idx += 4;

        header.kdf = KdfSection {
            version: kdf_ver,
            id: kdf_id,
            salt: kdf_salt,
            memory_cost_kib: kdf_memory,
            time_cost: kdf_time,
            parallelism: kdf_parallelism,
        };

        //Wrapping
        let wrapping_ver: u16 = u16::from_le_bytes(
            data[idx..idx + 2]
                .try_into()
                .map_err(|e: TryFromSliceError| VaultError::Slice(e))?,
        );
        idx += 2;
        let wrapping_key: [u8; 48] = data[idx..idx + 48]
            .try_into()
            .map_err(|e| VaultError::Slice(e))?;
        idx += 48;
        let nonce: [u8; 24] = data[idx..idx + 24]
            .try_into()
            .map_err(|e| VaultError::Slice(e))?;
        idx += 24;
        let wrapping_nonce: [u8; 24] = data[idx..idx + 24]
            .try_into()
            .map_err(|e| VaultError::Slice(e))?;
        idx += 24;

        header.wrapping = WrappingSection {
            version: wrapping_ver,
            wrapped_master_key: wrapping_key,
            wrapping_nonce: wrapping_nonce,
            master_nonce: nonce,
        };

        //Fido2
        let fido_ver: u16 = u16::from_le_bytes(
            data[idx..idx + 2]
                .try_into()
                .map_err(|e: TryFromSliceError| VaultError::Slice(e))?,
        );
        idx += 2;
        let derive_input: [u8; 32] = data[idx..idx+32].try_into().map_err(|e| VaultError::Slice(e))?;
        idx += 32;

        let fido_count: u16 = u16::from_le_bytes(
            data[idx..idx + 2]
                .try_into()
                .map_err(|e: TryFromSliceError| VaultError::Slice(e))?,
        );
        idx += 2;
        let mut fido_creds: Vec<Fido2Credential> = vec![];
        for _ in 0..fido_count {
            let cred_length = u32::from_le_bytes(
                data[idx..idx + 4]
                    .try_into()
                    .map_err(|e: TryFromSliceError| VaultError::Slice(e))?,
            );
            idx += 4;
            let cred_id_len: u16 = u16::from_le_bytes(
                data[idx..idx + 2]
                    .try_into()
                    .map_err(|e: TryFromSliceError| VaultError::Slice(e))?,
            );
            idx += 2;
            let cred_id: Vec<u8> = data[idx..idx + usize::from(cred_id_len)].to_vec();
            idx += usize::from(cred_id_len);
            let rp_len: u16 = u16::from_le_bytes(
                data[idx..idx + 2]
                    .try_into()
                    .map_err(|e: TryFromSliceError| VaultError::Slice(e))?,
            );
            idx += 2;
            let rp_id = unobfuscate(&data[idx..idx + usize::from(rp_len)].to_vec())?;
                // .map_err(|_| VaultError::ParseError)?;

            idx += usize::from(rp_len);
            // let prf: [u8; 32] = data[idx..idx + 32]
            //     .try_into()
            //     .map_err(|e| VaultError::Slice(e))?;
            // idx += 32;
            let pub_key_len: u16 = u16::from_le_bytes(
                data[idx..idx + 2]
                    .try_into()
                    .map_err(|e: TryFromSliceError| VaultError::Slice(e))?,
            );
            idx += 2;
            let pub_key: Vec<u8> = data[idx..idx + usize::from(pub_key_len)].to_vec();
            idx += usize::from(pub_key_len);
            let sign_count = u32::from_le_bytes(
                data[idx..idx + 4]
                    .try_into()
                    .map_err(|e: TryFromSliceError| VaultError::Slice(e))?,
            );
            idx += 4;
            let fido_wrapping: [u8; 48] = data[idx..idx + 48]
                .try_into()
                .map_err(|e| VaultError::Slice(e))?;
            idx += 48;
            let fido_nonce: [u8; 24] = data[idx..idx + 24]
                .try_into()
                .map_err(|e| VaultError::Slice(e))?;
            idx += 24;
            let derive_key: [u8; 48] = data[idx..idx+48].try_into().map_err(|e| VaultError::Slice(e))?;
            idx += 48;
            let derive_nonce: [u8; 24] = data[idx..idx+24].try_into().map_err(|e| VaultError::Slice(e))?;
            idx += 24;
            let kdf_salt: [u8; 32] = data[idx..idx+32].try_into().map_err(|e| VaultError::Slice(e))?;
            idx += 32;
            let prf_input: [u8; 32] = data[idx..idx+32].try_into().map_err(|e| VaultError::Slice(e))?;
            idx += 32;
            let derive_salt: [u8; 32] = data[idx..idx+32].try_into().map_err(|e| VaultError::Slice(e))?;
            idx += 32;

            fido_creds.push(Fido2Credential {
                credential_length: cred_length,
                credential_id: cred_id,
                credential_id_length: cred_id_len,
                rp_id_length: rp_len,
                rp_id: rp_id,
                public_key_length: pub_key_len,
                public_key: pub_key,
                sign_count: sign_count,
                wrapped_wrapping_key: fido_wrapping,
                wrap_nonce: fido_nonce,
                derive_key: derive_key,
                derive_nonce: derive_nonce,
                kdf_salt: kdf_salt,
                prf_input: prf_input,
                derive_salt: derive_salt
            });
        }

        header.fido2 = Fido2Section {
            version: fido_ver,
            derive_input: derive_input,
            credential_count: fido_count,
            credentials: fido_creds,
        };

        //Cipher
        let cipher_ver = u16::from_le_bytes(
            data[idx..idx + 2]
                .try_into()
                .map_err(|e: TryFromSliceError| VaultError::Slice(e))?,
        );
        idx += 2;
        let cipher_id: CipherId = CipherId::try_from(data[idx])?;
        idx += 1;
        let cipher_nonce = u16::from_le_bytes(
            data[idx..idx + 2]
                .try_into()
                .map_err(|e: TryFromSliceError| VaultError::Slice(e))?,
        );
        idx += 2;
        let cipher_tag = u16::from_le_bytes(
            data[idx..idx + 2]
                .try_into()
                .map_err(|e: TryFromSliceError| VaultError::Slice(e))?,
        );
        idx += 2;

        header.cipher = CipherSection {
            version: cipher_ver,
            id: cipher_id,
            nonce_size: cipher_nonce,
            tag_size: cipher_tag,
        };

        //Meta
        let meta_ver = u16::from_le_bytes(
            data[idx..idx + 2]
                .try_into()
                .map_err(|e: TryFromSliceError| VaultError::Slice(e))?,
        );
        idx += 2;
        let meta_create = u64::from_le_bytes(
            data[idx..idx + 8]
                .try_into()
                .map_err(|e: TryFromSliceError| VaultError::Slice(e))?,
        );
        idx += 8;
        let meta_update = u64::from_le_bytes(
            data[idx..idx + 8]
                .try_into()
                .map_err(|e: TryFromSliceError| VaultError::Slice(e))?,
        );
        idx += 8;

        let vault_id = Uuid::from_bytes(
            data[idx..idx + 16]
                .try_into()
                .map_err(|e| VaultError::Slice(e))?,
        );
        idx += 16;

        header.metadata = MetadataSection {
            version: meta_ver,
            created_at_unix: meta_create,
            updated_at_unix: meta_update,
            vault_id: vault_id,
        };
        let vault_hash: [u8; 32] = data[idx..idx + 32].try_into().map_err(|e| VaultError::Slice(e))?;
        header.hash = vault_hash;
        let actual: [u8; 32] = blake3::hash(&data[0..idx].to_vec()).into();
        println!("{:?}", actual);
        println!("{:?}", vault_hash);
        idx += 32;

        return Ok((header, idx));
    }
}
