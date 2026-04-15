mod kdf;
mod encryption;
mod secure_bytes;

use std::convert::TryInto;

use argon2::{Algorithm, Argon2, Params, Version};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use base64::Engine;
use base64::engine::GeneralPurpose;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::Hmac;
use secrecy::{ExposeSecret,  SecretString};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

// ---------- Header / Payload structs ----------

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KdfParams {
    pub alg: String,        // "argon2id"
    pub time: u32,          // iterations
    pub memory: u32,        // KiB
    pub parallelism: u32,   // lanes
    pub salt: String,       // base64
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CipherParams {
    pub alg: String,        // "xchacha20-poly1305"
    pub nonce: String,      // base64
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultHeader {
    pub version: u32,
    pub kdf: KdfParams,
    pub cipher: CipherParams,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultItem {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub tags: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultPayload {
    pub vault_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub items: Vec<VaultItem>,
}

// ---------- Errors ----------

#[derive(Debug)]
pub enum CryptoError {
    InvalidFormat(String),
    Crypto(String),
    Json(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidFormat(s) => write!(f, "Invalid format: {s}"),
            CryptoError::Crypto(s) => write!(f, "Crypto error: {s}"),
            CryptoError::Json(s) => write!(f, "JSON error: {s}"),
        }
    }
}

impl std::error::Error for CryptoError {}

impl From<argon2::password_hash::Error> for CryptoError {
    fn from(e: argon2::password_hash::Error) -> Self {
        CryptoError::Crypto(e.to_string())
    }
}

impl From<serde_json::Error> for CryptoError {
    fn from(e: serde_json::Error) -> Self {
        CryptoError::Json(e.to_string())
    }
}

// ---------- Helper: Argon2id KDF ----------

fn derive_key(master_password: &str, kdf: &KdfParams) -> Result<[u8; 32], CryptoError> {
    let engine = GeneralPurpose::new(&base64::alphabet::STANDARD, base64::engine::GeneralPurposeConfig::new());

    if kdf.alg.to_lowercase() != "argon2id" {
        return Err(CryptoError::InvalidFormat(format!(
            "Unsupported KDF alg: {}",
            kdf.alg
        )));
    }

    let salt_bytes = engine.decode(&kdf.salt)
        .map_err(|e| CryptoError::InvalidFormat(format!("Bad salt b64: {e}")))?;

    let params = Params::new(kdf.memory, kdf.time, kdf.parallelism, None)
        .map_err(|e| CryptoError::Crypto(format!("Bad Argon2 params: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2.hash_password_into(master_password.as_bytes(), &salt_bytes, &mut key).unwrap();

    Ok(key)
}

// ---------- Public API: create, encrypt, decrypt ----------

/// Create a fresh header with random salt + nonce and fixed KDF params.
pub fn create_new_header() -> VaultHeader {
    let engine = GeneralPurpose::new(&base64::alphabet::STANDARD, base64::engine::GeneralPurposeConfig::new());
    let mut salt_bytes = [0u8; 32];
    let mut nonce_bytes = [0u8; 24];
    OsRng.fill_bytes(&mut salt_bytes);
    OsRng.fill_bytes(&mut nonce_bytes);


    let kdf = KdfParams {
        alg: "argon2id".to_string(),
        time: 4,
        memory: 262144,
        parallelism: 2,
        salt: engine.encode(salt_bytes),
    };

    let cipher = CipherParams {
        alg: "xchacha20-poly1305".to_string(),
        nonce: engine.encode(nonce_bytes),
    };

    VaultHeader {
        version: 1,
        kdf,
        cipher,
    }
}

/// Encrypt a payload with the given master password.
/// Returns full file bytes (magic + header + ciphertext).
pub fn  encrypt_vault(
    master_password: &str,
    mut header: VaultHeader,
    payload: &VaultPayload,
) -> Result<Vec<u8>, CryptoError> {
    // If header has no nonce/salt set by caller, ensure they’re set
    // (here we assume caller uses create_new_header).
    let engine = GeneralPurpose::new(&base64::alphabet::STANDARD, base64::engine::GeneralPurposeConfig::new());

    let header_json = serde_json::to_vec(&header)?;

    // Derive key
    let mut key_bytes = derive_key(master_password, &header.kdf)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);

    // Nonce
    let nonce_bytes = engine.decode(&header.cipher.nonce)
        .map_err(|e| CryptoError::InvalidFormat(format!("Bad nonce b64: {e}")))?;
    if nonce_bytes.len() != 24 {
        return Err(CryptoError::InvalidFormat(
            "Nonce must be 24 bytes for XChaCha20".into(),
        ));
    }
    let nonce = XNonce::from_slice(&nonce_bytes);

    // Plaintext
    let plaintext = serde_json::to_vec(payload)?;

    // AAD = header JSON
    let aad = header_json.clone();

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| CryptoError::Crypto(format!("Encrypt failed: {e}")))?;

    // Zero key material
    key_bytes.zeroize();

    // Build final file: MAGIC | u16 header_len (BE) | header_json | ciphertext
    const MAGIC: &[u8; 7] = b"PVLT01\0";

    let header_len: u16 = header_json
        .len()
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat("Header too large".into()))?;

    let mut out = Vec::with_capacity(MAGIC.len() + 2 + header_json.len() + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&header_len.to_be_bytes());
    out.extend_from_slice(&header_json);
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

/// Decrypt full file bytes with master password.
/// Returns (header, payload) on success.
pub fn decrypt_vault(
    master_password: &str,
    data: &[u8],
) -> Result<(VaultHeader, VaultPayload), CryptoError> {
    const MAGIC: &[u8; 7] = b"PVLT01\0";

    if data.len() < MAGIC.len() + 2 {
        return Err(CryptoError::InvalidFormat("Data too short".into()));
    }

    if &data[..MAGIC.len()] != MAGIC {
        return Err(CryptoError::InvalidFormat(
            "Magic bytes do not match".into(),
        ));
    }

    let mut cursor = MAGIC.len();

    // header length
    let header_len_bytes: [u8; 2] = data[cursor..cursor + 2]
        .try_into()
        .map_err(|_| CryptoError::InvalidFormat("Bad header length".into()))?;
    cursor += 2;

    let header_len = u16::from_be_bytes(header_len_bytes) as usize;

    if data.len() < cursor + header_len {
        return Err(CryptoError::InvalidFormat(
            "Data truncated before header".into(),
        ));
    }

    let header_json = &data[cursor..cursor + header_len];
    cursor += header_len;

    let header: VaultHeader = serde_json::from_slice(header_json)?;

    // ciphertext
    let ciphertext = &data[cursor..];

    // Derive key
    let mut key_bytes = derive_key(master_password, &header.kdf)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);

    // Nonce
    let nonce_bytes = base64::decode(&header.cipher.nonce)
        .map_err(|e| CryptoError::InvalidFormat(format!("Bad nonce b64: {e}")))?;
    if nonce_bytes.len() != 24 {
        return Err(CryptoError::InvalidFormat(
            "Nonce must be 24 bytes for XChaCha20".into(),
        ));
    }
    let nonce = XNonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: header_json,
            },
        )
        .map_err(|e| CryptoError::Crypto(format!("Decrypt failed: {e}")))?;

    key_bytes.zeroize();

    let payload: VaultPayload = serde_json::from_slice(&plaintext)?;

    Ok((header, payload))
}

pub(crate) fn hash(pw: SecretString, m: u32, t: u32, p: u32) -> Result<([u8; 32], [u8; 32]), Box<dyn std::error::Error>> {
    let params = Params::new(m, t, p, None)
        .map_err(|e| CryptoError::Crypto(format!("Bad Argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut salt_bytes = [0u8; 32];

    OsRng.fill_bytes(&mut salt_bytes);
    let mut key = [0u8; 32];
    argon2.hash_password_into(pw.expose_secret().as_bytes(), &salt_bytes, &mut key).unwrap();
    Ok((key, salt_bytes))
}

pub(crate) fn hash_with_bytes(bytes: &[u8], m: u32, t: u32, p: u32) -> Result<([u8; 32], [u8; 32]), Box<dyn std::error::Error>> {
    let params = Params::new(m, t, p, None)
        .map_err(|e| CryptoError::Crypto(format!("Bad Argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut salt_bytes = [0u8; 32];

    OsRng.fill_bytes(&mut salt_bytes);
    let mut key = [0u8; 32];
    argon2.hash_password_into(bytes, &salt_bytes, &mut key).unwrap();
    Ok((key, salt_bytes))
}

pub(crate) fn hash_fix_salt(pw: SecretString,salt: &[u8; 32], m: u32, t: u32, p: u32) -> Result<([u8; 32]), Box<dyn std::error::Error>> {
    let params = Params::new(m, t, p, None)
        .map_err(|e| CryptoError::Crypto(format!("Bad Argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2.hash_password_into(pw.expose_secret().as_bytes(), salt, &mut key).unwrap();
    Ok((key))
}

pub(crate) fn encrypt(message: &Vec<u8>, key: &[u8; 32], nonce: &[u8; 24], aad: &Vec<u8>) -> Result<(Vec<u8>), Box<dyn std::error::Error>> {
    let nonce = XNonce::from_slice(nonce);
    let key = Key::from_slice(key);

    let cipher = XChaCha20Poly1305::new(key);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: message,
                aad: aad,
            },
        )
        .map_err(|e| CryptoError::Crypto(format!("Encrypt failed: {e}")))?;
    Ok(ciphertext)
}

pub fn decrypt(ciphertext: &Vec<u8>, key_bytes: &[u8; 32], nonce: &[u8; 24], aad: &Vec<u8>) -> Result<(Vec<u8>), Box<dyn std::error::Error>> {
    let nonce = XNonce::from_slice(nonce);
    let key = Key::from_slice(key_bytes);
    let cipher = XChaCha20Poly1305::new(key);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: aad,
            },
        )
        .map_err(|e| CryptoError::Crypto(format!("Decrypt failed: {e}")))?;

    return Ok(plaintext);
}



