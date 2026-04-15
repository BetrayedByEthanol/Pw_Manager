use std::array::TryFromSliceError;
use std::path::{Path, PathBuf};
use std::fs;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::process::{Command, Stdio};
use aes_gcm::aead::Buffer;
use argon2::password_hash::rand_core::{OsRng, RngCore};
use hmac::{Hmac, Mac, KeyInit};
use rpassword::read_password;
use crate::crypto::{
    create_new_header, decrypt_vault,
    encrypt_vault,
    VaultHeader, VaultPayload,
};
use crate::fsutil::{atomic_write, read_vault};
use secrecy::{SecretString, ExposeSecret, SecretSlice};
use serde::Serialize;
use sha2::Sha256;
use uuid::Uuid;
use uuid::Version::Random;
use hkdf::Hkdf;

use zeroize::Zeroize;
use crate::{crypto, fido2};
use crate::vault::body::VaultyBody;
use crate::vault::header::{AADHeader, Fido2Credential, VaultyHeader};
use crate::cli::prompt_yes_no;
use crate::vault::derived::VaultyDerived;
use crate::vault::entry::{VaultAAD, VaultyEntry};
use crate::vault::header::CipherId::XChaCha20Poly1305;
use crate::vault::payload::{PasswordEntry, TypeEntry};

mod schema;
mod operations;
mod session;
pub mod entry;
mod metadata;
mod manager;
mod error;
pub mod body;
pub mod header;
mod payload;
mod derived;

type HmacSha256 = Hmac<Sha256>;

pub fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn hkdf_derive(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("HKDF expand length must be <= 255 * HashLen");
    okm
}


fn prompt_pw(question: String) -> Result<SecretString, Box<dyn std::error::Error>> {
    print!("{}", question);
    let var = if question.contains("password") {"MASTER_PASSWORD"} else { "PIN" };
    if let Ok(val) = env::var(var) {
        return Ok(SecretString::from(val));
    }
    std::io::stdout().flush()?;
    match read_password() {
        Ok(pw) => Ok(SecretString::from(pw)),
        Err(e) => {
            eprintln!("\n[ERROR] Secure input unavailable: {e}");
            eprintln!("[ERROR] Aborting — refusing to prompt with echo enabled.");
            Err(e.into())
        }
    }
}
pub fn init_vault() -> Result<Vault, Box<dyn std::error::Error>> {
    let mut vh = VaultyHeader::new();

    let (master_hash, salt) = crypto::hash(prompt_pw("Master password: ".parse()?)?, vh.kdf.memory_cost_kib, vh.kdf.time_cost, vh.kdf.parallelism)?;
    vh.kdf.salt = salt;

    let mut master_key = [0u8; 32];
    OsRng.fill_bytes(&mut master_key);

    let mut wrapping_secret = [0u8; 32];
    OsRng.fill_bytes(&mut wrapping_secret);

    let mut wrapping_nonce = [0u8; 24];
    OsRng.fill_bytes(&mut wrapping_nonce);

    let mut master_nonce = [0u8; 24];
    OsRng.fill_bytes(&mut master_nonce);

    let mut fido2_device_count: u16 = 0;
    let mut fido2_devices: Vec<Fido2Credential> = vec![];

    let mut derive_input = [0u8; 32];
    OsRng.fill_bytes(&mut derive_input);

    let mut derive_master = [0u8; 32];
    OsRng.fill_bytes(&mut derive_master);

    vh.wrapping.master_nonce = master_nonce;


    while prompt_yes_no("Register Fido2 device?") {
        fido2_device_count += 1;
        let mut cred_length: usize = 170;

        let mut kdf_salt: [u8; 32] = [0u8; 32];
        OsRng.fill_bytes(&mut kdf_salt);

        let mut prf_input: [u8; 32] = [0u8; 32];
        OsRng.fill_bytes(&mut prf_input);

        let mut derive_salt: [u8; 32] = [0u8; 32];
        OsRng.fill_bytes(&mut derive_salt);

        let mut  derive_nonce: [u8; 24] = [0u8; 24];
        OsRng.fill_bytes(&mut derive_nonce);

        let mut master_wrapping_nonce = [0u8; 24];
        OsRng.fill_bytes(&mut master_wrapping_nonce);


        let pin = prompt_pw("Pin: ".parse()?)?;
        let (credential_id, rp_id,pub_key)  = fido2::ctap_register(&pin)?;


        let mut base_aad = AADHeader::from(&vh).to_aad_bytes();
        base_aad.extend_from_slice(&credential_id);
        base_aad.extend_from_slice(&rp_id.as_bytes());
        base_aad.extend_from_slice(&pub_key);


        let cred_ids = vec![credential_id.clone()];
        let pub_keys = vec![pub_key.clone()];

        let ws_prf_salt = hkdf_derive(&wrapping_secret, None, "vault-wrapping-salt-v1".as_bytes());
        let ws_hmac_key = hkdf_derive(&wrapping_secret, None, "vault-wrapping-hmac-v1".as_bytes());


        let (prf_out, verify, credential_id) = fido2::ctap_authenticate(&ws_prf_salt, &pin, cred_ids.clone(), &rp_id, pub_keys.clone())?;


        let mix = hmac_sha256(&ws_hmac_key, &prf_out);
        let kek_master = hkdf_derive(&mix, Some(&kdf_salt), "vault-master-wrap-v1".as_bytes());

        let wrapped_key = crypto::encrypt(&master_key.to_vec(), &kek_master, &master_wrapping_nonce, &base_aad)?;
        if !verify {
            println!("Authentication failed!");
            continue;
        }

        let (prf_out_derive, verify_derive, credential_id_derive) = fido2::ctap_authenticate(&prf_input, &pin, cred_ids.clone(), &rp_id, pub_keys.clone())?;

        let derive_mix = hmac_sha256(&derive_input, &prf_out_derive);

        let kek_derive = hkdf_derive(&derive_mix, Some(&derive_salt), "vault-master-derive-v1".as_bytes());

        let wrapped_derive = crypto::encrypt(&derive_master.to_vec(), &kek_derive, &derive_nonce, &base_aad )?;


        let mut  device = Fido2Credential {
            credential_length: cred_length.try_into()?,
            credential_id_length: credential_id.len().try_into()?,
            credential_id: credential_id,
            rp_id_length: rp_id.len().try_into()?,
            rp_id: rp_id,
            public_key_length: pub_key.len().try_into()?,
            public_key: pub_key,
            sign_count: 0,
            wrapped_wrapping_key: wrapped_key.as_slice().try_into()?,
            wrap_nonce: master_wrapping_nonce,
            derive_key: wrapped_derive.as_slice().try_into()?,
            derive_nonce: derive_nonce,
            kdf_salt: kdf_salt,
            prf_input: prf_input,
            derive_salt: derive_salt
        };
        cred_length = cred_length + device.credential_id_length as usize + device.rp_id_length as usize + device.public_key_length as usize;
        device.credential_length = cred_length.try_into()?;
        fido2_devices.push(device);
    }

    master_key.zeroize();

    let base_aad = AADHeader::from(&vh).to_aad_bytes();
    let wrapped_key = crypto::encrypt(&wrapping_secret.to_vec(), &master_hash, &wrapping_nonce, &base_aad )?;
    vh.wrapping.wrapped_master_key = wrapped_key.as_slice().try_into()?;
    vh.wrapping.wrapping_nonce = wrapping_nonce;
    wrapping_secret.zeroize();

    vh.fido2.credential_count = fido2_device_count;
    vh.fido2.credentials = fido2_devices;
    vh.fido2.derive_input = derive_input;
    // let (wrapp)
    let derived = VaultyDerived{ vault_secret: SecretSlice::from(derive_master.clone().to_vec()) };
    derive_master.zeroize();
    let mut vault = Vault::new(vh, derived, VaultyBody::new());

    let sealed_vault = vault.seal_vault()?;

    // let vault_data = vault.serialize()?;
    atomic_write(&sealed_vault.serialize()?)?;
    Ok(vault)

}

pub fn load_vault() -> Result<Vault, Box<dyn std::error::Error>> {
    let vault_data = read_vault()?;
    let (dvh, idx): (VaultyHeader, usize) = VaultyHeader::deserialize(&vault_data)?;
    let payload = vault_data[idx..].to_vec();
    let sealed_vault = SealedVault::new(dvh, payload);
    sealed_vault.unseal_vault()
}

pub struct Vault{
    pub header: VaultyHeader,
    pub derived: VaultyDerived<[u8]>,
    pub body: VaultyBody
}

impl Vault {
    pub fn new(header: VaultyHeader, derived:VaultyDerived<[u8]>, body: VaultyBody) -> Self {
        Vault {
            header,
            derived,
            body
        }
    }

    pub fn seal_vault(&mut self) -> Result<SealedVault, Box<dyn Error>> {
        let payload = self.body.serialize()?;
        let master_hash = crypto::hash_fix_salt(prompt_pw("Master password: ".parse()?)?, &self.header.kdf.salt , self.header.kdf.memory_cost_kib, self.header.kdf.time_cost, self.header.kdf.parallelism)?;

        let mut wrapping_secret = crypto::decrypt(&self.header.wrapping.wrapped_master_key.as_slice().try_into()?, &master_hash, &self.header.wrapping.wrapping_nonce, &AADHeader::from(&self.header).to_aad_bytes())?;
        let pin = prompt_pw("Pin: ".parse()?)?;
        let cred_ids = self.header.fido2.credentials.iter().map(|e| e.credential_id.clone()).collect::<Vec<Vec<u8>>>();
        let rp_id = self.header.fido2.credentials.get(0).unwrap().rp_id.clone();
        let pub_key = self.header.fido2.credentials.iter().map(|e| e.public_key.clone()).collect::<Vec<Vec<u8>>>();

        let ws_prf_salt = hkdf_derive(&wrapping_secret, None, "vault-wrapping-salt-v1".as_bytes());
        let ws_hmac_key = hkdf_derive(&wrapping_secret, None, "vault-wrapping-hmac-v1".as_bytes());

        let (prf_out, verify, credential_id) = fido2::ctap_authenticate(&ws_prf_salt, &pin, cred_ids.clone(), &rp_id, pub_key.clone())?;


        let mix = hmac_sha256(&ws_hmac_key, &prf_out);

        wrapping_secret.zeroize();

        let entry = self.header.fido2.credentials.iter().find(|e| e.credential_id == credential_id).unwrap();
        let mut base_aad = AADHeader::from(&self.header).to_aad_bytes();
        base_aad.extend_from_slice(&credential_id);
        base_aad.extend_from_slice(&rp_id.as_bytes());
        base_aad.extend_from_slice(&entry.public_key.clone());

        let kek_master = hkdf_derive(&mix, Some(&entry.kdf_salt), "vault-master-wrap-v1".as_bytes());
        
        let mut master_key: [u8; 32] =  crypto::decrypt(&entry.wrapped_wrapping_key.to_vec(), &kek_master, &entry.wrap_nonce, &base_aad)?.as_slice().try_into()?;
        let cipher_text = crypto::encrypt(&payload, &master_key, &self.header.wrapping.master_nonce, &AADHeader::from(&self.header).to_aad_bytes())?;
        master_key.zeroize();
        self.derived.vault_secret.zeroize();
        Ok(SealedVault::new(self.header.clone(), cipher_text))
    }


    pub fn add_entry(&mut self, is_default: bool, title: String, username: Option<String>, password: SecretString, urls: Vec<String>, notes: Option<String>) {
        let payload = PasswordEntry {
            title: title,
            username: username,
            password: password,
            urls: urls,
            notes: notes,
        };
        let mut entry_key : [u8; 32] = [0u8; 32];
        OsRng.fill_bytes(&mut entry_key);

        let mut entry_nonce: [u8; 24] = [0u8; 24];
        OsRng.fill_bytes(&mut entry_nonce);

        let mut wrapping_nonce: [u8; 24] = [0u8; 24];
        OsRng.fill_bytes(&mut wrapping_nonce);

        let domain = String::from("vaulty.com");
        let target = String::from("vaulty.com");


        let mut entry = VaultyEntry::new();
        entry.is_default = is_default;
        entry.target_length = target.len().try_into().unwrap();
        entry.target = target;
        entry.domain_tag_length = domain.len().try_into().unwrap();
        entry.domain_tag = domain;

        let (hash, salt) = if is_default {crypto::hash_with_bytes(self.derived.vault_secret.expose_secret(), self.header.kdf.memory_cost_kib, self.header.kdf.time_cost, self.header.kdf.parallelism).unwrap()} else {crypto::hash(prompt_pw("Entry Password:".parse().unwrap()).unwrap(), self.header.kdf.memory_cost_kib, self.header.kdf.time_cost, self.header.kdf.parallelism).unwrap()};
        entry.salt = salt;

        let payload_bytes = payload.serialize();
        let aad = VaultAAD::from(&entry, self.header.metadata.vault_id).to_aad_bytes();
        let encrypted_payload = crypto::encrypt(&payload_bytes, &entry_key, &entry_nonce, &aad).unwrap();

        entry.payload_length = encrypted_payload.len().try_into().unwrap();
        entry.payload = encrypted_payload;

        let wrapped_key = crypto::encrypt(&entry_key.to_vec(), &hash, &wrapping_nonce, &aad).unwrap();
        entry_key.zeroize();

        entry.wrapped_key = wrapped_key.as_slice().try_into().unwrap();
        entry.nonce = entry_nonce.as_slice().try_into().unwrap();
        entry.wrapping_nonce = wrapping_nonce.as_slice().try_into().unwrap();

        self.body.entries.push(entry);
        self.body.entries_count += 1;

    }
}

pub struct SealedVault {
    pub header: VaultyHeader,
    pub payload: Vec<u8>,
}

impl SealedVault {
    fn new(header: VaultyHeader, payload: Vec<u8>) -> Self {
        SealedVault {
            header,
            payload,
        }
    }

    fn serialize(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut buf = self.header.serialize()?;
        buf.extend_from_slice(&self.payload);
        Ok(buf)
    }

    fn deserialize(data: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let vault_data = &data.to_vec();
        let (dvh, idx): (VaultyHeader, usize) = VaultyHeader::deserialize(vault_data)?;

        Ok(Self::new(dvh, vault_data[idx..].to_vec()))
    }

    fn unseal_vault(&self) -> Result<Vault ,Box<dyn  Error>> {
        let master_hash = crypto::hash_fix_salt(prompt_pw("Master password: ".parse()?)?, &self.header.kdf.salt , self.header.kdf.memory_cost_kib, self.header.kdf.time_cost, self.header.kdf.parallelism)?;

        let mut wrapping_secret = crypto::decrypt(&self.header.wrapping.wrapped_master_key.as_slice().try_into()?, &master_hash, &self.header.wrapping.wrapping_nonce, &AADHeader::from(&self.header).to_aad_bytes())?;
        let pin = prompt_pw("Pin: ".parse()?)?;
        let cred_ids = self.header.fido2.credentials.iter().map(|e| e.credential_id.clone()).collect::<Vec<Vec<u8>>>();
        let rp_id = self.header.fido2.credentials.get(0).unwrap().rp_id.clone();
        let pub_key = self.header.fido2.credentials.iter().map(|e| e.public_key.clone()).collect::<Vec<Vec<u8>>>();

        let ws_prf_salt = hkdf_derive(&wrapping_secret, None, "vault-wrapping-salt-v1".as_bytes());
        let ws_hmac_key = hkdf_derive(&wrapping_secret, None, "vault-wrapping-hmac-v1".as_bytes());

        let (prf_out, verify, credential_id) = fido2::ctap_authenticate(&ws_prf_salt, &pin, cred_ids.clone(), &rp_id, pub_key.clone())?;


        let mix = hmac_sha256(&ws_hmac_key, &prf_out);

        wrapping_secret.zeroize();

        let entry = self.header.fido2.credentials.iter().find(|e| e.credential_id == credential_id).unwrap();
        let mut base_aad = AADHeader::from(&self.header).to_aad_bytes();
        base_aad.extend_from_slice(&credential_id);
        base_aad.extend_from_slice(&rp_id.as_bytes());
        base_aad.extend_from_slice(&entry.public_key.clone());

        let kek_master = hkdf_derive(&mix, Some(&entry.kdf_salt), "vault-master-wrap-v1".as_bytes());

        let mut master_key: [u8; 32] =  crypto::decrypt(&entry.wrapped_wrapping_key.to_vec(), &kek_master, &entry.wrap_nonce, &base_aad)?.as_slice().try_into()?;
        let cipher_text = crypto::decrypt(&self.payload, &master_key, &self.header.wrapping.master_nonce, &AADHeader::from(&self.header).to_aad_bytes())?;
        master_key.zeroize();
        println!("{:?}", cipher_text.clone());
        let (body, idx) = VaultyBody::deserialize(&cipher_text)?;


        let (prf_out_derive, derive_verify, derive_credential_id) =  fido2::ctap_authenticate(&entry.prf_input, &pin, cred_ids.clone(), &rp_id, pub_key.clone())?;
        let derive_mix = hmac_sha256(&self.header.fido2.derive_input, &prf_out_derive);

        let derive_kek = hkdf_derive(&derive_mix, Some(&entry.derive_salt), "vault-master-derive-v1".as_bytes());

        let mut derive_key = crypto::decrypt(&entry.derive_key.to_vec(), &derive_kek, &entry.derive_nonce, &base_aad)?;

        let derived = VaultyDerived{ vault_secret: SecretSlice::from(derive_key.clone()) };
        derive_key.zeroize();
        return Ok(Vault::new(self.header.clone(),derived, body));
    }

}
