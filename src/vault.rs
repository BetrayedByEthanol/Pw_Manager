use std::path::{Path, PathBuf};
use std::fs;

use crate::crypto::{
    create_new_header, decrypt_vault,
    encrypt_vault,
    VaultHeader, VaultPayload,
};
use crate::fsutil::atomic_write_with_backup;

use uuid::Uuid;

mod schema;
mod operations;
mod session;
mod entry;
mod metadata;
mod manager;
mod error;
pub mod body;
pub mod header;

pub struct LoadedVault {
    pub header: VaultHeader,
    pub payload: VaultPayload,
    pub master_pw: String,
    pub path: PathBuf,
    pub backup_dir: PathBuf,
}

impl LoadedVault {
    pub fn load(path: &Path, master_pw: String) -> Result<Self, Box<dyn std::error::Error>> {
        let backup_dir = path.join("backups");
        let data_file = path.join("data.dat");


        if !backup_dir.exists() {
            fs::create_dir(backup_dir.to_str().unwrap()).unwrap();
        }

        if !data_file.exists(){
            let header = create_new_header();
            let payload = VaultPayload {
                vault_id: Uuid::new_v4().to_string(),
                created_at: now(),
                updated_at: now(),
                items: vec![],
            };
            let out = encrypt_vault(&master_pw, header.clone(), &payload)?;
            atomic_write_with_backup(&data_file, &backup_dir, &out)?;

            return Ok(LoadedVault {
                header,
                payload,
                master_pw,
                path: data_file.to_path_buf(),
                backup_dir,
            })
        }

        let data = fs::read(data_file.clone())?;
        let (header, payload) = decrypt_vault(&master_pw, &data)?;

        Ok(LoadedVault {
            header,
            payload,
            master_pw,
            path: data_file.to_path_buf(),
            backup_dir,
        })
    }
}

fn now() -> String {
    // Minimal ISO-like timestamp
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("T{secs}")
}