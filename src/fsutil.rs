use std::env;
use std::error::Error;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Timestamp for backup filename
fn timestamp() -> Result<String , Box<dyn std::error::Error>> {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();
    Ok(format!("{}", secs))
}

/// Atomic write:
/// 1) write temp file
/// 2) fsync temp
/// 3) rename old → backup (optional)
/// 4) rename temp → actual
pub fn atomic_write(new_bytes: &Vec<u8>) -> Result<(), Box<dyn Error>> {
    let exe_path = env::current_exe()?;
    let vault_path = exe_path.parent().ok_or("Could not open parent")?.join("vault");
    let tmp_path = vault_path.with_extension("tmp");
    {
        let mut f = File::create(&tmp_path)?;
        f.write_all(new_bytes)?;
        f.sync_all()?;
    }

    fs::rename(&tmp_path, vault_path)?;

    Ok(())
}

pub fn vault_exists() -> Result<bool, Box<dyn Error>> {
    let exe_path = env::current_exe()?;
    let vault_path = exe_path.parent().ok_or("Could not open parent")?.join("vault");
    Ok(vault_path.exists())
}

pub fn read_vault() -> Result<Vec<u8>, Box<dyn Error>> {
    let exe_path = env::current_exe()?;
    let vault_path = exe_path.parent().ok_or("Could not open parent")?.join("vault");
    let mut f = File::open(&vault_path)?;
    let mut contents = Vec::new();
    f.read_to_end(&mut contents)?;
    Ok(contents)
}