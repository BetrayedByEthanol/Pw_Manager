use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Timestamp for backup filename
fn timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("{}", secs)
}

/// Atomic write:
/// 1) write temp file
/// 2) fsync temp
/// 3) rename old → backup (optional)
/// 4) rename temp → actual
pub fn atomic_write(
    new_bytes: &Vec<u8>,
) -> std::io::Result<()> {
    let exe_path = env::current_exe().expect("Failed to get executable path");
    let vault_path = exe_path.parent().unwrap().join("vault");
    let tmp_path = vault_path.with_extension("tmp");
    {
        let mut f = File::create(&tmp_path)?;
        f.write_all(new_bytes)?;
        f.sync_all()?;
    }

    fs::rename(&tmp_path, vault_path)?;

    Ok(())
}

pub fn vault_exists() -> bool {
    let exe_path = env::current_exe().expect("Failed to get executable path");
    let vault_path = exe_path.parent().unwrap().join("vault");
    vault_path.exists()
}

pub fn read_vault() -> std::io::Result<Vec<u8>> {
    let exe_path = env::current_exe().expect("Failed to get executable path");
    let vault_path = exe_path.parent().unwrap().join("vault");
    let mut f = File::open(&vault_path)?;
    let mut contents = Vec::new();
    f.read_to_end(&mut contents)?;
    Ok(contents)
}