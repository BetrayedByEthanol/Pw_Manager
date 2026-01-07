use std::fs::{self, File};
use std::io::{Write};
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
pub fn atomic_write_with_backup(
    vault_path: &Path,
    backup_dir: &Path,
    new_bytes: &[u8],
) -> std::io::Result<()> {

    let tmp_path = vault_path.with_extension("tmp");
    // Step 1: write tmp
    {
        let mut f = File::create(&tmp_path)?;
        f.write_all(new_bytes)?;
        f.sync_all()?;
    }

    // Step 2: backup old file if exists
    // if vault_path.exists() {
    //     fs::create_dir_all(backup_dir)?;
    //     let backup_name = format!(
    //         "vault-{}.dat",
    //         timestamp()
    //     );
    //     let backup_path = backup_dir.join(backup_name);
    //     fs::rename(vault_path, backup_path)?;
    // }

    // Step 3: rename tmp → main
    fs::rename(&tmp_path, vault_path)?;

    Ok(())
}
