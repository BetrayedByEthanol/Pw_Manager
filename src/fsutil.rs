//! V01 filesystem safety baseline for the legacy vault format.
//! The canonical v0.4.5 format, ancestry, and migration are future work.
use std::env;
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::os::unix::fs::OpenOptionsExt;
use uuid::Uuid;

const MAX_VAULT_BYTES: u64 = 128 * 1024 * 1024;

fn vault_path() -> Result<PathBuf, Box<dyn Error>> {
    let exe_path = env::current_exe()?;
    Ok(exe_path.parent().ok_or("missing executable parent")?.join("vault"))
}

struct Guard(PathBuf);
impl Drop for Guard {
    fn drop(&mut self) { let _ = fs::remove_file(&self.0); }
}

fn sync_dir(dir: &Path) -> Result<(), Box<dyn Error>> {
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Serialize a complete new file and atomically replace the active path.
/// A durable previous-version snapshot is created before replacement.
/// Exclusive lock file prevents simultaneous writers; stale crash locks
/// require deliberate operator recovery rather than unsafe auto-removal.
pub fn atomic_write_at(path: &Path, new_bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    if new_bytes.is_empty() || new_bytes.len() as u64 > MAX_VAULT_BYTES {
        return Err("invalid vault size".into());
    }
    let dir = path.parent().ok_or("missing vault directory")?;
    let lock_path = path.with_extension("lock");
    let _lock_file = OpenOptions::new().write(true).create_new(true)
        .mode(0o600).open(&lock_path)?;
    let _guard = Guard(lock_path);

    let tmp_path = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let result = (|| -> Result<(), Box<dyn Error>> {
        let mut tmp = OpenOptions::new().write(true).create_new(true)
            .mode(0o600).open(&tmp_path)?;
        tmp.write_all(new_bytes)?;
        tmp.sync_all()?;

        if let Ok(meta) = fs::symlink_metadata(path) {
            if !meta.file_type().is_file() || meta.file_type().is_symlink() {
                return Err("refusing to replace a non-regular or symlinked vault".into());
            }
        }
        if path.exists() {
            // Keep the old encrypted bytes recoverable even if replacement fails.
            let backup_tmp = path.with_extension(format!("previous-tmp-{}", Uuid::new_v4()));
            let backup_result = (|| -> Result<(), Box<dyn Error>> {
                let mut source = File::open(path)?;
                let mut backup = OpenOptions::new().write(true).create_new(true)
                    .mode(0o600).open(&backup_tmp)?;
                std::io::copy(&mut source, &mut backup)?;
                backup.sync_all()?;
                fs::rename(&backup_tmp, path.with_extension("previous"))?;
                sync_dir(dir)?;
                Ok(())
            })();
            if backup_result.is_err() { let _ = fs::remove_file(&backup_tmp); }
            backup_result?;
        }

        fs::rename(&tmp_path, path)?;
        sync_dir(dir)?;
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_file(&tmp_path); }
    result
}

pub fn atomic_write(new_bytes: &Vec<u8>) -> Result<(), Box<dyn Error>> {
    atomic_write_at(&vault_path()?, new_bytes)
}

pub fn vault_exists() -> Result<bool, Box<dyn Error>> {
    Ok(vault_path()?.exists())
}

pub fn read_vault() -> Result<Vec<u8>, Box<dyn Error>> {
    let path = vault_path()?;
    let mut file = File::open(path)?;
    if file.metadata()?.len() > MAX_VAULT_BYTES {
        return Err("vault file exceeds maximum size".into());
    }
    let mut data = Vec::new();
    file.take(MAX_VAULT_BYTES + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_VAULT_BYTES {
        return Err("vault file exceeds maximum size".into());
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn atomic_replace_keeps_previous() {
        let dir = std::env::temp_dir().join(format!("vaulty-v01-{}", Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("vault");
        atomic_write_at(&path, b"first").unwrap();
        atomic_write_at(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        assert_eq!(fs::read(path.with_extension("previous")).unwrap(), b"first");
        assert!(!path.with_extension("lock").exists());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn existing_lock_rejects_write_without_modifying_vault() {
        let dir = std::env::temp_dir().join(format!("vaulty-v01-lock-{}", Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("vault");
        atomic_write_at(&path, b"first").unwrap();
        File::create(path.with_extension("lock")).unwrap();
        assert!(atomic_write_at(&path, b"second").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"first");
        fs::remove_dir_all(dir).unwrap();
    }
}
