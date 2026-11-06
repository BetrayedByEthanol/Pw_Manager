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

/// V01-A checkpoints are test-only injection points, never a runtime configuration.
/// A failed operation after rename is an ambiguous commit: inspect active/previous
/// files instead of automatically retrying or claiming that no write occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteCheckpoint {
    AfterTempSync,
    BeforeBackupRename,
    AfterBackupSync,
    BeforeActiveRename,
    AfterActiveRename,
    AfterParentSync,
}

fn validate_existing_regular_file(path: &Path) -> Result<bool, Box<dyn Error>> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() && !meta.file_type().is_symlink() => {
            if meta.len() > MAX_VAULT_BYTES { return Err("existing vault is too large".into()); }
            Ok(true)
        }
        Ok(_) => Err("refusing non-regular or symlinked vault path".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn atomic_write_with_checkpoint<F>(
    path: &Path, new_bytes: &[u8], mut check: F
) -> Result<(), Box<dyn Error>>
where F: FnMut(WriteCheckpoint) -> Result<(), Box<dyn Error>>,
{
    if new_bytes.is_empty() || new_bytes.len() as u64 > MAX_VAULT_BYTES {
        return Err("invalid vault size".into());
    }
    let dir = path.parent().ok_or("missing vault directory")?;
    let dir_meta = fs::symlink_metadata(dir)?;
    if !dir_meta.file_type().is_dir() || dir_meta.file_type().is_symlink() {
        return Err("refusing a non-directory or symlinked vault parent".into());
    }
    // The owner must recover a stale lock explicitly after verifying no writer
    // is live. Never silently steal an existing lock.
    let lock_path = path.with_extension("lock");
    let _lock_file = OpenOptions::new().write(true).create_new(true)
        .mode(0o600).open(&lock_path)?;
    let _guard = Guard(lock_path);

    let tmp_path = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let result = (|| -> Result<(), Box<dyn Error>> {
        let exists = validate_existing_regular_file(path)?;
        let mut tmp = OpenOptions::new().write(true).create_new(true)
            .mode(0o600).open(&tmp_path)?;
        tmp.write_all(new_bytes)?;
        tmp.sync_all()?;
        check(WriteCheckpoint::AfterTempSync)?;

        if exists {
            // The previous active generation is durable BEFORE replacing it.
            // V01 retains one history copy; V02 replaces this with authenticated
            // ancestry, verified reopening and a protected backup inventory.
            let backup_tmp = path.with_extension(format!("previous-tmp-{}", Uuid::new_v4()));
            let backup_result = (|| -> Result<(), Box<dyn Error>> {
                // Do not follow a path replaced with a symlink since the first
                // check. This is not race-free openat/O_NOFOLLOW protection.
                validate_existing_regular_file(path)?.then_some(())
                    .ok_or("active vault disappeared before backup")?;
                let mut source = File::open(path)?;
                let mut backup = OpenOptions::new().write(true).create_new(true)
                    .mode(0o600).open(&backup_tmp)?;
                let copied = std::io::copy(&mut source, &mut backup)?;
                if copied > MAX_VAULT_BYTES { return Err("backup source too large".into()); }
                backup.sync_all()?;
                check(WriteCheckpoint::BeforeBackupRename)?;
                fs::rename(&backup_tmp, path.with_extension("previous"))?;
                sync_dir(dir)?;
                check(WriteCheckpoint::AfterBackupSync)?;
                Ok(())
            })();
            if backup_result.is_err() { let _ = fs::remove_file(&backup_tmp); }
            backup_result?;
        }

        // An attacker with write access to the containing directory can still
        // race replacement; the canonical V02 writer must use dirfd/openat.
        if exists && !validate_existing_regular_file(path)? {
            return Err("active vault disappeared before commit".into());
        }
        check(WriteCheckpoint::BeforeActiveRename)?;
        fs::rename(&tmp_path, path)?;
        check(WriteCheckpoint::AfterActiveRename)?;
        sync_dir(dir)?;
        check(WriteCheckpoint::AfterParentSync)?;
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_file(&tmp_path); }
    result
}

/// Performs one bounded atomic replacement with a durable previous generation.
/// Before-rename failure preserves active bytes; after-rename failure may have
/// committed already and must be resolved by checking both encrypted copies.
pub fn atomic_write_at(path: &Path, new_bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    atomic_write_with_checkpoint(path, new_bytes, |_| Ok(()))
}

pub fn atomic_write(new_bytes: &Vec<u8>) -> Result<(), Box<dyn Error>> {
    atomic_write_at(&vault_path()?, new_bytes)
}

pub fn vault_exists() -> Result<bool, Box<dyn Error>> {
    Ok(vault_path()?.exists())
}

pub fn read_vault() -> Result<Vec<u8>, Box<dyn Error>> {
    let path = vault_path()?;
    if !validate_existing_regular_file(&path)? {
        return Err("vault file does not exist".into());
    }
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

#[cfg(test)]
mod fault_tests {
    use super::*;
    use std::process::Command;
    use std::os::unix::fs::symlink;

    fn fixture(label: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("vaulty-{}-{}", label, Uuid::new_v4()));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("vault");
        atomic_write_at(&path, b"OLD_ENCRYPTED_BYTES").unwrap();
        (dir, path)
    }

    fn injected_failure(path: &Path, step: WriteCheckpoint) -> Result<(), Box<dyn Error>> {
        atomic_write_with_checkpoint(path, b"NEW_ENCRYPTED_BYTES", |current| {
            if current == step { return Err("deterministic filesystem fault".into()); }
            Ok(())
        })
    }

    #[test]
    fn injected_precommit_failures_preserve_active_vault() {
        for checkpoint in [
            WriteCheckpoint::AfterTempSync,
            WriteCheckpoint::BeforeBackupRename,
            WriteCheckpoint::AfterBackupSync,
            WriteCheckpoint::BeforeActiveRename,
        ] {
            let (dir, path) = fixture("precommit");
            assert!(injected_failure(&path, checkpoint).is_err());
            assert_eq!(fs::read(&path).unwrap(), b"OLD_ENCRYPTED_BYTES");
            assert!(!path.with_extension("lock").exists());
            // No active temporary file survives a clean error.
            assert!(!fs::read_dir(&dir).unwrap().any(|x|
                x.unwrap().file_name().to_string_lossy().starts_with("vault.tmp-")));
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn after_rename_failure_is_ambiguous_and_preserves_old_backup() {
        for checkpoint in [WriteCheckpoint::AfterActiveRename, WriteCheckpoint::AfterParentSync] {
            let (dir, path) = fixture("postcommit");
            assert!(injected_failure(&path, checkpoint).is_err());
            // An Err after rename does NOT imply no commit.
            assert_eq!(fs::read(&path).unwrap(), b"NEW_ENCRYPTED_BYTES");
            assert_eq!(fs::read(path.with_extension("previous")).unwrap(), b"OLD_ENCRYPTED_BYTES");
            assert!(!path.with_extension("lock").exists());
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn symlinked_vault_or_directory_is_rejected() {
        let (dir, path) = fixture("symlink");
        let external = dir.join("external");
        fs::write(&external, b"DO_NOT_TOUCH").unwrap();
        fs::remove_file(&path).unwrap();
        symlink(&external, &path).unwrap();
        assert!(atomic_write_at(&path, b"new").is_err());
        assert_eq!(fs::read(&external).unwrap(), b"DO_NOT_TOUCH");
        assert!(read_vault_at_for_test(&path).is_err());
        assert!(!path.with_extension("lock").exists());
        let linked_dir = dir.join("linked");
        let target = dir.join("nested");
        fs::create_dir(&target).unwrap();
        symlink(&target, &linked_dir).unwrap();
        assert!(atomic_write_at(&linked_dir.join("vault"), b"new").is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    fn read_vault_at_for_test(path: &Path) -> Result<Vec<u8>, Box<dyn Error>> {
        validate_existing_regular_file(path)?;
        if !validate_existing_regular_file(path)? { return Err("missing file".into()); }
        Ok(fs::read(path)?)
    }

    #[test]
    fn simulated_abrupt_process_exit_leaves_recoverable_copy_and_stale_lock() {
        const CHILD_VAR: &str = "VAULTY_V01A_ABRUPT_EXIT_PATH";
        if let Ok(raw_path) = std::env::var(CHILD_VAR) {
            let path = Path::new(&raw_path);
            let _ = atomic_write_with_checkpoint(path, b"NEW_ENCRYPTED_BYTES", |checkpoint| {
                if checkpoint == WriteCheckpoint::AfterBackupSync {
                    // Emulate termination without running Drop cleanup.
                    std::process::exit(97);
                }
                Ok(())
            });
            panic!("expected termination before commit");
        }
        let (dir, path) = fixture("abrupt");
        let result = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("fsutil::fault_tests::simulated_abrupt_process_exit_leaves_recoverable_copy_and_stale_lock")
            .env(CHILD_VAR, &path)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(97));
        assert_eq!(fs::read(&path).unwrap(), b"OLD_ENCRYPTED_BYTES");
        assert_eq!(fs::read(path.with_extension("previous")).unwrap(), b"OLD_ENCRYPTED_BYTES");
        // Deliberately no automatic stale-lock theft after abrupt exit.
        assert!(path.with_extension("lock").exists());
        assert!(atomic_write_at(&path, b"SHOULD_NOT_COMMIT").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"OLD_ENCRYPTED_BYTES");
        fs::remove_dir_all(dir).unwrap();
    }
}
