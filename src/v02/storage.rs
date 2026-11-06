//! Candidate storage adapter for V02. No production entry point yet.
//! Fail-closed base comparison and durable encrypted conflict copies.
//! Descriptor-relative, race-free openat/O_NOFOLLOW and power-loss review
//! remain V02 security-acceptance blockers; do NOT enable for real credentials.
use super::{V02Error, Vmk, open_file};
use super::model::MAX_FILE;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase { AfterTempSync, AfterBackupSync, BeforeReplace, AfterReplace, AfterParentSync }
#[derive(Debug, PartialEq, Eq)]
pub enum CommitOutcome { Committed, ConflictPreserved(PathBuf) }

struct LockGuard(PathBuf);
impl Drop for LockGuard {
    fn drop(&mut self) { let _ = fs::remove_file(&self.0); }
}
fn io_error(_: std::io::Error) -> V02Error { V02Error::Invalid("candidate file IO failed") }
fn check_regular(path: &Path) -> Result<bool, V02Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(V02Error::Invalid("symlink or nonregular vault file"));
            }
            if metadata.len() as usize > MAX_FILE { return Err(V02Error::TooLarge); }
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io_error(e)),
    }
}
fn check_directory(dir: &Path) -> Result<(), V02Error> {
    let m = fs::symlink_metadata(dir).map_err(io_error)?;
    if !m.file_type().is_dir() || m.file_type().is_symlink() {
        return Err(V02Error::Invalid("invalid vault parent directory"));
    }
    Ok(())
}
fn read_bounded(path: &Path) -> Result<Vec<u8>, V02Error> {
    if !check_regular(path)? { return Err(V02Error::Conflict); }
    let f = File::open(path).map_err(io_error)?;
    let mut bytes = Vec::new();
    f.take(MAX_FILE as u64 + 1).read_to_end(&mut bytes).map_err(io_error)?;
    if bytes.len() > MAX_FILE { return Err(V02Error::TooLarge); }
    Ok(bytes)
}
#[cfg(unix)]
fn make_private_file(path: &Path, bytes: &[u8]) -> Result<(), V02Error> {
    let mut file = OpenOptions::new().write(true).create_new(true)
        .mode(0o600).open(path).map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    Ok(())
}
#[cfg(not(unix))]
fn make_private_file(_path: &Path, _bytes: &[u8]) -> Result<(), V02Error> {
    Err(V02Error::Invalid("V02 candidate storage not supported on this platform"))
}
fn sync_dir(dir: &Path) -> Result<(), V02Error> {
    File::open(dir).map_err(io_error)?.sync_all().map_err(io_error)
}
fn write_private_with_cleanup(path: &Path, bytes: &[u8]) -> Result<(), V02Error> {
    let result = make_private_file(path, bytes);
    if result.is_err() { let _ = fs::remove_file(path); }
    result
}
fn conflict_copy(dir: &Path, path: &Path, bytes: &[u8]) -> Result<PathBuf, V02Error> {
    let original = path.file_name().ok_or(V02Error::Invalid("unnamed vault"))?;
    let new = dir.join(format!("{}.conflict-{}", original.to_string_lossy(), Uuid::new_v4()));
    write_private_with_cleanup(&new, bytes)?;
    sync_dir(dir)?;
    Ok(new)
}
/// Commits a presealed/AEAD-verified successor ONLY if its authenticated
/// predecessor is still the active file. On conflict, NEVER overwrite the
/// active file: durably preserve the independently encrypted candidate.
/// A returned error after rename may mean commit occurred; verify both files.
pub fn commit_candidate(
    path: &Path, expected_previous: &[u8], candidate: &[u8], vmk: &Vmk,
) -> Result<CommitOutcome, V02Error> {
    commit_with_checkpoint(path, expected_previous, candidate, vmk, |_| Ok(()))
}
pub(super) fn commit_with_checkpoint<F>(
    path: &Path, previous: &[u8], candidate: &[u8], vmk: &Vmk, mut check: F
) -> Result<CommitOutcome, V02Error>
where F: FnMut(Phase) -> Result<(), V02Error> {
    if previous.len() > MAX_FILE || candidate.len() > MAX_FILE {
        return Err(V02Error::TooLarge);
    }
    let old = open_file(previous, vmk)?;
    let next = open_file(candidate, vmk)?;
    if next.header.vault_id != old.header.vault_id
        || next.header.generation != old.header.generation.checked_add(1)
            .ok_or(V02Error::TooLarge)?
        || next.header.predecessor_hash != *blake3::hash(previous).as_bytes()
        || next.header.commit_id == old.header.commit_id {
        return Err(V02Error::Invalid("invalid candidate lineage"));
    }
    let dir = path.parent().ok_or(V02Error::Invalid("vault directory absent"))?;
    check_directory(dir)?;
    #[cfg(not(unix))]
    { return Err(V02Error::Invalid("V02 writer requires reviewed platform support")); }
    #[cfg(unix)]
    let _guard = {
        let lock = path.with_extension("lock");
        let _lock_file = OpenOptions::new().write(true).create_new(true)
            .mode(0o600).open(&lock).map_err(io_error)?;
        LockGuard(lock)
    };
    if !check_regular(path)? { return Err(V02Error::Conflict); }
    let current = read_bounded(path)?;
    if blake3::hash(&current) != blake3::hash(previous) || current != previous {
        let copy = conflict_copy(dir, path, candidate)?;
        return Ok(CommitOutcome::ConflictPreserved(copy));
    }
    let tmp = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let old_tmp = path.with_extension(format!("previous-tmp-{}", Uuid::new_v4()));
    let result = (|| -> Result<CommitOutcome, V02Error> {
        make_private_file(&tmp, candidate)?;
        check(Phase::AfterTempSync)?;
        make_private_file(&old_tmp, previous)?;
        let previous_path = path.with_extension("previous");
        fs::rename(&old_tmp, &previous_path).map_err(io_error)?;
        sync_dir(dir)?;
        check(Phase::AfterBackupSync)?;
        // Not race-free: V02 cannot be enabled for real credentials until
        // descriptor-relative directory and file identity checks are reviewed.
        if !check_regular(path)? || read_bounded(path)? != previous {
            let _ = conflict_copy(dir, path, candidate)?;
            return Err(V02Error::Conflict);
        }
        check(Phase::BeforeReplace)?;
        fs::rename(&tmp, path).map_err(io_error)?;
        check(Phase::AfterReplace)?;
        sync_dir(dir)?;
        check(Phase::AfterParentSync)?;
        let published = read_bounded(path)?;
        if published != candidate || open_file(&published, vmk).is_err() {
            return Err(V02Error::AuthenticationFailed);
        }
        Ok(CommitOutcome::Committed)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
        let _ = fs::remove_file(&old_tmp);
    }
    result
}
