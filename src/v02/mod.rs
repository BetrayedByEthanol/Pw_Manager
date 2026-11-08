//! Vaulty V02 **candidate** format and cryptographic foundation.
//!
//! This module deliberately has no password, recovery-code, virtual-PRF,
//! physical-FIDO2, trusted-client or UI unlock path. v0.4.5's final wire
//! transcript, factor combiner and key commitment need independent OPEN-01/15
//! review. The shipping binary remains disabled. Do not store real credentials.
//!
//! VMK authenticates only the outer metadata body. VERS and entry DEKs are
//! independently random. Entry ciphertext is AEAD-encrypted with a DEK that
//! cannot be obtained from the VMK.
mod codec;
mod model;
// V02-G review-only V3RV wire/transcript draft. Test-compiled exclusively;
// never available to production unlock, serialization or migration.
#[cfg(test)]
mod vnext_review;
// REVIEW-ONLY public PRF input/salt proposal, compiled exclusively in tests.
// Does not call physical tokens or authorize vNext key slots.
#[cfg(test)]
mod v02i_prf_review;
// Proposed future-version metadata binding is exercised only by synthetic
// tests. Never reinterpret VLY2 entry AEAD associated data (F-9).
#[cfg(test)]
mod entry_binding_candidate;
// Candidate-only key-slot KDF/AEAD prototype. Never activates VLY2 slots or
// exposes unreviewed factor input as a production unlock API (OPEN-01/15).
mod v02b;
pub mod storage;
pub use model::{
    ClientRecord, Dek, EntryMode, EntryRecord, EntryTier, FactorPolicy, PublicHeader,
    RecoveryPolicy, Slot, SlotState, SlotTarget, V02Error, VaultBody, VaultMode, Vers, Vmk,
};
use model::{ENTRY_DOMAIN, MAX_BODY, MAX_ENTRY_BYTES, OUTER_DOMAIN, random_nonce};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use uuid::Uuid;
use zeroize::Zeroizing;

pub struct Opened {
    pub header: PublicHeader,
    pub body: VaultBody, // authenticated metadata and still-encrypted entry payloads
}
/// AEAD associated data binds vault and entry IDs, revision and all policy
/// selectors. Changing policy without reencrypting under the entry's DEK
/// fails authentication, even if an outer VMK is available.
fn entry_aad(vault_id: Uuid, record: &EntryRecord) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ENTRY_DOMAIN.len() + 16 + 16 + 8 + 3);
    aad.extend_from_slice(ENTRY_DOMAIN);
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(record.id.as_bytes());
    aad.extend_from_slice(&record.revision.to_le_bytes());
    aad.extend_from_slice(&[record.mode as u8, record.tier as u8, record.recovery as u8]);
    aad
}
fn outer_aad(header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(OUTER_DOMAIN.len() + header.len());
    aad.extend_from_slice(OUTER_DOMAIN);
    aad.extend_from_slice(header);
    aad
}
/// Low-level payload encryption; caller must independently provision a
/// scoped entry-DEK slot before any real credential could be usable.
/// No VMK or VERS argument is accepted here.
pub fn seal_entry(
    vault_id: Uuid, record: &mut EntryRecord, dek: &Dek, plaintext: &[u8],
) -> Result<(), V02Error> {
    if record.tombstone || record.id.is_nil() || record.revision == 0
        || plaintext.len() > MAX_ENTRY_BYTES - 16 {
        return Err(V02Error::Invalid("entry identity, tombstone or plaintext size"));
    }
    let nonce = random_nonce();
    let cipher = XChaCha20Poly1305::new(Key::from_slice(dek.key()));
    let aad = entry_aad(vault_id, record);
    let ciphertext = cipher.encrypt(XNonce::from_slice(&nonce),
        Payload { msg: plaintext, aad: &aad })
        .map_err(|_| V02Error::AuthenticationFailed)?;
    record.nonce = nonce;
    record.ciphertext = ciphertext;
    Ok(())
}
pub fn open_entry(
    vault_id: Uuid, record: &EntryRecord, dek: &Dek, mode: VaultMode,
) -> Result<Zeroizing<Vec<u8>>, V02Error> {
    record.validate(mode)?;
    if record.tombstone { return Err(V02Error::Invalid("tombstoned entry")); }
    let aad = entry_aad(vault_id, record);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(dek.key()));
    let plaintext = cipher.decrypt(XNonce::from_slice(&record.nonce),
        Payload { msg: &record.ciphertext, aad: &aad })
        .map_err(|_| V02Error::AuthenticationFailed)?;
    Ok(Zeroizing::new(plaintext))
}
/// Encrypts a complete outer body with an independently supplied VMK.
/// The VMK is never persisted in clear, or used in entry AAD/key derivation.
/// This is a codec primitive, **not** a user-authorized vault save/unlock.
pub fn seal_file(header: &PublicHeader, body: &VaultBody, vmk: &Vmk)
    -> Result<Vec<u8>, V02Error>
{
    let plaintext = Zeroizing::new(codec::encode_body(body, header)?);
    if plaintext.len() > MAX_BODY { return Err(V02Error::TooLarge); }
    let nonce = random_nonce();
    let header_bytes = codec::encode_header(header, plaintext.len() + 16, &nonce)?;
    let aad = outer_aad(&header_bytes);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(vmk.key()));
    let mut ciphertext = cipher.encrypt(XNonce::from_slice(&nonce),
        Payload { msg: &plaintext, aad: &aad })
        .map_err(|_| V02Error::AuthenticationFailed)?;
    let mut result = header_bytes;
    result.append(&mut ciphertext);
    Ok(result)
}
/// Authenticates the ENTIRE public header as AAD, decrypts only the outer
/// metadata body, and validates its authenticated ancestry and records.
/// The caller-supplied VMK represents a future authorized V03 operation,
/// not an actual production unlock.
pub fn open_file(file: &[u8], vmk: &Vmk) -> Result<Opened, V02Error> {
    let parsed = codec::parse_header(file)?;
    let aad = outer_aad(parsed.aad_header);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(vmk.key()));
    let plaintext = Zeroizing::new(cipher.decrypt(
        XNonce::from_slice(&parsed.outer_nonce),
        Payload { msg: parsed.ciphertext, aad: &aad },
    ).map_err(|_| V02Error::AuthenticationFailed)?);
    let body = codec::decode_body(&plaintext, &parsed.header)?;
    Ok(Opened { header: parsed.header, body })
}
/// Creates a versioned encrypted candidate from a previously AUTHENTICATED
/// encrypted file. Never silently drop an entry: a removed entry requires a
/// revision-incremented tombstone. Never accept changes without revision bump.
/// This stages bytes only; storage::commit_candidate checks the actual disk
/// head under a writer lock and preserves encrypted conflicts.
pub fn prepare_successor<F>(previous: &[u8], vmk: &Vmk, edit: F) -> Result<Vec<u8>, V02Error>
where F: FnOnce(&mut VaultBody) -> Result<(), V02Error> {
    let opened = open_file(previous, vmk)?;
    let old = opened.body.clone();
    let mut header = opened.header;
    header.generation = header.generation.checked_add(1).ok_or(V02Error::TooLarge)?;
    header.predecessor_hash = *blake3::hash(previous).as_bytes();
    header.commit_id = Uuid::new_v4();
    let mut body = old.clone();
    body.generation = header.generation;
    body.commit_id = header.commit_id;
    body.predecessor_hash = header.predecessor_hash;
    edit(&mut body)?;
    body.validate(&header)?;
    validate_entry_transition(&old, &body)?;
    seal_file(&header, &body, vmk)
}

/// Shared cross-generation entry transition rules. Both candidate creation
/// and the final disk commit MUST enforce these rules: `seal_file` is a
/// low-level AEAD primitive, not an authorization to bypass revision history.
pub(super) fn validate_entry_transition(
    old: &VaultBody, next: &VaultBody,
) -> Result<(), V02Error> {
    for existing in &old.entries {
        let Some(next_entry) = next.entries.iter().find(|e| e.id == existing.id) else {
            return Err(V02Error::Invalid("missing tombstone for removed entry"));
        };
        if existing.tombstone && !next_entry.tombstone {
            return Err(V02Error::Invalid("tombstone revived"));
        }
        if next_entry != existing && next_entry.revision <= existing.revision {
            return Err(V02Error::Invalid("modified entry without revision bump"));
        }
        // VLY2 does not bind origin/username/title in the entry's own AAD
        // (F-9). At least require a new DEK-authenticated payload whenever
        // those fields change on the normal successor/commit path. This
        // prevents an otherwise-successful metadata-only redirect and avoids
        // persisting an entry whose revision changed but ciphertext is stale.
        // It is NOT a substitute for binding metadata in a new wire version:
        // low-level seal_file and a compromised VMK remain outside this check.
        if !next_entry.tombstone
            && (next_entry.origin != existing.origin
                || next_entry.username != existing.username
                || next_entry.title != existing.title)
            && (next_entry.nonce == existing.nonce
                || next_entry.ciphertext == existing.ciphertext)
        {
            return Err(V02Error::Invalid(
                "entry metadata change requires fresh DEK ciphertext and nonce"
            ));
        }
    }
    for item in &next.entries {
        if old.entries.iter().all(|e| e.id != item.id) && item.revision != 1 {
            return Err(V02Error::Invalid("new entry must start at revision one"));
        }
    }
    Ok(())
}
/// Classify unsupported input without implicitly invoking legacy decrypt.
pub fn classify_file(bytes: &[u8]) -> Result<(), V02Error> {
    codec::parse_header(bytes).map(|_| ())
}
#[cfg(test)]
mod tests;
