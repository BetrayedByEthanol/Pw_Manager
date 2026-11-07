//! V02-E *future version only* entry metadata AAD candidate (F-9).
//!
//! Does NOT change the VLY2 format, entry_aad, seal_entry, open_entry or
//! persisted ciphertext. Metadata binding must be approved, versioned and
//! migrated explicitly before it is used by any authorized fill route.
use super::{model::ENTRY_DOMAIN, EntryRecord, V02Error, Uuid};

const DOMAIN: &[u8] = b"Vaulty/V02-E/REVIEW-ONLY/entry-binding/vNext";

/// A separate candidate domain binding public-to-VMK metadata used to
/// authorize future entry fill. The caller must separately canonicalize and
/// authorize origins/frames; byte equality here is not browser trust.
pub(super) fn entry_aad_vnext(vault_id: Uuid, entry: &EntryRecord) -> Result<Vec<u8>, V02Error> {
    if vault_id.is_nil() || entry.id.is_nil() || entry.revision == 0
        || entry.title.len() > 2048 || entry.username.len() > 2048
        || entry.origin.len() > 4096
    {
        return Err(V02Error::Invalid("candidate entry binding identity/metadata"));
    }
    let mut out = Vec::with_capacity(DOMAIN.len() + ENTRY_DOMAIN.len() + 128
        + entry.title.len() + entry.username.len() + entry.origin.len());
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(ENTRY_DOMAIN);
    out.extend_from_slice(vault_id.as_bytes());
    out.extend_from_slice(entry.id.as_bytes());
    out.extend_from_slice(&entry.revision.to_be_bytes());
    out.extend_from_slice(&[entry.mode as u8, entry.tier as u8, entry.recovery as u8]);
    for part in [&entry.origin, &entry.username, &entry.title] {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part.as_bytes());
    }
    Ok(out)
}
