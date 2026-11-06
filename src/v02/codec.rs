//! Deterministic, bounded v2 *candidate* binary encoding. No serde
//! ambiguity, duplicate JSON keys, unchecked slicing or legacy auto-upgrade.
use super::model::*;
use uuid::Uuid;

pub(super) struct Reader<'a> { data: &'a [u8], pos: usize }
impl<'a> Reader<'a> {
    pub(super) fn new(data: &'a [u8]) -> Self { Self {data, pos: 0} }
    pub(super) fn take(&mut self, n: usize) -> Result<&'a [u8], V02Error> {
        let end = self.pos.checked_add(n).ok_or(V02Error::TooLarge)?;
        let value = self.data.get(self.pos..end)
            .ok_or(V02Error::Invalid("truncated field"))?;
        self.pos = end;
        Ok(value)
    }
    pub(super) fn array<const N: usize>(&mut self) -> Result<[u8;N], V02Error> {
        self.take(N)?.try_into().map_err(|_| V02Error::Invalid("fixed field"))
    }
    pub(super) fn u8(&mut self) -> Result<u8, V02Error> { Ok(self.array::<1>()?[0]) }
    pub(super) fn u16(&mut self) -> Result<u16, V02Error> { Ok(u16::from_le_bytes(self.array()?)) }
    pub(super) fn u32(&mut self) -> Result<u32, V02Error> { Ok(u32::from_le_bytes(self.array()?)) }
    pub(super) fn u64(&mut self) -> Result<u64, V02Error> { Ok(u64::from_le_bytes(self.array()?)) }
    pub(super) fn uuid(&mut self) -> Result<Uuid, V02Error> {
        Ok(Uuid::from_bytes(self.array()?))
    }
    pub(super) fn bytes_u16(&mut self, cap: usize) -> Result<Vec<u8>, V02Error> {
        let n = self.u16()? as usize;
        if n > cap { return Err(V02Error::TooLarge); }
        Ok(self.take(n)?.to_vec())
    }
    pub(super) fn bytes_u32(&mut self, cap: usize) -> Result<Vec<u8>, V02Error> {
        let n = self.u32()? as usize;
        if n > cap { return Err(V02Error::TooLarge); }
        Ok(self.take(n)?.to_vec())
    }
    pub(super) fn text(&mut self, cap: usize) -> Result<String, V02Error> {
        String::from_utf8(self.bytes_u16(cap)?).map_err(|_| V02Error::Invalid("invalid UTF-8"))
    }
    pub(super) fn finish(&self) -> Result<(), V02Error> {
        if self.pos != self.data.len() {
            Err(V02Error::Invalid("trailing bytes/noncanonical length"))
        } else { Ok(()) }
    }
}
pub(super) struct Writer { data: Vec<u8> }
impl Writer {
    pub(super) fn new() -> Self { Self { data: Vec::new() } }
    pub(super) fn raw(&mut self, s: &[u8]) { self.data.extend_from_slice(s); }
    pub(super) fn u8(&mut self, n: u8) { self.data.push(n); }
    pub(super) fn u16(&mut self, n: u16) { self.raw(&n.to_le_bytes()); }
    pub(super) fn u32(&mut self, n: u32) { self.raw(&n.to_le_bytes()); }
    pub(super) fn u64(&mut self, n: u64) { self.raw(&n.to_le_bytes()); }
    pub(super) fn uuid(&mut self, n: Uuid) { self.raw(n.as_bytes()); }
    pub(super) fn bytes16(&mut self, s: &[u8], max: usize) -> Result<(), V02Error> {
        if s.len() > max { return Err(V02Error::TooLarge); }
        let n: u16 = s.len().try_into().map_err(|_| V02Error::TooLarge)?;
        self.u16(n);
        self.raw(s);
        Ok(())
    }
    pub(super) fn bytes32(&mut self, s: &[u8], max: usize) -> Result<(), V02Error> {
        if s.len() > max { return Err(V02Error::TooLarge); }
        let n: u32 = s.len().try_into().map_err(|_| V02Error::TooLarge)?;
        self.u32(n);
        self.raw(s);
        Ok(())
    }
    pub(super) fn text(&mut self, s: &str, max: usize) -> Result<(), V02Error> {
        self.bytes16(s.as_bytes(), max)
    }
    pub(super) fn finish(self) -> Vec<u8> { self.data }
}
fn validate_ordered<T, F>(values: &[T], key: F) -> Result<(), V02Error>
where F: Fn(&T) -> Uuid {
    for pair in values.windows(2) {
        if key(&pair[0]) >= key(&pair[1]) {
            return Err(V02Error::Invalid("out-of-order or repeated record id"));
        }
    }
    Ok(())
}
fn encode_slot(w: &mut Writer, s: &Slot) -> Result<(), V02Error> {
    w.uuid(s.id);
    w.u8(s.target as u8);
    w.uuid(s.target_id);
    w.u8(s.factors as u8);
    w.u8(s.state as u8);
    w.raw(&s.nonce);
    w.bytes16(&s.ciphertext, MAX_SLOT_BYTES)
}
fn decode_slot(r: &mut Reader<'_>) -> Result<Slot, V02Error> {
    Ok(Slot {
        id: r.uuid()?,
        target: SlotTarget::try_from(r.u8()?)?,
        target_id: r.uuid()?,
        factors: FactorPolicy::try_from(r.u8()?)?,
        state: SlotState::try_from(r.u8()?)?,
        nonce: r.array()?,
        ciphertext: r.bytes_u16(MAX_SLOT_BYTES)?,
    })
}
fn encode_slots(w: &mut Writer, slots: &[Slot]) -> Result<(), V02Error> {
    if slots.len() > MAX_SLOTS { return Err(V02Error::TooLarge); }
    w.u16(slots.len() as u16);
    let mut sorted: Vec<&Slot> = slots.iter().collect();
    sorted.sort_by_key(|s| s.id);
    for s in sorted { encode_slot(w, s)?; }
    Ok(())
}
fn decode_slots(r: &mut Reader<'_>) -> Result<Vec<Slot>, V02Error> {
    let n = r.u16()? as usize;
    if n > MAX_SLOTS { return Err(V02Error::TooLarge); }
    let mut result = Vec::with_capacity(n);
    for _ in 0..n { result.push(decode_slot(r)?); }
    validate_ordered(&result, |s| s.id)?;
    Ok(result)
}

/// Public header is deliberately small; no entry title, URL, username or
/// entry DEK wrap resides outside the authenticated encrypted outer body.
pub(super) fn encode_header(
    header: &PublicHeader, ciphertext_len: usize, nonce: &[u8;24]
) -> Result<Vec<u8>, V02Error> {
    header.validate()?;
    if ciphertext_len < 16 || ciphertext_len > MAX_BODY + 16 || nonce == &[0u8;24] {
        return Err(V02Error::Invalid("outer ciphertext bounds/nonce"));
    }
    let mut w = Writer::new();
    w.raw(MAGIC);
    w.u16(VERSION);
    w.u16(0); // reserved flags, must stay zero
    w.u32(0); // header length patched after encoding
    w.u32(ciphertext_len.try_into().map_err(|_| V02Error::TooLarge)?);
    w.uuid(header.vault_id);
    w.uuid(header.commit_id);
    w.u64(header.generation);
    w.raw(&header.predecessor_hash);
    w.raw(nonce);
    w.u8(header.mode as u8);
    encode_slots(&mut w, &header.vmk_slots)?;
    encode_slots(&mut w, &header.bootstrap_slots)?;
    let mut bytes = w.finish();
    if bytes.len() > MAX_HEADER { return Err(V02Error::TooLarge); }
    let total: u32 = bytes.len().try_into().map_err(|_| V02Error::TooLarge)?;
    bytes[8..12].copy_from_slice(&total.to_le_bytes());
    Ok(bytes)
}
pub(super) struct ParsedHeader<'a> {
    pub header: PublicHeader,
    pub outer_nonce: [u8;24],
    pub aad_header: &'a [u8],
    pub ciphertext: &'a [u8],
}
/// Parse only a bounded public header, before any expensive cryptography.
pub(super) fn parse_header(file: &[u8]) -> Result<ParsedHeader<'_>, V02Error> {
    // Identify unsupported historic source formats before applying v2 framing.
    if file.starts_with(b"VLT1") || file.starts_with(b"{") {
        return Err(V02Error::MigrationRequired);
    }
    if file.len() < 16 { return Err(V02Error::Invalid("truncated framing")); }
    if file.get(0..4) != Some(&MAGIC[..]) {
        return Err(V02Error::Invalid("unknown format magic"));
    }
    if u16::from_le_bytes([file[4],file[5]]) != VERSION {
        return Err(V02Error::UnsupportedVersion);
    }
    if u16::from_le_bytes([file[6],file[7]]) != 0 {
        return Err(V02Error::Invalid("unsupported reserved flags"));
    }
    let head_len = u32::from_le_bytes(file[8..12].try_into().map_err(|_| V02Error::Invalid("head len"))?) as usize;
    let encrypted_len = u32::from_le_bytes(file[12..16].try_into().map_err(|_| V02Error::Invalid("cipher len"))?) as usize;
    let total = head_len.checked_add(encrypted_len).ok_or(V02Error::TooLarge)?;
    if head_len < 117 || head_len > MAX_HEADER || encrypted_len < 16
        || encrypted_len > MAX_BODY + 16 || total > MAX_FILE || total != file.len() {
        return Err(V02Error::Invalid("invalid file or declared lengths"));
    }
    let mut r = Reader::new(&file[..head_len]);
    if &r.array::<4>()? != MAGIC || r.u16()? != VERSION || r.u16()? != 0
        || r.u32()? as usize != head_len || r.u32()? as usize != encrypted_len {
        return Err(V02Error::Invalid("noncanonical header framing"));
    }
    let mut r = Reader::new(&file[..head_len]);
    let _ = r.take(16)?;
    let vault_id = r.uuid()?;
    let commit_id = r.uuid()?;
    let generation = r.u64()?;
    let predecessor_hash = r.array::<32>()?;
    let outer_nonce = r.array::<24>()?;
    let mode = VaultMode::try_from(r.u8()?)?;
    let vmk_slots = decode_slots(&mut r)?;
    let bootstrap_slots = decode_slots(&mut r)?;
    r.finish()?;
    let header = PublicHeader {
        vault_id, commit_id, generation, predecessor_hash, mode, vmk_slots, bootstrap_slots
    };
    header.validate()?;
    if outer_nonce == [0u8;24] { return Err(V02Error::Invalid("zero outer nonce")); }
    Ok(ParsedHeader {
        header, outer_nonce,
        aad_header: &file[..head_len], ciphertext: &file[head_len..],
    })
}

fn encode_entry(w: &mut Writer, item: &EntryRecord) -> Result<(), V02Error> {
    w.uuid(item.id);
    w.u64(item.revision);
    w.u8(item.mode as u8);
    w.u8(item.tier as u8);
    w.u8(item.recovery as u8);
    w.u8(u8::from(item.tombstone));
    w.text(&item.title, 2048)?;
    w.text(&item.username, 2048)?;
    w.text(&item.origin, 4096)?;
    w.raw(&item.nonce);
    w.bytes32(&item.ciphertext, MAX_ENTRY_BYTES)?;
    encode_slots(w, &item.dek_slots)
}
fn decode_entry(r: &mut Reader<'_>) -> Result<EntryRecord, V02Error> {
    let id = r.uuid()?;
    let revision = r.u64()?;
    let mode = EntryMode::try_from(r.u8()?)?;
    let tier = EntryTier::try_from(r.u8()?)?;
    let recovery = RecoveryPolicy::try_from(r.u8()?)?;
    let tombstone = match r.u8()? {
        0 => false, 1 => true, _ => return Err(V02Error::Invalid("invalid tombstone bit")),
    };
    let title = r.text(2048)?;
    let username = r.text(2048)?;
    let origin = r.text(4096)?;
    let nonce = r.array()?;
    let ciphertext = r.bytes_u32(MAX_ENTRY_BYTES)?;
    let dek_slots = decode_slots(r)?;
    Ok(EntryRecord {
        id, revision, mode, tier, recovery, tombstone,
        title, username, origin, nonce, ciphertext, dek_slots,
    })
}
/// Compute the full encoded size **before** allocating or copying ciphertexts.
/// Individual records may each be valid while their aggregate exceeds MAX_BODY.
/// Every addition is checked, and the running total is bounded immediately.
fn checked_budget(total: &mut usize, additional: usize) -> Result<(), V02Error> {
    *total = total.checked_add(additional).ok_or(V02Error::TooLarge)?;
    if *total > MAX_BODY { return Err(V02Error::TooLarge); }
    Ok(())
}
fn budget_slots(total: &mut usize, slots: &[Slot]) -> Result<(), V02Error> {
    // Count u16 + each slot: UUID(16), target(1), target UUID(16),
    // factors(1), state(1), nonce(24), ciphertext length u16(2).
    checked_budget(total, 2)?;
    for slot in slots {
        checked_budget(total, 61)?;
        checked_budget(total, slot.ciphertext.len())?;
    }
    Ok(())
}
fn predicted_body_size(body: &VaultBody) -> Result<usize, V02Error> {
    // Vault UUID + commit UUID + generation + predecessor hash;
    // two slot vectors, entry count u16, client count u16.
    let mut total = 16 + 16 + 8 + 32 + 2 + 2;
    budget_slots(&mut total, &body.vers_slots)?;
    budget_slots(&mut total, &body.provider_seed_slots)?;
    for entry in &body.entries {
        // Entry fixed: id(16), revision(8), four enum/flags bytes,
        // three UTF-8 length u16, nonce(24), ciphertext length u32,
        // DEK-slot count u16 is accounted for in budget_slots below.
        checked_budget(&mut total, 62)?;
        checked_budget(&mut total, entry.title.len())?;
        checked_budget(&mut total, entry.username.len())?;
        checked_budget(&mut total, entry.origin.len())?;
        checked_budget(&mut total, entry.ciphertext.len())?;
        budget_slots(&mut total, &entry.dek_slots)?;
    }
    for _ in &body.clients {
        checked_budget(&mut total, 16 + 32 + 1)?;
    }
    Ok(total)
}

pub(super) fn encode_body(body: &VaultBody, header: &PublicHeader) -> Result<Vec<u8>, V02Error> {
    header.validate()?;
    body.validate(header)?;
    // Reject an oversized aggregate before allocating the encoder buffer.
    let predicted = predicted_body_size(body)?;
    let mut w = Writer::new();
    w.uuid(body.vault_id);
    w.uuid(body.commit_id);
    w.u64(body.generation);
    w.raw(&body.predecessor_hash);
    encode_slots(&mut w, &body.vers_slots)?;
    encode_slots(&mut w, &body.provider_seed_slots)?;
    let mut entries: Vec<&EntryRecord> = body.entries.iter().collect();
    entries.sort_by_key(|e| e.id);
    w.u16(entries.len() as u16);
    for item in entries { encode_entry(&mut w, item)?; }
    let mut clients: Vec<&ClientRecord> = body.clients.iter().collect();
    clients.sort_by_key(|c| c.id);
    w.u16(clients.len() as u16);
    for client in clients {
        w.uuid(client.id);
        w.raw(&client.public_identity);
        w.u8(u8::from(client.revoked));
    }
    let result = w.finish();
    // Keep the preflight in sync with the canonical encoder's actual layout.
    if result.len() != predicted {
        return Err(V02Error::Invalid("body size estimate mismatch"));
    }
    Ok(result)
}
pub(super) fn decode_body(bytes: &[u8], header: &PublicHeader) -> Result<VaultBody, V02Error> {
    if bytes.len() > MAX_BODY { return Err(V02Error::TooLarge); }
    let mut r = Reader::new(bytes);
    let vault_id = r.uuid()?;
    let commit_id = r.uuid()?;
    let generation = r.u64()?;
    let predecessor_hash = r.array()?;
    let vers_slots = decode_slots(&mut r)?;
    let provider_seed_slots = decode_slots(&mut r)?;
    let count = r.u16()? as usize;
    if count > MAX_ENTRIES { return Err(V02Error::TooLarge); }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count { entries.push(decode_entry(&mut r)?); }
    validate_ordered(&entries, |e| e.id)?;
    let count = r.u16()? as usize;
    if count > MAX_CLIENTS { return Err(V02Error::TooLarge); }
    let mut clients = Vec::with_capacity(count);
    for _ in 0..count {
        let id = r.uuid()?;
        let public_identity = r.array()?;
        let revoked = match r.u8()? {
            0 => false, 1 => true,
            _ => return Err(V02Error::Invalid("invalid client status")),
        };
        clients.push(ClientRecord { id, public_identity, revoked });
    }
    validate_ordered(&clients, |c| c.id)?;
    r.finish()?;
    let body = VaultBody {
        vault_id, commit_id, generation, predecessor_hash,
        vers_slots, provider_seed_slots, entries, clients,
    };
    body.validate(header)?;
    Ok(body)
}
