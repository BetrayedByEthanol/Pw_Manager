//! V02-G REVIEW-ONLY vNext key-slot wire proposal ("V3RV").
//!
//! Compiled ONLY by tests. This module NEVER authenticates a factor, opens a
//! slot, produces Verified/READY, or migrates a VLY2 key. It parses adversarial
//! bytes into UNTRUSTED structures; its 32-byte commitment is UNVERIFIED.
//! OPEN-01/15 and owner KDF/encoding/recovery decisions remain BLOCKED.
use super::model::{
    route_is_allowed, EntryMode, EntryTier, FactorPolicy, RecoveryPolicy,
    SlotTarget, V02Error, VaultMode,
};
use uuid::Uuid;

const MAGIC: &[u8; 4] = b"V3RV"; // NOT VLY2 and NOT an activated VLY3 format
const VERSION: u16 = 1;        // Review proposal v1, NOT production protocol
const SUITE: u16 = 1;          // Review labels only; no approved commitment suite
const MAX_DESCRIPTOR: usize = 1024;
const MAX_FRAME: usize = 2048;
const MAX_CREDENTIAL: usize = 128;
const WRAPPED_KEY_CT: usize = 48; // proposed 32-byte key + 16-byte AEAD tag
const SLOT_DOMAIN: &[u8] = b"Vaulty/V02-G/REVIEW-ONLY/slot-context/v1";
const COMMIT_DOMAIN: &[u8] = b"Vaulty/V02-G/REVIEW-ONLY/commitment-context/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Purpose { Normal = 1, Recovery = 2 }
impl Purpose {
    fn read(n: u8) -> Result<Self, V02Error> {
        match n { 1 => Ok(Self::Normal), 2 => Ok(Self::Recovery),
            _ => Err(V02Error::Invalid("review purpose")) }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScopeKind { Vault = 1, Group = 2, Entry = 3 }
impl ScopeKind {
    fn read(n: u8) -> Result<Self, V02Error> {
        match n { 1 => Ok(Self::Vault), 2 => Ok(Self::Group),
            3 => Ok(Self::Entry), _ => Err(V02Error::Invalid("review recovery scope")) }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct RecoveryScope { kind: ScopeKind, owner: Uuid }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EntryPolicy { mode: EntryMode, tier: EntryTier, recovery: RecoveryPolicy }
#[derive(Clone, Debug, PartialEq, Eq)]
struct PasswordKdf {
    encoding: u8, // 1 = proposed UTF8_NFC_v1, NOT owner-approved or implemented
    salt: [u8; 16],
    memory_kib: u32, passes: u32, lanes: u8,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Provider {
    None,
    Virtual { id: Uuid, purpose_hash: [u8; 32] },
    Physical {
        credential: Vec<u8>, rp_id_hash: [u8; 32], prf_salt: [u8; 32],
        scope: u8, // 1 vault/credential; 2 entry/slot -- NOT device verified
        up: bool, uv: bool,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Descriptor {
    vault_id: Uuid, slot_id: Uuid,
    target: SlotTarget, target_id: Uuid,
    vault_mode: VaultMode, route: FactorPolicy,
    entry: Option<EntryPolicy>,
    purpose: Purpose,
    recovery_scope: Option<RecoveryScope>,
    ancestor: Option<Uuid>, // untrusted edge; full graph validation is future work
    password: Option<PasswordKdf>,
    provider: Provider,
}
impl Descriptor {
    fn validate(&self) -> Result<(), V02Error> {
        if self.vault_id.is_nil() || self.slot_id.is_nil()
            || (self.target == SlotTarget::EntryDek) != !self.target_id.is_nil()
        { return Err(V02Error::Invalid("review slot identity")); }
        let entry = self.entry.map(|e| (e.mode, e.tier, e.recovery));
        if !route_is_allowed(self.vault_mode, self.target, self.route, entry) {
            return Err(V02Error::Invalid("review route policy"));
        }
        let recovery = self.route.is_recovery();
        if recovery != (self.purpose == Purpose::Recovery) {
            return Err(V02Error::Invalid("review purpose/route mismatch"));
        }
        match (&self.recovery_scope, recovery) {
            (None, false) => {},
            (Some(scope), true) => {
                if scope.owner.is_nil() { return Err(V02Error::Invalid("nil recovery owner")); }
                let valid = match self.entry {
                    None => scope.kind == ScopeKind::Vault && scope.owner == self.vault_id,
                    Some(e) => match e.recovery {
                        RecoveryPolicy::Shared => scope.kind == ScopeKind::Vault
                            && scope.owner == self.vault_id,
                        RecoveryPolicy::Group => scope.kind == ScopeKind::Group,
                        RecoveryPolicy::Independent => scope.kind == ScopeKind::Entry
                            && scope.owner == self.target_id,
                        RecoveryPolicy::StrictNone => false,
                    },
                };
                if !valid { return Err(V02Error::Invalid("review recovery scope policy")); }
            }
            _ => return Err(V02Error::Invalid("review scope/route mismatch")),
        }
        if self.ancestor.is_some_and(|a| a.is_nil() || a == self.slot_id) {
            return Err(V02Error::Invalid("review ancestor identity"));
        }
        let pwd = matches!(self.route, FactorPolicy::VaultPasswordVirtual |
            FactorPolicy::VaultPasswordPhysical | FactorPolicy::CodePassword |
            FactorPolicy::CustomVirtual | FactorPolicy::CustomPhysical);
        if pwd != self.password.is_some() {
            return Err(V02Error::Invalid("review password recipe"));
        }
        if let Some(p) = &self.password {
            // TEST-ONLY parse guard, NOT calibrated production Argon2 defaults.
            if p.encoding != 1 || p.salt == [0; 16] ||
                !(8192..=262144).contains(&p.memory_kib) ||
                !(2..=8).contains(&p.passes) ||
                !(1..=4).contains(&p.lanes) ||
                p.memory_kib < 8 * u32::from(p.lanes) {
                return Err(V02Error::Invalid("review KDF fields"));
            }
        }
        let physical = matches!(self.route, FactorPolicy::VaultPasswordPhysical |
            FactorPolicy::CodePhysical | FactorPolicy::DefaultPhysical |
            FactorPolicy::CustomPhysical);
        let virtual_route = matches!(self.route, FactorPolicy::VaultPasswordVirtual |
            FactorPolicy::DefaultVirtual | FactorPolicy::CustomVirtual)
            && !(self.target == SlotTarget::ProviderSeed
                && self.vault_mode == VaultMode::PasswordVirtual
                && self.route == FactorPolicy::VaultPasswordVirtual);
        match &self.provider {
            Provider::None if !physical && !virtual_route => {},
            Provider::Virtual { id, purpose_hash } if virtual_route &&
                !id.is_nil() && *purpose_hash != [0;32] => {},
            Provider::Physical { credential, rp_id_hash, prf_salt, scope, up, .. }
                if physical && !credential.is_empty() && credential.len() <= MAX_CREDENTIAL
                && *rp_id_hash != [0;32] && *prf_salt != [0;32] && *up
                && matches!(*scope, 1 | 2)
                && !(self.entry.is_some_and(|e| e.tier == EntryTier::Isolated)
                    && *scope != 2) => {},
            _ => return Err(V02Error::Invalid("review provider/factor mismatch")),
        }
        Ok(())
    }
    fn encode(&self) -> Result<Vec<u8>, V02Error> {
        self.validate()?;
        let mut o=Vec::with_capacity(240);
        o.extend_from_slice(self.vault_id.as_bytes());
        o.extend_from_slice(self.slot_id.as_bytes());
        o.push(self.target as u8);
        o.extend_from_slice(self.target_id.as_bytes());
        o.push(self.vault_mode as u8);
        o.push(self.route as u8);
        match self.entry {
            None=>o.push(0),
            Some(e)=>{o.extend_from_slice(&[1,e.mode as u8,e.tier as u8,e.recovery as u8]);}
        }
        o.push(self.purpose as u8);
        match &self.recovery_scope {
            None=>o.push(0),
            Some(s)=>{o.push(s.kind as u8);o.extend_from_slice(s.owner.as_bytes());}
        }
        match self.ancestor {
            None=>o.push(0),
            Some(id)=>{o.push(1);o.extend_from_slice(id.as_bytes());}
        }
        match &self.password {
            None=>o.push(0),
            Some(p)=>{
                o.extend_from_slice(&[1,p.encoding,1]); // kdf 1: Argon2id-v0x13 proposal
                o.extend_from_slice(&p.salt);
                o.extend_from_slice(&p.memory_kib.to_be_bytes());
                o.extend_from_slice(&p.passes.to_be_bytes());
                o.push(p.lanes);
            }
        }
        match &self.provider {
            Provider::None=>o.push(0),
            Provider::Virtual {id,purpose_hash}=>{
                o.push(1);o.extend_from_slice(id.as_bytes());o.extend_from_slice(purpose_hash);
            }
            Provider::Physical {credential,rp_id_hash,prf_salt,scope,up,uv}=>{
                o.push(2);
                o.extend_from_slice(&(credential.len() as u16).to_be_bytes());
                o.extend_from_slice(credential);
                o.extend_from_slice(rp_id_hash);
                o.extend_from_slice(prf_salt);
                o.extend_from_slice(&[*scope,u8::from(*up),u8::from(*uv)]);
            }
        }
        if o.len()>MAX_DESCRIPTOR{return Err(V02Error::TooLarge);}
        Ok(o)
    }
    fn decode(bytes: &[u8]) -> Result<Self,V02Error> {
        if bytes.len()>MAX_DESCRIPTOR{return Err(V02Error::TooLarge);}
        let mut r=Reader::new(bytes);
        let vault_id=r.uuid()?;let slot_id=r.uuid()?;
        let target=SlotTarget::try_from(r.u8()?)?;
        let target_id=r.uuid()?;
        let vault_mode=VaultMode::try_from(r.u8()?)?;
        let route=FactorPolicy::try_from(r.u8()?)?;
        let entry=match r.u8()? {
            0=>None,
            1=>Some(EntryPolicy{
                mode:EntryMode::try_from(r.u8()?)?,
                tier:EntryTier::try_from(r.u8()?)?,
                recovery:RecoveryPolicy::try_from(r.u8()?)?,
            }),
            _=>return Err(V02Error::Invalid("review entry flag"))
        };
        let purpose=Purpose::read(r.u8()?)?;
        let recovery_scope=match r.u8()? {
            0=>None,
            n=>Some(RecoveryScope{kind:ScopeKind::read(n)?,owner:r.uuid()?}),
        };
        let ancestor=match r.u8()? {
            0=>None,1=>Some(r.uuid()?),
            _=>return Err(V02Error::Invalid("review ancestor flag")),
        };
        let password=match r.u8()? {
            0=>None,
            1=>{
                let encoding=r.u8()?;let kdf=r.u8()?;
                if kdf!=1{return Err(V02Error::Invalid("unknown review KDF"));}
                Some(PasswordKdf{encoding,salt:r.array()?,
                    memory_kib:r.u32()?,passes:r.u32()?,lanes:r.u8()?})
            }
            _=>return Err(V02Error::Invalid("review password flag")),
        };
        let provider=match r.u8()? {
            0=>Provider::None,
            1=>Provider::Virtual{id:r.uuid()?,purpose_hash:r.array()?},
            2=>{
                let n=r.u16()? as usize;
                if n>MAX_CREDENTIAL{return Err(V02Error::TooLarge);}
                let credential=r.take(n)?.to_vec();
                let rp_id_hash=r.array()?;let prf_salt=r.array()?;
                let scope=r.u8()?;let up=r.bool()?;let uv=r.bool()?;
                Provider::Physical{credential,rp_id_hash,prf_salt,scope,up,uv}
            }
            _=>return Err(V02Error::Invalid("unknown review provider")),
        };
        r.finish()?;
        let d=Self{vault_id,slot_id,target,target_id,vault_mode,route,
            entry,purpose,recovery_scope,ancestor,password,provider};
        d.validate()?;
        // Reject semantically equivalent alternate encodings, if any.
        if d.encode()?.as_slice()!=bytes{return Err(V02Error::Invalid("noncanonical descriptor"));}
        Ok(d)
    }
}

/// Parsed ciphertext and commitment tags are opaque attacker-controlled bytes.
/// Structural validity NEVER means key commitment, READY or factor provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
struct UntrustedEnvelope {
    descriptor: Descriptor, nonce: [u8;24],
    ciphertext: [u8; WRAPPED_KEY_CT], commitment: [u8;32],
}
impl UntrustedEnvelope {
    fn encode(&self)->Result<Vec<u8>,V02Error>{
        if self.nonce==[0;24] {return Err(V02Error::Invalid("zero review nonce"));}
        let desc=self.descriptor.encode()?;
        let mut out=Vec::with_capacity(desc.len()+80);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&SUITE.to_be_bytes());
        out.extend_from_slice(&(desc.len() as u16).to_be_bytes());
        out.extend_from_slice(&desc);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(WRAPPED_KEY_CT as u16).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.commitment);
        if out.len()>MAX_FRAME{return Err(V02Error::TooLarge);}
        Ok(out)
    }
    fn decode(bytes:&[u8])->Result<Self,V02Error>{
        if bytes.len()>MAX_FRAME{return Err(V02Error::TooLarge);}
        let mut r=Reader::new(bytes);
        if &r.array::<4>()?!=MAGIC{return Err(V02Error::UnsupportedVersion);}
        if r.u16()?!=VERSION || r.u16()?!=SUITE {
            return Err(V02Error::UnsupportedVersion);
        }
        let n=r.u16()? as usize;
        if n>MAX_DESCRIPTOR{return Err(V02Error::TooLarge);}
        let descriptor=Descriptor::decode(r.take(n)?)?;
        let nonce=r.array()?;
        if r.u16()? as usize!=WRAPPED_KEY_CT {
            return Err(V02Error::Invalid("review ciphertext size"));
        }
        let ciphertext=r.array()?;
        let commitment=r.array()?;
        r.finish()?;
        let out=Self{descriptor,nonce,ciphertext,commitment};
        if out.encode()?.as_slice()!=bytes {
            return Err(V02Error::Invalid("noncanonical review envelope"));
        }
        Ok(out)
    }
    /// Future key schedule's proposed public descriptor context. It is not a
    /// key or an authentication result; approval may require transcript edits.
    fn slot_context(&self)->Result<Vec<u8>,V02Error>{
        let desc=self.descriptor.encode()?;
        let mut out=Vec::with_capacity(SLOT_DOMAIN.len()+10+desc.len());
        out.extend_from_slice(SLOT_DOMAIN);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_be_bytes());
        out.extend_from_slice(&SUITE.to_be_bytes());
        out.extend_from_slice(&(desc.len() as u16).to_be_bytes());
        out.extend_from_slice(&desc);
        Ok(out)
    }
    /// Proposed commitment-input bytes; no commitment function is approved.
    fn commitment_context(&self)->Result<Vec<u8>,V02Error>{
        let mut out=Vec::with_capacity(COMMIT_DOMAIN.len()+MAX_DESCRIPTOR+130);
        out.extend_from_slice(COMMIT_DOMAIN);
        out.extend_from_slice(&self.slot_context()?);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(WRAPPED_KEY_CT as u16).to_be_bytes());
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }
}
struct Reader<'a>{bytes:&'a[u8],pos:usize}
impl<'a> Reader<'a>{
    fn new(bytes:&'a[u8])->Self{Self{bytes,pos:0}}
    fn take(&mut self,n:usize)->Result<&'a[u8],V02Error>{
        let end=self.pos.checked_add(n).ok_or(V02Error::TooLarge)?;
        let part=self.bytes.get(self.pos..end).ok_or(V02Error::Invalid("truncated review frame"))?;
        self.pos=end;Ok(part)
    }
    fn array<const N:usize>(&mut self)->Result<[u8;N],V02Error>{
        self.take(N)?.try_into().map_err(|_|V02Error::Invalid("review fixed field"))
    }
    fn u8(&mut self)->Result<u8,V02Error>{Ok(self.array::<1>()?[0])}
    fn u16(&mut self)->Result<u16,V02Error>{Ok(u16::from_be_bytes(self.array()?))}
    fn u32(&mut self)->Result<u32,V02Error>{Ok(u32::from_be_bytes(self.array()?))}
    fn uuid(&mut self)->Result<Uuid,V02Error>{Ok(Uuid::from_bytes(self.array()?))}
    fn bool(&mut self)->Result<bool,V02Error>{
        match self.u8()?{0=>Ok(false),1=>Ok(true),_=>Err(V02Error::Invalid("review boolean"))}
    }
    fn finish(&self)->Result<(),V02Error>{
        if self.pos==self.bytes.len(){Ok(())}
        else{Err(V02Error::Invalid("trailing review bytes"))}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id(n:u8)->Uuid{Uuid::from_bytes([n;16])}
    fn sample()->UntrustedEnvelope{
        UntrustedEnvelope{
            descriptor:Descriptor{
                vault_id:id(1),slot_id:id(2),target:SlotTarget::EntryDek,
                target_id:id(3),vault_mode:VaultMode::PasswordVirtual,
                route:FactorPolicy::CodePhysical,
                entry:Some(EntryPolicy{mode:EntryMode::DefaultPhysical,
                    tier:EntryTier::Isolated,recovery:RecoveryPolicy::Independent}),
                purpose:Purpose::Recovery,
                recovery_scope:Some(RecoveryScope{kind:ScopeKind::Entry,owner:id(3)}),
                ancestor:None,password:None,
                provider:Provider::Physical{credential:b"synthetic-credential".to_vec(),
                    rp_id_hash:[6;32],prf_salt:[7;32],scope:2,up:true,uv:true},
            },
            nonce:[8;24],ciphertext:[9;WRAPPED_KEY_CT],commitment:[10;32],
        }
    }
    #[test]
    fn strict_review_envelope_roundtrip_and_vly2_rejects_new_magic(){
        let x=sample();let b=x.encode().unwrap();
        assert_eq!(&b[..4],b"V3RV");
        assert_eq!(b[4..6],VERSION.to_be_bytes());
        assert_eq!(UntrustedEnvelope::decode(&b).unwrap(),x);
        assert!(crate::v02::classify_file(&b).is_err(),
            "vNext cannot be silently treated as VLY2");
        assert_ne!(MAGIC,b"VLY2");
    }
    #[test]
    fn truncation_trailing_size_version_and_unknown_tags_are_refused(){
        let b=sample().encode().unwrap();
        for n in 0..b.len(){assert!(UntrustedEnvelope::decode(&b[..n]).is_err(),
            "accepted truncation at {n}");}
        let mut extra=b.clone();extra.push(0);
        assert!(UntrustedEnvelope::decode(&extra).is_err());
        let mut bad=b.clone();bad[4]=42;
        assert_eq!(UntrustedEnvelope::decode(&bad).err(),Some(V02Error::UnsupportedVersion));
        let mut bad=b.clone();bad[6]=42;
        assert_eq!(UntrustedEnvelope::decode(&bad).err(),Some(V02Error::UnsupportedVersion));
        let mut bad=b.clone();bad[8..10].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(UntrustedEnvelope::decode(&bad).is_err());
        let mut bad=b.clone();bad[10+32]=255; // target tag in descriptor
        assert!(UntrustedEnvelope::decode(&bad).is_err());
        let mut bad=b.clone();bad.extend(vec![0u8;MAX_FRAME]);
        assert_eq!(UntrustedEnvelope::decode(&bad).err(),Some(V02Error::TooLarge));
    }
    #[test]
    fn isolated_policy_scope_uv_and_provider_negative_cases(){
        let x=sample();
        assert!(x.encode().is_ok());
        let mut d=x.clone();d.descriptor.provider=Provider::None;
        assert!(d.encode().is_err());
        let mut d=x.clone();d.descriptor.route=FactorPolicy::CodeOnly;
        assert!(d.encode().is_err());
        let mut d=x.clone();d.descriptor.route=FactorPolicy::CodePassword;
        assert!(d.encode().is_err());
        let mut d=x.clone();d.descriptor.entry.as_mut().unwrap().recovery=RecoveryPolicy::StrictNone;
        assert!(d.encode().is_err());
        let mut d=x.clone();d.descriptor.recovery_scope.as_mut().unwrap().owner=id(5);
        assert!(d.encode().is_err());
        let mut d=x.clone();d.descriptor.ancestor=Some(d.descriptor.slot_id);
        assert!(d.encode().is_err());
        let mut d=x.clone();
        if let Provider::Physical{scope,..}=&mut d.descriptor.provider {*scope=1;}
        assert!(d.encode().is_err());
        let mut d=x.clone();
        if let Provider::Physical{up,..}=&mut d.descriptor.provider {*up=false;}
        assert!(d.encode().is_err());
        // UV=false remains a proposal / OPEN-15 question. Encoding it as a
        // flag is NOT proof of presence, user verification or active hardware.
        let mut d=x.clone();
        if let Provider::Physical{uv,..}=&mut d.descriptor.provider {*uv=false;}
        assert!(d.encode().is_ok());
    }
    #[test]
    fn password_recipe_and_recovery_scope_fail_closed(){
        let mut x=sample();
        x.descriptor.entry.as_mut().unwrap().tier=EntryTier::Standard;
        x.descriptor.entry.as_mut().unwrap().recovery=RecoveryPolicy::Shared;
        x.descriptor.route=FactorPolicy::CodeOnly;
        x.descriptor.provider=Provider::None;
        x.descriptor.recovery_scope=Some(RecoveryScope{kind:ScopeKind::Vault,
            owner:x.descriptor.vault_id});
        assert!(x.encode().is_ok(),"Standard weaker recovery is structural only");
        let mut d=x.clone();d.descriptor.purpose=Purpose::Normal;
        assert!(d.encode().is_err());
        let mut d=x.clone();d.descriptor.recovery_scope=None;
        assert!(d.encode().is_err());
        let mut d=x.clone();d.descriptor.vault_mode=VaultMode::PasswordPhysical;
        assert!(d.encode().is_err());

        let mut d=x.clone();
        d.descriptor.route=FactorPolicy::CustomPhysical;
        d.descriptor.entry.as_mut().unwrap().mode=EntryMode::CustomPhysical;
        d.descriptor.purpose=Purpose::Normal;d.descriptor.recovery_scope=None;
        d.descriptor.password=Some(PasswordKdf{
            encoding:1,salt:[4;16],memory_kib:65536,passes:3,lanes:1});
        d.descriptor.provider=Provider::Physical{credential:b"token".to_vec(),
            rp_id_hash:[4;32],prf_salt:[5;32],scope:2,up:true,uv:true};
        assert!(d.encode().is_ok());
        let mut wrong=d.clone();
        wrong.descriptor.password.as_mut().unwrap().encoding=2;
        assert!(wrong.encode().is_err(),"unknown proposed password encoding");
        let mut wrong=d.clone();
        wrong.descriptor.password.as_mut().unwrap().memory_kib=u32::MAX;
        assert!(wrong.encode().is_err(),"hostile KDF params");
        let mut wrong=d.clone();
        wrong.descriptor.password.as_mut().unwrap().passes=0;
        assert!(wrong.encode().is_err());
    }
    #[test]
    fn untrusted_valid_mutations_change_binding_context_but_are_not_authenticated(){
        let x=sample();
        let aad=x.slot_context().unwrap();
        let commit=x.commitment_context().unwrap();
        let mut v=x.clone();v.descriptor.slot_id=id(11);
        assert_ne!(aad,v.slot_context().unwrap());
        assert_ne!(commit,v.commitment_context().unwrap());
        let mut v=x.clone();v.nonce=[4;24];
        assert_eq!(aad,v.slot_context().unwrap());
        assert_ne!(commit,v.commitment_context().unwrap());
        let mut v=x.clone();v.ciphertext[0]^=1;
        assert_ne!(commit,v.commitment_context().unwrap());
        let mut v=x.clone();v.descriptor.vault_id=id(12);
        assert_ne!(aad,v.slot_context().unwrap());
        // Crucially, a changed but still parse-valid descriptor is UNTRUSTED:
        // no authentication key or committing AEAD is checked in this codec.
        assert!(UntrustedEnvelope::decode(&v.encode().unwrap()).is_ok());
    }
    #[test]
    fn encoding_is_canonical_and_strict_for_boolean_and_credential_length(){
        let b=sample().encode().unwrap();
        let dlen=u16::from_be_bytes([b[8],b[9]]) as usize;
        assert_eq!(b.len(),10+dlen+24+2+WRAPPED_KEY_CT+32);
        let mut bad=b.clone();
        // Find physical credential tag deterministically near descriptor end:
        // Physical is 2 + u16 length + credential + 32+32+scope+up+uv.
        let tail=10+dlen;
        let physical_prefix=tail-(1+2+b"synthetic-credential".len()+32+32+3);
        assert_eq!(bad[physical_prefix],2);
        let up=tail-2;bad[up]=3;
        assert!(UntrustedEnvelope::decode(&bad).is_err());
        let mut bad=b.clone();
        bad[physical_prefix+1..physical_prefix+3].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(UntrustedEnvelope::decode(&bad).is_err());
        let mut bad=b.clone();bad[tail+24..tail+26].copy_from_slice(&49u16.to_be_bytes());
        assert!(UntrustedEnvelope::decode(&bad).is_err());
    }
    #[test]
    fn mutations_of_secret_authorizing_metadata_bind_vnext_aad(){
        use crate::v02::model::{EntryRecord,Slot};
        let id=id(3);
        let e=EntryRecord{id,revision:1,mode:EntryMode::DefaultPhysical,
            tier:EntryTier::Isolated,recovery:RecoveryPolicy::StrictNone,tombstone:false,
            title:"synthetic title".into(),username:"synthetic username".into(),
            origin:"https://example.test".into(),nonce:[9;24],ciphertext:vec![0;48],
            dek_slots:vec![Slot::pending(SlotTarget::EntryDek,id,
                FactorPolicy::DefaultPhysical)]};
        let a=crate::v02::entry_binding_candidate::entry_aad_vnext(id(1),&e).unwrap();
        let mut changed=e.clone();changed.origin="https://attacker.invalid".into();
        assert_ne!(a,crate::v02::entry_binding_candidate::entry_aad_vnext(id(1),&changed).unwrap());
        changed=e.clone();changed.username.push('!');
        assert_ne!(a,crate::v02::entry_binding_candidate::entry_aad_vnext(id(1),&changed).unwrap());
        changed=e.clone();changed.title.push('!');
        assert_ne!(a,crate::v02::entry_binding_candidate::entry_aad_vnext(id(1),&changed).unwrap());
    }
}
