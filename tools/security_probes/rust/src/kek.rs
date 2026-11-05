//! OPEN-01: candidate-only two-input/recovery KEK + separate commit-key expansion.
//! This is an interoperability probe; NOT approved key commitment or an AEAD.
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde_json::{json,Value};
use sha2::{Digest,Sha256};

type HmacSha256 = Hmac<Sha256>;
const PREFIX:&[u8]=b"VAULTY-KEK-v0.4-CANDIDATE\0";
fn frame(input:&[u8])->Result<Vec<u8>,String>{
    if input.len()>u16::MAX as usize{return Err("Oversized frame".into());}
    let mut out=(input.len() as u16).to_be_bytes().to_vec();out.extend_from_slice(input);Ok(out)
}
fn context(v:&Value)->Result<Vec<u8>,String>{
    let mut result=Vec::new();
    for field in ["vault_id","target_id","slot_id","purpose","policy"] {
        let s=v.get(field).and_then(Value::as_str).ok_or_else(||format!("Missing {field}"))?;
        if s.is_empty() || s.len()>255{return Err(format!("Invalid {field}"));}
        result.extend(frame(s.as_bytes())?);
    }
    Ok(result)
}
fn decode(v:&Value,field:&str)->Result<Vec<u8>,String>{
    hex::decode(v.get(field).and_then(Value::as_str).ok_or_else(||format!("Missing {field}"))?)
        .map_err(|e|format!("Invalid {field}: {e}"))
}
fn mac(key:&[u8],value:&[u8])->Result<Vec<u8>,String>{
    let mut x=HmacSha256::new_from_slice(key).map_err(|e|e.to_string())?;
    x.update(value);Ok(x.finalize().into_bytes().to_vec())
}
pub fn derive(v:&Value)->Result<Value,String>{
    let mode=v.get("mode").and_then(Value::as_str).ok_or("Missing mode")?;
    if !matches!(mode,"two_factor"|"recovery_code_only") {return Err("Invalid mode".into());}
    let ctx=context(v)?;
    let mut salt_input=PREFIX.to_vec();salt_input.extend_from_slice(b"SALT\0");salt_input.extend(&ctx);
    let salt=Sha256::digest(&salt_input);
    let mut ikm=PREFIX.to_vec();
    if mode=="two_factor"{
        let a=decode(v,"first_component_hex")?;
        let b=decode(v,"prf_component_hex")?;
        if a.len()!=32 || b.len()!=32{return Err("Two-factor input must be 32 bytes each".into());}
        ikm.extend_from_slice(b"TWO-FACTOR\0");ikm.extend(frame(&a)?);ikm.extend(frame(&b)?);
    }else{
        if v.get("first_component_hex").is_some() || v.get("prf_component_hex").is_some(){
            return Err("Code-only slot must not insert fake second factor".into());
        }
        let code=decode(v,"recovery_code_hex")?;
        if code.len()!=32{return Err("Recovery code must be 32 bytes".into());}
        ikm.extend_from_slice(b"CODE-ONLY\0");ikm.extend(frame(&code)?);
    }
    let (prk,hk)=Hkdf::<Sha256>::extract(Some(&salt),&ikm);
    let mut info=PREFIX.to_vec();info.extend_from_slice(b"EXPAND\0");
    info.extend(frame(mode.as_bytes())?);info.extend(&ctx);
    let mut kek=[0u8;32];hk.expand(&info,&mut kek).map_err(|e|e.to_string())?;
    let mut commit_info=PREFIX.to_vec();commit_info.extend_from_slice(b"COMMIT-KEY\0");
    commit_info.extend(frame(mode.as_bytes())?);commit_info.extend(&ctx);
    let mut commit_key=[0u8;32];hk.expand(&commit_info,&mut commit_key).map_err(|e|e.to_string())?;
    let nonce=decode(v,"nonce_hex")?;
    let aad=decode(v,"aad_hex")?;
    let ciphertext=decode(v,"ciphertext_hex")?;
    if nonce.len()!=24 || aad.len()>4096 || ciphertext.is_empty() || ciphertext.len()>4096 {
        return Err("Invalid nonce/AAD/ciphertext length".into());
    }
    let mut commit_input=PREFIX.to_vec();commit_input.extend_from_slice(b"COMMIT-TAG\0");
    commit_input.extend(&ctx);commit_input.extend(frame(&nonce)?);
    commit_input.extend(frame(&aad)?);commit_input.extend(frame(&ciphertext)?);
    let tag=mac(&commit_key,&commit_input)?;
    Ok(json!({"salt_hex":hex::encode(salt),"prk_hex":hex::encode(prk),
        "info_hex":hex::encode(info),"kek_hex":hex::encode(kek),
        "commit_info_hex":hex::encode(commit_info),"commit_key_hex":hex::encode(commit_key),
        "commit_input_hex":hex::encode(commit_input),"commit_tag_hex":hex::encode(tag)}))
}
pub fn verify(doc:&Value)->Result<usize,String>{
    if doc.get("version").and_then(Value::as_str)!=Some("VAULTY-OPEN-01-CANDIDATE-v1") {
        return Err("Invalid vector schema".into());
    }
    let vectors=doc.get("vectors").and_then(Value::as_array).ok_or("Missing vectors")?;
    if vectors.is_empty(){return Err("Empty vectors".into());}
    for v in vectors {
        let got=derive(v)?;
        for (key,value) in got.as_object().ok_or("Invalid output")? {
            if v.get(key)!=Some(value){return Err(format!("Vector {}: {key} mismatch",v["id"]));}
        }
    }
    Ok(vectors.len())
}
