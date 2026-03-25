mod cli;
mod crypto;
mod fsutil;
mod io;
mod security;
mod util;
mod vault;
mod x11_keysyms;

use crate::vault::LoadedVault;
use std::fs::File;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::Engine;
use base64::engine::GeneralPurpose;
use rand::RngCore;
use rpassword::read_password;
use std::io::Write;
use std::path::Path;
use webauthn_rs::prelude::PublicKeyCredential;
// use scrypt::{Params, scrypt};
use crossterm::event::{Event, KeyCode, read};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ctap_hid_fido2::{
    FidoKeyHid, FidoKeyHidFactory,
    fidokey::{
        AssertionExtension, GetAssertionArgsBuilder, MakeCredentialArgsBuilder,
        credential_management::credential_management_params::CredentialProtectionPolicy,
    },
    public_key::{self, PublicKey},
    public_key_credential_user_entity::PublicKeyCredentialUserEntity,
    verifier,
};
use fido2_rs::credentials::{Credential, Opt};
use fido2_rs::device::{Device, DeviceList};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::process::{Command, Stdio};

fn prompt_pw() -> String {
    print!("Master password: ");
    std::io::stdout().flush().unwrap();
    read_password().unwrap_or_else(|_| {
        eprintln!("\nSecure input not available, falling back to visible input.");
        let mut pw = String::new();
        std::io::stdin().read_line(&mut pw).unwrap();
        pw.trim_end().to_string()
    })
}

fn fido_rs() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Scanning for FIDO2 devices...\n");
    let devices: DeviceList = DeviceList::list_devices(5);
    for dev in devices {
        println!("{:?}", dev);
        let device = dev.open()?;
        print!("{:}", device.is_fido2()); // prints true!
        let mut credentials = Credential::new();

        // credentials.set_id("Test".as_bytes())?;
        // credentials.set_rk(Opt::True)?;
        // credentials.set_rp();
        // credentials.set_uv();
        // credentials.set_client_data();
        // credentials.set_attestation_format();
        // credentials.set_client_data_hash();
        // credentials.set_cose_type();
        // credentials.set_extension();
        // credentials.set_protection();
        // credentials.set_pin_min_len();
        // credentials.set_blob();
        // credentials.set_user();

        break;
    }
    Ok(())
}

fn ctap_register() -> Result<(), Box<dyn std::error::Error>> {
    let device = FidoKeyHidFactory::create(&ctap_hid_fido2::Cfg::init()).unwrap();
    println!("{:}", device.get_info()?);
    let mut buf = vec![0u8; 32];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut buf);
    const RP_ID: &str = "example.com";
    let username = "alice";
    let args = MakeCredentialArgsBuilder::new(RP_ID, &buf)
        .user_entity(
            &(PublicKeyCredentialUserEntity::new(
                Some(username.as_bytes()),
                Some(username),
                Some(username),
            )),
        )
        .pin("miControl")
        .resident_key()
        .build();
    let attestation = device.make_credential_with_args(&args)?;
    println!("{:}", attestation);
    let verify = verifier::verify_attestation(RP_ID, &buf, &attestation);
    println!("{:}", verify.is_success);
    println!("{:}", hex::encode(verify.credential_id));
    let pub_key = verify.credential_public_key.clone();
    // PublicKey::with_der(&pub_key.der, public_key::PublicKeyType::Ecdsa256);
    println!("{:}", hex::encode(verify.credential_public_key.der));
    Ok(())
}

fn ctap_authenticate() -> Result<(), Box<dyn std::error::Error>> {
    let device = FidoKeyHidFactory::create(&ctap_hid_fido2::Cfg::init()).unwrap();
    print!("{:}", device.get_info()?);
    let mut buf = vec![0u8; 32];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut buf);
    const RP_ID: &str = "example.com";
    let username = "alice";
    
    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut salt);
    
    // let extension = AssertionExtension::create_hmac_secret_from_string("Test");
    let extension = AssertionExtension::HmacSecret(Some(salt));


    let args = GetAssertionArgsBuilder::new(RP_ID, &buf)
    .credential_id(&(hex::decode("2F64CF4A6F7CBED2A1720CBAE18C2A14F5A6BE3C6B971BEF9DBC8713367D25BE45B524D7869B907070FA2074E3C3DE78").unwrap()))
    .pin("miControl")
    .extensions(&[extension])
    .build();

    // challenge
    // rpId
    // signature
    // (optionally) sign_count

    let publickey = hex::decode(
        "042F64CF4A6F7CBED2A1720CBAE1F09563BFFFDE3965E2FD9B298448B466E8B152690A6E8F310AA3216BD9D9AD90D267C552EBE1F29A3C8A7BFF1635C4BEBBA9A6",
    )?;
    let assertion = device.get_assertion_with_args(&args)?;
    let assert = assertion.get(0).unwrap();
    let prf: [u8; 32] = assert
        .extensions
        .iter()
        .find_map(|e| match e {
            AssertionExtension::HmacSecret(Some(bytes)) => Some(*bytes),
            _ => None,
        }).unwrap();
    println!("{:?}", prf);
    let verify = verifier::verify_assertion(
        RP_ID,
        &(PublicKey::with_der(&publickey, public_key::PublicKeyType::Ecdsa256)),
        &buf,
        &(assert),
    );
    println!("{:}", verify);
    Ok(())
}

fn prompt_yes_no(question: &str) -> bool {
    print!("{} (y/n)", question);

    std::io::stdout().flush().unwrap();

    enable_raw_mode().unwrap();

    let result = loop {
        if let Event::Key(event) = read().unwrap() {
            match event.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => break true,
                KeyCode::Char('n') | KeyCode::Char('N') => break false,
                _ => {}
            }
        }
    };

    disable_raw_mode().unwrap();
    println!();
    result
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // let result = prompt_yes_no("Continue?");
    // println!("Result: {}", result);
    // ctap_register();
    let vh = vault::header::VaultyHeader::new();
    //ctap_authenticate();
    return Ok(());
}
