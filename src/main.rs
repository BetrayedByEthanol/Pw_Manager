mod cli;
mod crypto;
mod fsutil;
mod io;
mod security;
mod util;
mod vault;
mod x11_keysyms;

use std::fs::File;
use crate::vault::LoadedVault;

use rand::RngCore;
use rpassword::read_password;
use webauthn_rs::prelude::PublicKeyCredential;
use std::io::Write;
use std::path::Path;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::Engine;
use base64::engine::GeneralPurpose;
use scrypt::{Params, scrypt};
use serde::Deserialize;
use std::process::{Command, Stdio};
use sha2::{Sha256, Digest};
use fido2_rs::device::{ Device, DeviceList};
use fido2_rs::credentials::{Credential, Opt};
use ctap_hid_fido2::{
    FidoKeyHid, FidoKeyHidFactory, fidokey::{
        GetAssertionArgsBuilder, MakeCredentialArgsBuilder, credential_management::credential_management_params::CredentialProtectionPolicy
    }, public_key::{self, PublicKey}, public_key_credential_user_entity::PublicKeyCredentialUserEntity, verifier
};


fn prompt_pw() -> String {
    print!("Master password: ");
    std::io::stdout().flush().unwrap();
    let password = read_password().unwrap_or_else(|_| {
        eprintln!("\nSecure input not available, falling back to visible input.");
        let mut pw = String::new();
        std::io::stdin().read_line(&mut pw).unwrap();
        pw.trim_end().to_string()
    });
    password
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
    .user_entity(&(PublicKeyCredentialUserEntity::new(Some(username.as_bytes()), Some(username),Some( username))))
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Ok");
    let device = FidoKeyHidFactory::create(&ctap_hid_fido2::Cfg::init()).unwrap();    
    print!("{:}", device.get_info()?);
    let mut buf = vec![0u8; 32];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut buf);
    const RP_ID: &str = "example.com";
    let username = "alice";
    let args = GetAssertionArgsBuilder::new(RP_ID, &buf)
    .credential_id(&(hex::decode("92C512FA21CFD44088E87A547909403609D3A4064AC417F823C3BEBAC93AFEE3A9BDDD41557413FA530E30D2008E0E7E").unwrap()))
    .pin("miControl")
    .build();

    let publickey = hex::decode("0492C512FA21CFD44088E87A5479DEBF1616C13640DC8E2CFE1B1569EB0F981FF1724C2DFDB0207680BA36DEB2B320CC49058D693F8DE6386F8AF5F2CE2C9954D4")?;
    let assertion = device.get_assertion_with_args(&args)?;
    let verify = verifier::verify_assertion(RP_ID, &(PublicKey::with_der(&publickey, public_key::PublicKeyType::Ecdsa256)), &buf, &(assertion.get(0).unwrap()));
    println!("{:}", verify);
    return Ok(());
}
