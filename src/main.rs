mod cli;
mod crypto;
mod fsutil;
mod io;
mod security;
mod util;
mod vault;
mod x11_keysyms;
mod fido2;
mod obfuscate;

use crate::vault::{header::VaultyHeader, init_vault, load_vault};
use std::fs::File;

use aes_gcm::{
    aead::{Aead, KeyInit},
};
use base64::Engine;
use rpassword::read_password;
use std::io::Write;
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
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use crate::cli::menu;
use crate::fsutil::{atomic_write, read_vault, vault_exists};
use crate::vault::entry::VaultyEntry;



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






fn main() -> Result<(), Box<dyn std::error::Error>> {
    // let result = prompt_yes_no("Continue?");
    // println!("Result: {}", result);
    // ctap_register();
    // let result = init_vault()?;

    // let entry = VaultyEntry::new();
    // entry.print_entry();

    // let mut vault = if !vault_exists()? {init_vault()?} else {load_vault()?};

    let pw = util::pw_generator::generate_password(util::pw_generator::CharSet::ALL)?;
    println!("{:?}", pw.expose_secret());
    // vault.add_entry(true, "amazon".to_string(), Some(String::from("username")), SecretString::from("asdasdas"), vec![String::from("amazon.de")], None);
    // atomic_write(&vault.seal_vault()?.serialize()?)?;
    // println!("{:?}", vault.header.metadata.vault_id);
    // if vault.body.entries.len() > 0 {
    //     vault.body.entries[0].print_entry(vault.header.metadata.vault_id, &vault.header.kdf, &vault.derived.vault_secret);
    // }

    // menu(&vault)?;

    // let vh = vault::header::VaultyHeader::new();
    // println!("{:?}", &vh.metadata.vault_id);
    // let vh_bytes = vh.serialize()?;
    // println!("{:?}", &vh_bytes);
    // let (dvh, idx): (VaultyHeader, usize) = VaultyHeader::deserialize(&vh_bytes)?;
    // println!("{:?}", &dvh.metadata.vault_id);
    //ctap_authenticate();
    return Ok(());
}
