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

use rpassword::read_password;
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
use ctap_hid_fido2::{FidoKeyHid};


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



fn main() -> Result<(), Box<dyn std::error::Error>> {
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


    return Ok(());
}
