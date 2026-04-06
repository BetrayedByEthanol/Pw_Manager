use std::path::{Path, PathBuf};
use std::fs;
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::process::{Command, Stdio};
use rpassword::read_password;
use crate::crypto::{
    create_new_header, decrypt_vault,
    encrypt_vault,
    VaultHeader, VaultPayload,
};
use crate::fsutil::atomic_write_with_backup;
use secrecy::{Secret, ExposeSecret};

use uuid::Uuid;

mod schema;
mod operations;
mod session;
mod entry;
mod metadata;
mod manager;
mod error;
pub mod body;
pub mod header;
mod payload;

fn prompt_pw() -> Result<Secret<String>, Box<dyn std::error::Error>> {
    print!("Master password: ");
    std::io::stdout().flush()?;
    match read_password() {
        Ok(pw) => Ok(Secret::new(pw)),
        Err(e) => {
            eprintln!("\n[ERROR] Secure input unavailable: {e}");
            eprintln!("[ERROR] Aborting — refusing to prompt with echo enabled.");
            Err(e.into())
        }
    }
}
pub fn init_vault() -> Result<(), Box<dyn std::error::Error>> {

    println!("{}", env::current_dir().unwrap().display());
    let exe_path = env::current_exe().expect("Failed to get executable path");
    let exe_dir = exe_path.parent().expect("Failed to get executable directory");

    println!("Executable directory: {}", exe_dir.display());
    let vault_dir = exe_dir.join("vault");
    let mount_dir = exe_dir.join("mount");
    if vault_dir.exists() {
        println!("Removing existing vault directory");
        fs::remove_dir_all(vault_dir.clone())?;
    }
    if mount_dir.exists() {
        println!("Removing existing mount directory");
        fs::remove_dir_all(mount_dir.clone())?;
    }
    println!("Creating vault directory:");

    fs::create_dir(vault_dir.clone())?;
    fs::create_dir(mount_dir.clone())?;
    // let vault_pw = prompt_pw()?;

    let mut child = Command::new("gocryptfs")
        .args([
            "-init",
            "-aessiv",
            "-passfile",
            "/dev/stdin",
            vault_dir.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        // .stdout(Stdio::piped())
        .spawn()?;
    // println!("{:?}", vault_pw.expose_secret());
    child.stdin.as_mut().unwrap().write_all("asdasd".as_bytes())?;
    let child_out = child.wait_with_output()?;
    println!("Mounting vault: {:}", child_out.status);
    // child = Command::new("gocryptfs-xray").args(["-dumpmasterkey", vault_dir.to_str().unwrap()]).stdin(Stdio::piped()).spawn()?;

    child = Command::new("gocryptfs")
        .args([
            vault_dir.to_str().unwrap(),
            mount_dir.to_str().unwrap()
        ])
        .stdin(Stdio::piped())
        .spawn()?;

    child.stdin.as_mut().unwrap().write_all("asdasd".as_bytes())?;
    child.wait()?;
    println!("Creating test file");
    File::create(mount_dir.join("test.txt"))?.write_all(
        "Hello, world!".as_bytes()
    ).expect("Failed to write file");

    child = Command::new("umount").args([mount_dir.to_str().unwrap()]).spawn()?;
    child.wait()?;
    Ok(())

}

pub struct LoadedVault {
    pub header: VaultHeader,
    pub payload: VaultPayload,
    pub master_pw: String,
    pub path: PathBuf,
    pub backup_dir: PathBuf,
}

impl LoadedVault {
    pub fn load(path: &Path, master_pw: String) -> Result<Self, Box<dyn std::error::Error>> {
        let backup_dir = path.join("backups");
        let data_file = path.join("data.dat");


        if !backup_dir.exists() {
            fs::create_dir(backup_dir.to_str().unwrap()).unwrap();
        }

        if !data_file.exists(){
            let header = create_new_header();
            let payload = VaultPayload {
                vault_id: Uuid::new_v4().to_string(),
                created_at: now(),
                updated_at: now(),
                items: vec![],
            };
            let out = encrypt_vault(&master_pw, header.clone(), &payload)?;
            atomic_write_with_backup(&data_file, &backup_dir, &out)?;

            return Ok(LoadedVault {
                header,
                payload,
                master_pw,
                path: data_file.to_path_buf(),
                backup_dir,
            })
        }

        let data = fs::read(data_file.clone())?;
        let (header, payload) = decrypt_vault(&master_pw, &data)?;

        Ok(LoadedVault {
            header,
            payload,
            master_pw,
            path: data_file.to_path_buf(),
            backup_dir,
        })
    }
}

fn now() -> String {
    // Minimal ISO-like timestamp
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("T{secs}")
}