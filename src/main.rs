mod vault;
mod crypto;
mod fsutil;
mod cli;
mod io;
mod security;
mod util;

use std::{env, fs};
use std::fs::File;
use std::io::{ Write};
use std::path::Path;
use tempfile::TempDir;

use crate::vault::LoadedVault;
use rpassword::read_password;

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

fn main() {
    let path = Path::new("/home/admin/sec");
    let tmp = TempDir::new().unwrap();
    let path2 = tmp.path();
    let exe_path = env::current_exe().expect("cannot get exe path");
    let exe_dir = exe_path.parent().unwrap();
    println!("{:?}", path2);
    let target = path.join("vault");
    fs::create_dir(target.clone()).unwrap();
    let mut f = File::create(target.join("data.dat")).unwrap();
    f.write("Hello, world!".as_bytes()).unwrap();

    for entry in path.read_dir().unwrap() {
        println!("{:?}", entry.unwrap().path());
    }
    for entry in exe_dir.read_dir().unwrap() {
        println!("Exec dir {:?}", entry.unwrap().path());
    }
    fs::remove_dir_all(target).unwrap();

    // If the vault exists, mount dir and load it.
    let res = std::process::Command::new("ls").output().unwrap().stdout;
    println!("ls {:?}", String::from_utf8_lossy(&res));

    // else create a new one.


    // let args: Vec<String> = env::args().collect();
    // if args.len() < 2 {
    //     eprintln!("Commands: list | add | show <id> | search <text>");
    //     return ();
    // }
    // let cmd = args[1].as_str();
    // let pw = prompt_pw();
    // let exe = env::current_exe().unwrap();
    // let parent = exe.parent().unwrap().parent()
    //     .map(|p| p.to_path_buf())
    //     .ok_or_else(|| std::io::Error::new(
    //         std::io::ErrorKind::NotFound,
    //         "Executable has no parent directory"
    //     )).expect("Wrong path");
    // let path = Path::new("/home/admin/sec");
    // let mut vault = LoadedVault::load(path, pw).unwrap();
    //
    // println!("Hello, world! {0}", path.to_str().unwrap());
}
