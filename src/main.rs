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
use enigo::{Key, Enigo, Keyboard, Settings};
use global_hotkey::{hotkey::{Code, HotKey, Modifiers}, GlobalHotKeyManager, GlobalHotKeyEvent};
use std::thread;
use std::time::{Duration, Instant};
use crate::vault::LoadedVault;
use rpassword::read_password;
use x11rb::connection::Connection;
use x11rb::protocol::xproto::*;
use x11rb::rust_connection::RustConnection;
use x11rb::protocol::Event;
use x11_keysyms as xk;


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

fn autotype_text(text: &str) {
    let mut enigo = Enigo::new(&Settings::default()).unwrap();
    enigo.key(Key::LControl, enigo::Direction::Release);
    enigo.key(Key::RControl, enigo::Direction::Release);

    for ch in text.chars() {
        enigo.key(Key::Unicode(ch), enigo::Direction::Click).unwrap();
        thread::sleep(Duration::from_millis(10)); // Small delay between keystrokes
    }

    enigo.key(Key::LControl, enigo::Direction::Press);
    enigo.key(Key::RControl, enigo::Direction::Press);

}


fn main() {
    let manager = GlobalHotKeyManager::new().unwrap();

    let hotkey = HotKey::new(Some(Modifiers::CONTROL), Code::KeyB);
    let mut last_triggered = Instant::now();
    let debounce_delay = Duration::from_millis(500);
    // Register the hotkey
    manager.register(hotkey).unwrap();
    let receiver = GlobalHotKeyEvent::receiver();

    let (conn, screen_num) = RustConnection::connect(None).unwrap();

    loop {
        if let Ok(event) = receiver.try_recv() {
            if event.id == hotkey.id() {
                let now = Instant::now();
                if now.duration_since(last_triggered) <= debounce_delay {
                    continue;
                }

                last_triggered = now;
                println!("Hotkey pressed! Typing 'hello'...");

                // Small delay to allow the hotkey to be released
                thread::sleep(Duration::from_millis(100));

                // Autotype "hello"
                autotype_text("hello");
            }
        }

        // Small sleep to avoid busy-waiting
        thread::sleep(Duration::from_millis(10));
    }

    println!("Done");
    // let path = Path::new("/home/admin/sec");
    // let tmp = TempDir::new().unwrap();
    // let path2 = tmp.path();
    // let exe_path = env::current_exe().expect("cannot get exe path");
    // let exe_dir = exe_path.parent().unwrap();
    // println!("{:?}", path2);
    // let target = path.join("vault");
    // fs::create_dir(target.clone()).unwrap();
    // let mut f = File::create(target.join("data.dat")).unwrap();
    // f.write("Hello, world!".as_bytes()).unwrap();
    //
    // for entry in path.read_dir().unwrap() {
    //     println!("{:?}", entry.unwrap().path());
    // }
    // for entry in exe_dir.read_dir().unwrap() {
    //     println!("Exec dir {:?}", entry.unwrap().path());
    // }
    // fs::remove_dir_all(target).unwrap();
    //
    // // If the vault exists, mount dir and load it.
    // let res = std::process::Command::new("ls").output().unwrap().stdout;
    // println!("ls {:?}", String::from_utf8_lossy(&res));

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
