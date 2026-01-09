mod vault;
mod crypto;
mod fsutil;
mod cli;
mod io;
mod security;
mod util;
mod x11_keysyms;

use std::{env, fs};
use std::fs::File;
use std::io::{ Write};
use std::path::Path;
use tempfile::TempDir;
use enigo::{Key, Enigo, Keyboard, Settings};
use global_hotkey::{hotkey::{Code, HotKey, Modifiers}, GlobalHotKeyManager, GlobalHotKeyEvent};
use std::thread;
use std::time::{Duration, Instant};
use std::collections::HashSet;
use std::error::Error;
use crate::vault::LoadedVault;
use rpassword::read_password;
use x11rb::connection::Connection;
use x11rb::protocol::xproto::*;
use x11rb::protocol::xtest::fake_input;
use x11rb::rust_connection::RustConnection;
use x11rb::protocol::Event;
use x11rb::CURRENT_TIME;
use crate::x11_keysyms as xk;


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


fn find_keycode_for_keysym(
    conn: &RustConnection,
    keysym: u32,
) -> Result<Option<u8>, Box<dyn Error>> {
    let setup = conn.setup();
    let min = setup.min_keycode;
    let max = setup.max_keycode;
    let count = max - min + 1;

    let reply = conn.get_keyboard_mapping(min, count).unwrap().reply().unwrap();
    let per = reply.keysyms_per_keycode as usize;
    let keysyms = reply.keysyms;
    for i in 0..count as usize {
        let kc = min + i as u8;
        let slice = &keysyms[i * per..(i + 1) * per];
        if slice.iter().any(|&ks| ks == keysym) {
            return Ok(Some(kc));
        }
    }
    Ok(None)
}

const KEY_PRESS: u8 = 2;
const KEY_RELEASE: u8 = 3;
const BUTTON_PRESS: u8 = 4;
const BUTTON_RELEASE: u8 = 5;
const MOTION_NOTIFY: u8 = 6;

fn type_char(conn: &RustConnection, root: Window, ch: char) -> Result<(), Box<dyn Error>> {
    let keysym = ch as u32;
    if let Some(kc) = find_keycode_for_keysym(conn, keysym).unwrap() {
        println!("{}",kc);
        fake_input(&conn, KEY_PRESS, kc, 0, root, 0, 0, 0).unwrap();
        fake_input(&conn, KEY_RELEASE, kc, 0, root, 0, 0, 0).unwrap();
        conn.flush().unwrap();
    }
    Ok(())
}



fn type_with_keyboard_grab(
    conn: &RustConnection,
    root: Window,
    ctrl_keycodes: &HashSet<u8>,
    text: &str,
) -> Result<(), Box<dyn Error>> {
    println!("start");

    let grab = conn.grab_keyboard(false, root, CURRENT_TIME, GrabMode::ASYNC, GrabMode::ASYNC)?;
    if grab.reply().unwrap().status != GrabStatus::SUCCESS {
        return Ok(());
    }
    conn.ungrab_keyboard(CURRENT_TIME).unwrap();
    conn.flush().unwrap();

    for &kc in ctrl_keycodes {
        fake_input(&conn, KEY_RELEASE, kc, 0, root, 0, 0, 0).unwrap();
    }
    conn.flush().unwrap();
    thread::sleep(Duration::from_millis(200));

    let mut saw_real_ctrl_release = false;

    while let Some(e) = conn.poll_for_event().unwrap() {
        thread::sleep(Duration::from_millis(5));
    }

    for ch in text.chars() {
        // FLUSH CONNECTION EVENT POLL !!!
        while let Some(e) = conn.poll_for_event().unwrap() {
            if let Event::KeyRelease(kr) = e {
                if ctrl_keycodes.contains(&kr.detail) {
                    println!("released control key during typing {}", &kr.detail);
                    saw_real_ctrl_release = true;
                } else {
                    println!("released character key {}", &kr.detail);
                }
            }
        }

        type_char(conn, root, ch).unwrap();
        println!("");
        thread::sleep(Duration::from_millis(200));
    }


    while let Some(e) = conn.poll_for_event().unwrap() {
        if let Event::KeyRelease(kr) = e {
            if ctrl_keycodes.contains(&kr.detail) {
                println!("released control key during clean up {}", &kr.detail);
                saw_real_ctrl_release = true;
            }
        }
    }


    if !saw_real_ctrl_release {
        for &kc in ctrl_keycodes {
            // fake_input(&conn, KEY_PRESS, kc, 0, root, 0, 0, 0).unwrap();
        }
        conn.flush().unwrap();
    }
    for &kc in ctrl_keycodes {
        fake_input(&conn, KEY_RELEASE, kc, 0, root, 0, 0, 0).unwrap();
    }

    Ok(())
}


fn main() {

    let (conn, screen_num) = RustConnection::connect(None).unwrap();
    let root = conn.setup().roots[screen_num].root;

    // Resolve hotkey keycode (try lowercase then uppercase)
    let hotkey_kc = find_keycode_for_keysym(&conn, xk::XK_b as u32).unwrap()
        .or_else(|| find_keycode_for_keysym(&conn, xk::XK_B as u32).unwrap())
        .ok_or("Could not find keycode for B").unwrap();

    // Resolve Control keycodes
    let ctrl_l = find_keycode_for_keysym(&conn, xk::XK_Control_L as u32).unwrap();
    let ctrl_r = find_keycode_for_keysym(&conn, xk::XK_Control_R as u32).unwrap();
    let ctrl_keycodes: HashSet<u8> = [ctrl_l, ctrl_r].into_iter().flatten().collect();

    let ctrl_mask = KeyButMask::CONTROL;
    for extra in [0u16, u16::from(ModMask::LOCK), u16::from(ModMask::M2)] {
        conn.grab_key(
            false,
            root,
            ModMask::from(u16::from(ctrl_mask) | extra),
            hotkey_kc,
            GrabMode::ASYNC,
            GrabMode::ASYNC,
        ).unwrap();
    }
    conn.flush().unwrap();

    loop {
        let ev = conn.wait_for_event().unwrap();
        if let Event::KeyPress(kp) = ev {
            if kp.detail == hotkey_kc && (kp.state & ctrl_mask) == ctrl_mask {
                type_with_keyboard_grab(&conn, root, &ctrl_keycodes, "hello").unwrap();
            }
        }
    }

    // let manager = GlobalHotKeyManager::new().unwrap();
    //
    // let hotkey = HotKey::new(Some(Modifiers::CONTROL), Code::KeyB);
    // let mut last_triggered = Instant::now();
    // let debounce_delay = Duration::from_millis(500);
    // // Register the hotkey
    // manager.register(hotkey).unwrap();
    // let receiver = GlobalHotKeyEvent::receiver();
    //
    // let (conn, screen_num) = RustConnection::connect(None).unwrap();
    //
    // loop {
    //     if let Ok(event) = receiver.try_recv() {
    //         if event.id == hotkey.id() {
    //             let now = Instant::now();
    //             if now.duration_since(last_triggered) <= debounce_delay {
    //                 continue;
    //             }
    //
    //             last_triggered = now;
    //             println!("Hotkey pressed! Typing 'hello'...");
    //
    //             // Small delay to allow the hotkey to be released
    //             thread::sleep(Duration::from_millis(100));
    //
    //             // Autotype "hello"
    //             autotype_text("hello");
    //         }
    //     }
    //
    //     // Small sleep to avoid busy-waiting
    //     thread::sleep(Duration::from_millis(10));
    // }

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
