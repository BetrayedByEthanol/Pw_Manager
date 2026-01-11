mod cli;
mod crypto;
mod fsutil;
mod io;
mod security;
mod util;
mod vault;
mod x11_keysyms;
use crate::vault::LoadedVault;
use crate::x11_keysyms as xk;

use rpassword::read_password;
use std::collections::HashSet;
use std::error::Error;
use std::io::Write;
use std::thread;
use std::time::Duration;
use x11rb::connection::Connection;
use x11rb::protocol::Event;
use x11rb::protocol::xinput::DeviceId;
use x11rb::protocol::xinput::{self, ConnectionExt as _};
use x11rb::protocol::xproto::*;
use x11rb::protocol::xtest::fake_input;
use x11rb::rust_connection::RustConnection;
use x11rb::{CURRENT_TIME};

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

fn find_keycode_for_keysym(
    conn: &RustConnection,
    keysym: u32,
) -> Result<Option<u8>, Box<dyn Error>> {
    let setup = conn.setup();
    let min = setup.min_keycode;
    let max = setup.max_keycode;
    let count = max - min + 1;

    let reply = conn.get_keyboard_mapping(min, count)?.reply()?;
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

fn grab_keyboard(
    conn: &RustConnection,
    root: Window,
) -> Result<(Vec<DeviceId>, Option<DeviceId>), Box<dyn Error>> {
    let all_devices = xinput::Device::ALL;
    let reply = conn.xinput_xi_query_device(all_devices)?.reply()?;
    let mut device_ids = vec![];
    let mut xdevice: Option<DeviceId> = None;
    for device_info in &reply.infos {
        let dev = String::from_utf8_lossy(&device_info.name);
        println!(
            "{} {:?}: {}",
            device_info.deviceid,
            (device_info.type_),
            dev
        );

        let device_id = device_info.deviceid;
        let device_name = String::from_utf8_lossy(&device_info.name);
        if device_name.contains("XTEST") {
            xdevice = Some(device_id);
        }
        if device_info.type_ == xinput::DeviceType::SLAVE_KEYBOARD && !device_name.contains("XTEST")
        {
            let mask: Vec<u32> = vec![u32::from(
                xinput::XIEventMask::KEY_PRESS | xinput::XIEventMask::KEY_RELEASE,
            )];

            let reply = conn
                .xinput_xi_grab_device(
                    root,
                    CURRENT_TIME,
                    x11rb::NONE,
                    device_id,
                    GrabMode::ASYNC,
                    GrabMode::ASYNC,
                    xinput::GrabOwner::from(false),
                    &mask,
                )?
                .reply()?;

            if reply.status == GrabStatus::SUCCESS {
                println!("Successfully grabbed device {}", device_id);
                device_ids.push(device_id);
            } else {
                println!("Failed to grab device {}: {:?}", device_id, reply.status);
            }

        }
        println!();
    }
    Ok((device_ids, xdevice))
}

fn ungrab_keyboard(conn: &RustConnection, device_ids: Vec<DeviceId>) -> Result<(), Box<dyn Error>> {
    for device_id in device_ids {
        println!("Ungrabbing keyboard ID: {}", device_id);
        conn.xinput_xi_ungrab_device(CURRENT_TIME, device_id)?;
    }
    conn.flush()?;
    Ok(())
}

const KEY_PRESS: u8 = 2;
const KEY_RELEASE: u8 = 3;
const BUTTON_PRESS: u8 = 4;
const BUTTON_RELEASE: u8 = 5;
const MOTION_NOTIFY: u8 = 6;

fn type_char(
    conn: &RustConnection,
    root: Window,
    ch: char,
    device_id: u8,
) -> Result<(), Box<dyn Error>> {
    let keysym = ch as u32;
    if let Some(kc) = find_keycode_for_keysym(conn, keysym)? {
        println!("{}", kc);
        fake_input(&conn, KEY_PRESS, kc, 0, root, 0, 0, device_id)?;
        fake_input(&conn, KEY_RELEASE, kc, 0, root, 0, 0, device_id)?;
        conn.flush()?;
    }
    Ok(())
}

fn enable_xi2_raw_keys(
    conn: &RustConnection,
    root: Window,
) -> Result<(), Box<dyn std::error::Error>> {
    conn.xinput_xi_query_version(2, 0).unwrap().reply()?;
    let mask = xinput::EventMask {
        deviceid: xinput::Device::ALL_MASTER.into(),
        mask: vec![xinput::XIEventMask::RAW_KEY_PRESS | xinput::XIEventMask::RAW_KEY_RELEASE],
    };
    conn.xinput_xi_select_events(root, &[mask])?;
    conn.flush()?;
    Ok(())
}

fn freeze_inject_restore(
    conn: &RustConnection,
    root: Window,
    phys_down: &mut HashSet<u8>,
    ctrl_keycodes: &HashSet<u8>,
    text: &str,
) -> Result<(), Box<dyn Error>> {
    let keyboards = grab_keyboard(&conn, root)?;
    let device_ids = keyboards.0;
    let xdevice = keyboards.1.unwrap();

    // Make queue?
    let mut ctrl_keycodes_to_press: HashSet<u8> = phys_down.intersection(ctrl_keycodes).cloned().collect();

    for &kc in ctrl_keycodes.union(&(phys_down.clone())) {
        println!("masking ctrl key {}", &kc);
        fake_input(&conn, KEY_RELEASE, kc, 0, root, 0, 0, 0)?;
    }

    while let Some(_e) = conn.poll_for_event()? {
        thread::sleep(Duration::from_millis(200));
    }

    conn.flush()?;

    for ch in text.chars() {
        type_char(&conn, root, ch, xdevice as u8)?;
        println!();
        thread::sleep(Duration::from_millis(200));
    }

    while let Some(e) = conn.poll_for_event().unwrap() {
        if let Event::XinputRawKeyPress(kr) = e.clone() {
            if ctrl_keycodes.contains(&(kr.detail as u8)) {
                println!("pressed control key during typing {}", &kr.detail);
                phys_down.insert(kr.detail as u8);
            }
        }
        if let Event::XinputRawKeyRelease(kr) = e.clone() {
            if ctrl_keycodes.contains(&(kr.detail as u8)) {
                println!("released control key during typing {}", &kr.detail);
                phys_down.remove(&(kr.detail as u8));
            }
        }
    }

    for &kc in phys_down.intersection(ctrl_keycodes) {
        println!("restoring ctrl key {}", &kc);
        fake_input(&conn, KEY_PRESS, kc, 0, root, 0, 0, 0)?;
    }
    conn.flush()?;


    // for &kc in ctrl_keycodes.iter() {
    //     println!("masking ctrl key {}", &kc);
    //     fake_input(&conn, KEY_RELEASE, kc, 0, root, 0, 0, 0)?;
    // }

    ungrab_keyboard(conn, device_ids)?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (conn, screen_num) = RustConnection::connect(None)?;
    let root = conn.setup().roots[screen_num].root;

    enable_xi2_raw_keys(&conn, root)?;

    let hotkey_kc = find_keycode_for_keysym(&conn, xk::XK_b as u32)?
        .or_else(|| find_keycode_for_keysym(&conn, xk::XK_B as u32).unwrap())
        .ok_or("Could not find keycode for B")?;

    // Resolve Control keycodes
    let ctrl_l = find_keycode_for_keysym(&conn, xk::XK_Control_L as u32)?;
    let ctrl_r = find_keycode_for_keysym(&conn, xk::XK_Control_R as u32)?;
    let ctrl_keycodes: HashSet<u8> = [ctrl_l, ctrl_r].into_iter().flatten().collect();

    let mut physically_pressed: HashSet<u8> = HashSet::new();
    let mut triggered = false;
    let mut b_down = false;
    loop {
        let ev = conn.wait_for_event()?;

        match ev {
            Event::XinputRawKeyPress(e) => {
                if ctrl_keycodes.contains(&(e.detail as u8)) {
                    physically_pressed.insert(e.detail as u8);
                    println!("ctrl physically pressed");
                }
                let mut ctrl_down = physically_pressed
                    .iter()
                    .any(|kc| ctrl_keycodes.contains(kc));

                if e.detail as u8 == hotkey_kc {
                    b_down = true;
                    physically_pressed.insert(e.detail as u8);
                }

                if ctrl_down && b_down && !triggered {
                    triggered = true;
                    b_down = false;
                    freeze_inject_restore(
                        &conn,
                        root,
                        &mut physically_pressed,
                        &mut ctrl_keycodes.clone(),
                        "hello",
                    )?;
                }
            }
            Event::XinputRawKeyRelease(e) => {
                if ctrl_keycodes.contains(&(e.detail as u8)) {
                    physically_pressed.remove(&(e.detail as u8));
                    println!("ctrl physically released");
                }
                let mut ctrl_down = physically_pressed
                    .iter()
                    .any(|kc| ctrl_keycodes.contains(kc));

                if !(e.detail as u8 == hotkey_kc) && b_down {
                    b_down = false;
                    physically_pressed.remove(&(e.detail as u8));
                }

                if !(ctrl_down && b_down) {
                    triggered = false;
                }
            }
            _ => {}
        }
    }

}