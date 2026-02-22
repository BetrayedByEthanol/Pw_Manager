use std::error::Error;
use std::io::Write;
use std::process::{Command, Stdio};

fn init_gocryptfs() -> Result<(), Box<dyn Error>> {
    let mut status = Command::new("pwd").output()?;
    println!(
        "{}",
        String::from_utf8(status.stdout).expect("Our bytes should be valid utf8")
    );
    println!("Before mkdir");
    status = Command::new("ls").output()?;
    println!(
        "{}",
        String::from_utf8(status.stdout).expect("Our bytes should be valid utf8")
    );

    let mut exit_status = Command::new("mkdir")
        .arg("new_directory")
        .status()
        .expect("Failed to execute mkdir");
    if exit_status.success() {
        println!("Directory created successfully");
    } else {
        eprintln!("mkdir failed with exit code: {:?}", exit_status.code());
    }

    println!("after mkdir");
    status = Command::new("ls").output()?;
    println!(
        "{}",
        String::from_utf8(status.stdout).expect("Our bytes should be valid utf8")
    );

    let mut derived_key = [0u8; 32];

    let mut child = Command::new("gocryptfs")
        .args([
            "-init",
            "-aessiv",
            "-passfile",
            "/dev/stdin",
            "new_directory",
        ])
        .stdin(Stdio::piped())
        // .stdout(Stdio::piped())
        .spawn()?;

    child.stdin.as_mut().unwrap().write_all(&derived_key)?;
    let child_out = child.wait_with_output()?;


    println!("after gocryptfs");
    println!("{:?}", String::from_utf8(child_out.stdout));

    let mut child2 = Command::new("gocryptfs-xray").args(["-dumpmasterkey", "new_directory/gocryptfs.conf"]).stdin(Stdio::piped()).spawn()?;
    child2.stdin.as_mut().unwrap().write_all(&derived_key)?;
    let child_status = child2.wait_with_output()?;

    let err = child_status.stderr;
    println!(
        "XRAY: {:?}\n{:?}",
        String::from_utf8(child_status.stdout).expect("Our bytes should be valid utf8"), String::from_utf8(err)
    );

    println!("before rm");
    status = Command::new("ls").arg("new_directory").output()?;
    println!(
        "{}",
        String::from_utf8(status.stdout).expect("Our bytes should be valid utf8")
    );

    exit_status = Command::new("rm")
        .arg("-R")
        .arg("-f")
        .arg("new_directory")
        .status()
        .expect("Failed to execute rm");
    if exit_status.success() {
        println!("Directory created successfully");
    } else {
        eprintln!("rm failed with exit code: {:?}", exit_status.code());
    }

    println!("after rm");
    status = Command::new("ls").output()?;
    println!(
        "{}",
        String::from_utf8(status.stdout).expect("Our bytes should be valid utf8")
    );
    Ok(())
}