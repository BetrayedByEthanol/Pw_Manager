//! V01-A synthetic, end-to-end smoke test of the shipping entry point.
use std::fs;
use std::process::Command;
use uuid::Uuid;

#[test]
fn default_binary_fails_closed_without_file_or_secret_side_effects() {
    let directory = std::env::temp_dir().join(format!("vaulty-inert-{}", Uuid::new_v4()));
    fs::create_dir(&directory).unwrap();
    let sentinel = directory.join("vault");
    fs::write(&sentinel, b"ENCRYPTED_PREEXISTING_VAULT_SENTINEL").unwrap();
    let password = "SYNTHETIC_DO_NOT_PRINT_PASSWORD_123";
    let pin = "SYNTHETIC_DO_NOT_PRINT_PIN_456";
    let output = Command::new(env!("CARGO_BIN_EXE_pw_manager"))
        .current_dir(&directory)
        .env("MASTER_PASSWORD", password)
        .env("PIN", pin)
        .output()
        .unwrap();
    assert!(!output.status.success(), "shipping prototype must exit nonzero");
    assert!(output.stdout.is_empty(), "stdout must contain no revealed credentials");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("development prototype"), "state the fail-closed reason");
    assert!(!stderr.contains(password));
    assert!(!stderr.contains(pin));
    assert_eq!(fs::read(&sentinel).unwrap(), b"ENCRYPTED_PREEXISTING_VAULT_SENTINEL");
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 1,
        "must not initialize vault, create lock/tmp/backup, or write files");
    fs::remove_dir_all(directory).unwrap();
}
