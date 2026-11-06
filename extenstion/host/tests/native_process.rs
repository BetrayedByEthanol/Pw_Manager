//! Native messaging process boundary: only framed JSON, never a fake secret.
use std::io::{Read, Write};
use std::process::{Command, Stdio};

fn spawn_native(payload: &[u8]) -> std::process::Output {
    let mut process = Command::new(env!("CARGO_BIN_EXE_vaulty-native-host"))
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    process.stdin.take().unwrap().write_all(payload).unwrap();
    process.wait_with_output().unwrap()
}
fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut packet = (bytes.len() as u32).to_ne_bytes().to_vec();
    packet.extend_from_slice(bytes);
    packet
}
fn unpack(bytes: &[u8]) -> serde_json::Value {
    assert!(bytes.len() >= 4, "missing native length prefix");
    let n = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize;
    assert_eq!(bytes.len(), n + 4, "one framed JSON response, no extra stdout");
    serde_json::from_slice(&bytes[4..]).unwrap()
}
#[test]
fn save_request_never_claims_to_persist_or_echoes_secret() {
    let request = br#"{"requestId":"req_1","type":"SAVE_CREDENTIAL","origin":"https://example.org","credential":{"username":"u","password":"SYNTHETIC_SUPPLIED_SECRET_ABC"}}"#;
    let output = spawn_native(&frame(request));
    assert!(output.status.success(), "validated request gives structured UNAVAILABLE response");
    assert!(output.stderr.is_empty());
    let response = unpack(&output.stdout);
    assert_eq!(response["ok"], false);
    assert_eq!(response["requestId"], "req_1");
    assert_eq!(response["error"]["code"], "UNAVAILABLE");
    assert!(response.get("credentialId").is_none());
    assert!(response.get("status").is_none());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("SYNTHETIC_SUPPLIED_SECRET_ABC"));
}
#[test]
fn malformed_frame_fails_process_with_generic_error() {
    let output = spawn_native(&[3u8, 0, 0, 0, b'{']);
    assert!(!output.status.success());
    let response = unpack(&output.stdout);
    assert_eq!(response["ok"], false);
    assert_eq!(response["type"], "RELAY_ERROR");
    assert_eq!(response["error"]["code"], "NATIVE_HOST_ERROR");
}
#[test]
fn retrieve_request_has_no_fake_unlocked_or_credential_response() {
    let output = spawn_native(&frame(br#"{"requestId":"r","type":"RETRIEVE_CREDENTIAL","origin":"https://example.org"}"#));
    assert!(output.status.success());
    let response = unpack(&output.stdout);
    assert_eq!(response["error"]["code"], "UNAVAILABLE");
    assert!(response.get("credential").is_none());
    assert!(response.get("password").is_none());
    assert!(response.get("locked").is_none());
}
