use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::io::{Read, Write};

const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

const MOCK_USERNAME: &str = "demo@example.com";
const MOCK_PASSWORD: &str = "demo-password";
const MOCK_GENERATED_PASSWORD: &str = "Vaulty-Demo-Generated-Password-123!";

const ALLOWED_EXTENSION_REQUESTS: &[&str] = &[
    "GENERATE_PASSWORD",
    "SAVE_CREDENTIAL",
    "CHECK_LOCK_STATE",
    "CHECK_DUPLICATE_CREDENTIAL",
    "RETRIEVE_CREDENTIAL",
];

fn main() {
    if let Err(err) = run() {
        let _ = write_native_message(&json!({
            "ok": false,
            "type": "RELAY_ERROR",
            "error": {
                "code": "NATIVE_HOST_ERROR",
                "message": err.to_string()
            }
        }));
    }
}

fn run() -> Result<()> {
    let request = read_native_message()
        .context("failed to read browser native message")?;

    let response = handle_mock_request(request);

    write_native_message(&response)
        .context("failed to write native response")?;

    Ok(())
}

fn handle_mock_request(request: Value) -> Value {
    let request_id = request
        .get("requestId")
        .and_then(Value::as_str)
        .unwrap_or("");

    let Some(request_type) = request.get("type").and_then(Value::as_str) else {
        return relay_error(request_id, "INVALID_REQUEST", "Missing string field: type");
    };

    if request_id.trim().is_empty() {
        return relay_error("", "INVALID_REQUEST", "Missing string field: requestId");
    }

    if !ALLOWED_EXTENSION_REQUESTS.contains(&request_type) {
        return relay_error(
            request_id,
            "REQUEST_TYPE_NOT_ALLOWED",
            &format!("Request type is not allowed through mock host: {}", request_type),
        );
    }

    match request_type {
        "GENERATE_PASSWORD" => json!({
            "ok": true,
            "type": "GENERATE_PASSWORD_RESULT",
            "requestId": request_id,
            "generatedRequestId": "mock-generated-request-id",
            "password": MOCK_GENERATED_PASSWORD
        }),

        "RETRIEVE_CREDENTIAL" => json!({
            "ok": true,
            "type": "RETRIEVE_CREDENTIAL_RESULT",
            "requestId": request_id,
            "origin": request.get("origin").cloned().unwrap_or(Value::Null),
            "credential": {
                "username": MOCK_USERNAME,
                "password": MOCK_PASSWORD
            }
        }),

        "SAVE_CREDENTIAL" => json!({
            "ok": true,
            "type": "SAVE_CREDENTIAL_RESULT",
            "requestId": request_id,
            "status": "saved",
            "credentialId": "mock-credential-id"
        }),

        "CHECK_LOCK_STATE" => json!({
            "ok": true,
            "type": "CHECK_LOCK_STATE_RESULT",
            "requestId": request_id,
            "locked": false,
            "state": "unlocked_mock"
        }),

        "CHECK_DUPLICATE_CREDENTIAL" => json!({
            "ok": true,
            "type": "CHECK_DUPLICATE_CREDENTIAL_RESULT",
            "requestId": request_id,
            "duplicate": false
        }),

        _ => relay_error(
            request_id,
            "UNIMPLEMENTED_MOCK_REQUEST",
            &format!("Allowed but not implemented by mock host: {}", request_type),
        ),
    }
}

fn relay_error(request_id: &str, code: &str, message: &str) -> Value {
    json!({
        "ok": false,
        "type": "RELAY_ERROR",
        "requestId": request_id,
        "error": {
            "code": code,
            "message": message
        }
    })
}

fn read_native_message() -> Result<Value> {
    let mut len_buf = [0u8; 4];

    std::io::stdin()
        .read_exact(&mut len_buf)
        .context("missing message length prefix")?;

    let len = u32::from_ne_bytes(len_buf) as usize;

    if len == 0 {
        bail!("empty message");
    }

    if len > MAX_MESSAGE_BYTES {
        bail!("message too large: {} bytes", len);
    }

    let mut buffer = vec![0u8; len];

    std::io::stdin()
        .read_exact(&mut buffer)
        .context("failed to read message body")?;

    let value = serde_json::from_slice(&buffer)
        .context("message body is not valid JSON")?;

    Ok(value)
}

fn write_native_message(value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(value)
        .context("failed to serialize response")?;

    let len = bytes.len();

    if len > MAX_MESSAGE_BYTES {
        bail!("response too large: {} bytes", len);
    }

    let mut stdout = std::io::stdout();

    stdout
        .write_all(&(len as u32).to_ne_bytes())
        .context("failed to write response length")?;

    stdout
        .write_all(&bytes)
        .context("failed to write response body")?;

    stdout
        .flush()
        .context("failed to flush response")?;

    Ok(())
}
