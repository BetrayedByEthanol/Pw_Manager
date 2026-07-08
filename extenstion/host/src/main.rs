use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::result::Result as StdResult;

const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_REQUEST_ID_CHARS: usize = 128;
const MAX_TYPE_CHARS: usize = 64;
const MAX_ORIGIN_CHARS: usize = 2048;
const MAX_URL_CHARS: usize = 4096;
const MAX_IDENTITY_CHARS: usize = 512;
const MAX_EMAIL_CHARS: usize = 320;
const MAX_PASSWORD_CHARS: usize = 4096;
const MAX_GENERATED_REQUEST_ID_CHARS: usize = 128;
const MIN_PASSWORD_POLICY_LENGTH: u64 = 8;
const MAX_PASSWORD_POLICY_LENGTH: u64 = 128;

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

#[derive(Debug)]
struct ValidationError {
    request_id: String,
    code: &'static str,
    message: String,
}

fn main() {
    if let Err(err) = run() {
        let _ = write_native_message(&json!({
            "ok": false,
            "type": "RELAY_ERROR",
            "requestId": "",
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
    if let Err(err) = validate_request(&request) {
        return relay_error(&err.request_id, err.code, &err.message);
    }

    let request_id = request
        .get("requestId")
        .and_then(Value::as_str)
        .unwrap_or("");

    let request_type = request
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("");

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
            "action": "created",
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

fn validate_request(request: &Value) -> StdResult<(), ValidationError> {
    let Some(object) = request.as_object() else {
        return Err(validation_error("", "INVALID_REQUEST", "Request must be a JSON object"));
    };

    let request_id = match object.get("requestId") {
        Some(Value::String(value)) => value.as_str(),
        _ => {
            return Err(validation_error(
                "",
                "INVALID_REQUEST",
                "Missing string field: requestId",
            ));
        }
    };

    validate_request_id(request_id)?;

    let request_type = match object.get("type") {
        Some(Value::String(value)) => value.as_str(),
        _ => {
            return Err(validation_error(
                request_id,
                "INVALID_REQUEST",
                "Missing string field: type",
            ));
        }
    };

    validate_request_type(request_id, request_type)?;

    match request_type {
        "GENERATE_PASSWORD" => validate_generate_password_request(request_id, request),
        "RETRIEVE_CREDENTIAL" => validate_retrieve_credential_request(request_id, request),
        "SAVE_CREDENTIAL" => validate_save_credential_request(request_id, request),
        "CHECK_LOCK_STATE" => Ok(()),
        "CHECK_DUPLICATE_CREDENTIAL" => validate_duplicate_check_request(request_id, request),
        _ => Err(validation_error(
            request_id,
            "REQUEST_TYPE_NOT_ALLOWED",
            &format!("Request type is not allowed through mock host: {}", request_type),
        )),
    }
}

fn validate_request_id(request_id: &str) -> StdResult<(), ValidationError> {
    if request_id.trim().is_empty() {
        return Err(validation_error("", "INVALID_REQUEST", "Missing string field: requestId"));
    }

    if request_id.len() > MAX_REQUEST_ID_CHARS {
        return Err(validation_error(
            "",
            "INVALID_REQUEST",
            "requestId is too long",
        ));
    }

    if !request_id
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err(validation_error(
            "",
            "INVALID_REQUEST",
            "requestId contains unsupported characters",
        ));
    }

    Ok(())
}

fn validate_request_type(request_id: &str, request_type: &str) -> StdResult<(), ValidationError> {
    if request_type.trim().is_empty() {
        return Err(validation_error(request_id, "INVALID_REQUEST", "type must not be empty"));
    }

    if request_type.len() > MAX_TYPE_CHARS {
        return Err(validation_error(request_id, "INVALID_REQUEST", "type is too long"));
    }

    if !ALLOWED_EXTENSION_REQUESTS.contains(&request_type) {
        return Err(validation_error(
            request_id,
            "REQUEST_TYPE_NOT_ALLOWED",
            &format!("Request type is not allowed through mock host: {}", request_type),
        ));
    }

    Ok(())
}

fn validate_generate_password_request(request_id: &str, request: &Value) -> StdResult<(), ValidationError> {
    validate_required_origin(request_id, request)?;

    if let Some(policy) = request.get("policy") {
        validate_password_policy(request_id, policy)?;
    }

    Ok(())
}

fn validate_retrieve_credential_request(request_id: &str, request: &Value) -> StdResult<(), ValidationError> {
    validate_required_origin(request_id, request)?;

    if let Some(purpose) = request.get("purpose") {
        let purpose = expect_string(request_id, "purpose", purpose)?;

        if purpose != "login_fill" {
            return Err(validation_error(
                request_id,
                "INVALID_REQUEST",
                "Unsupported retrieve purpose",
            ));
        }
    }

    Ok(())
}

fn validate_save_credential_request(request_id: &str, request: &Value) -> StdResult<(), ValidationError> {
    validate_required_origin(request_id, request)?;

    if let Some(url) = request.get("url") {
        let url = expect_string(request_id, "url", url)?;
        validate_plain_string(request_id, "url", url, MAX_URL_CHARS, true)?;
    }

    if let Some(allow_overwrite) = request.get("allowOverwrite") {
        if !allow_overwrite.is_boolean() {
            return Err(validation_error(
                request_id,
                "INVALID_REQUEST",
                "allowOverwrite must be a boolean",
            ));
        }
    }

    let credential = request.get("credential").ok_or_else(|| {
        validation_error(request_id, "INVALID_REQUEST", "Missing object field: credential")
    })?;

    validate_credential_object(request_id, credential, true)?;

    if let Some(source) = request.get("source") {
        validate_source_object(request_id, source)?;
    }

    Ok(())
}

fn validate_duplicate_check_request(request_id: &str, request: &Value) -> StdResult<(), ValidationError> {
    validate_required_origin(request_id, request)?;

    if let Some(credential) = request.get("credential") {
        validate_credential_object(request_id, credential, false)?;
    }

    Ok(())
}

fn validate_required_origin(request_id: &str, request: &Value) -> StdResult<(), ValidationError> {
    let origin = request.get("origin").ok_or_else(|| {
        validation_error(request_id, "INVALID_REQUEST", "Missing string field: origin")
    })?;

    let origin = expect_string(request_id, "origin", origin)?;
    validate_origin(request_id, origin)
}

fn validate_origin(request_id: &str, origin: &str) -> StdResult<(), ValidationError> {
    validate_plain_string(request_id, "origin", origin, MAX_ORIGIN_CHARS, false)?;

    let Some(rest) = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
    else {
        return Err(validation_error(
            request_id,
            "INVALID_ORIGIN",
            "origin must start with http:// or https://",
        ));
    };

    if rest.is_empty() {
        return Err(validation_error(request_id, "INVALID_ORIGIN", "origin host is empty"));
    }

    if rest.contains('/') || rest.contains('?') || rest.contains('#') {
        return Err(validation_error(
            request_id,
            "INVALID_ORIGIN",
            "origin must not include path, query, or fragment",
        ));
    }

    Ok(())
}

fn validate_password_policy(request_id: &str, policy: &Value) -> StdResult<(), ValidationError> {
    let Some(policy_object) = policy.as_object() else {
        return Err(validation_error(
            request_id,
            "INVALID_POLICY",
            "policy must be an object",
        ));
    };

    if let Some(length) = policy_object.get("length") {
        let Some(length) = length.as_u64() else {
            return Err(validation_error(
                request_id,
                "INVALID_POLICY",
                "policy.length must be an integer",
            ));
        };

        if !(MIN_PASSWORD_POLICY_LENGTH..=MAX_PASSWORD_POLICY_LENGTH).contains(&length) {
            return Err(validation_error(
                request_id,
                "INVALID_POLICY",
                "policy.length is outside the allowed range",
            ));
        }
    }

    let class_fields = ["uppercase", "lowercase", "numbers", "symbols"];

    for field in class_fields {
        if let Some(value) = policy_object.get(field) {
            if !value.is_boolean() {
                return Err(validation_error(
                    request_id,
                    "INVALID_POLICY",
                    &format!("policy.{} must be a boolean", field),
                ));
            }
        }
    }

    let all_classes_explicitly_disabled = class_fields
        .iter()
        .all(|field| policy_object.get(*field).and_then(Value::as_bool) == Some(false));

    if all_classes_explicitly_disabled {
        return Err(validation_error(
            request_id,
            "INVALID_POLICY",
            "At least one password character class must be enabled",
        ));
    }

    Ok(())
}

fn validate_credential_object(
    request_id: &str,
    credential: &Value,
    require_password: bool,
) -> StdResult<(), ValidationError> {
    let Some(credential_object) = credential.as_object() else {
        return Err(validation_error(
            request_id,
            "INVALID_CREDENTIAL",
            "credential must be an object",
        ));
    };

    let email = optional_string_field(request_id, credential_object.get("email"), "credential.email")?;
    let username = optional_string_field(
        request_id,
        credential_object.get("username"),
        "credential.username",
    )?;

    if let Some(email) = email {
        validate_plain_string(request_id, "credential.email", email, MAX_EMAIL_CHARS, true)?;
    }

    if let Some(username) = username {
        validate_plain_string(
            request_id,
            "credential.username",
            username,
            MAX_IDENTITY_CHARS,
            true,
        )?;
    }

    let has_email = email.map(str::trim).map(|value| !value.is_empty()).unwrap_or(false);
    let has_username = username.map(str::trim).map(|value| !value.is_empty()).unwrap_or(false);
    let has_identity = has_email || has_username;

    if !has_identity {
        return Err(validation_error(
            request_id,
            "INVALID_CREDENTIAL",
            "credential requires email or username",
        ));
    }

    match credential_object.get("password") {
        Some(Value::String(password)) => {
            if require_password && password.is_empty() {
                return Err(validation_error(
                    request_id,
                    "INVALID_CREDENTIAL",
                    "credential.password must not be empty",
                ));
            }

            if password.len() > MAX_PASSWORD_CHARS {
                return Err(validation_error(
                    request_id,
                    "INVALID_CREDENTIAL",
                    "credential.password is too long",
                ));
            }

            if password.contains('\0') {
                return Err(validation_error(
                    request_id,
                    "INVALID_CREDENTIAL",
                    "credential.password contains a null byte",
                ));
            }
        }
        Some(_) => {
            return Err(validation_error(
                request_id,
                "INVALID_CREDENTIAL",
                "credential.password must be a string",
            ));
        }
        None if require_password => {
            return Err(validation_error(
                request_id,
                "INVALID_CREDENTIAL",
                "Missing string field: credential.password",
            ));
        }
        None => {}
    }

    Ok(())
}

fn validate_source_object(request_id: &str, source: &Value) -> StdResult<(), ValidationError> {
    let Some(source_object) = source.as_object() else {
        return Err(validation_error(
            request_id,
            "INVALID_SOURCE",
            "source must be an object",
        ));
    };

    if let Some(flow) = source_object.get("flow") {
        let flow = expect_string(request_id, "source.flow", flow)?;
        validate_plain_string(request_id, "source.flow", flow, 64, false)?;
    }

    if let Some(password_source) = source_object.get("passwordSource") {
        let password_source = expect_string(request_id, "source.passwordSource", password_source)?;
        validate_plain_string(request_id, "source.passwordSource", password_source, 128, false)?;
    }

    if let Some(generated_request_id) = source_object.get("generatedRequestId") {
        let generated_request_id = expect_string(
            request_id,
            "source.generatedRequestId",
            generated_request_id,
        )?;
        validate_plain_string(
            request_id,
            "source.generatedRequestId",
            generated_request_id,
            MAX_GENERATED_REQUEST_ID_CHARS,
            true,
        )?;
    }

    if let Some(field_sources) = source_object.get("fieldSources") {
        if !field_sources.is_object() {
            return Err(validation_error(
                request_id,
                "INVALID_SOURCE",
                "source.fieldSources must be an object",
            ));
        }
    }

    Ok(())
}

fn expect_string<'a>(request_id: &str, field: &str, value: &'a Value) -> StdResult<&'a str, ValidationError> {
    value.as_str().ok_or_else(|| {
        validation_error(
            request_id,
            "INVALID_REQUEST",
            &format!("{} must be a string", field),
        )
    })
}

fn optional_string_field<'a>(
    request_id: &str,
    value: Option<&'a Value>,
    field: &str,
) -> StdResult<Option<&'a str>, ValidationError> {
    match value {
        Some(Value::String(value)) => Ok(Some(value.as_str())),
        Some(_) => Err(validation_error(
            request_id,
            "INVALID_REQUEST",
            &format!("{} must be a string", field),
        )),
        None => Ok(None),
    }
}

fn validate_plain_string(
    request_id: &str,
    field: &str,
    value: &str,
    max_len: usize,
    allow_empty: bool,
) -> StdResult<(), ValidationError> {
    if !allow_empty && value.trim().is_empty() {
        return Err(validation_error(
            request_id,
            "INVALID_REQUEST",
            &format!("{} must not be empty", field),
        ));
    }

    if value.len() > max_len {
        return Err(validation_error(
            request_id,
            "INVALID_REQUEST",
            &format!("{} is too long", field),
        ));
    }

    if value.chars().any(|ch| ch.is_control()) {
        return Err(validation_error(
            request_id,
            "INVALID_REQUEST",
            &format!("{} contains control characters", field),
        ));
    }

    Ok(())
}

fn validation_error(request_id: &str, code: &'static str, message: &str) -> ValidationError {
    ValidationError {
        request_id: request_id.to_string(),
        code,
        message: message.to_string(),
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
