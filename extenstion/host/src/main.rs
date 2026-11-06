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

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => {
            // Error context may contain sensitive bytes: never echo it.
            let _ = write_native_message(&relay_error(
                "", "NATIVE_HOST_ERROR", "Native message rejected",
            ));
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let request = read_native_message()
        .context("failed to read browser native message")?;

    let response = handle_request(request);

    write_native_message(&response)
        .context("failed to write native response")?;

    Ok(())
}

/// Default installation has no daemon or verified E2E channel.
/// Valid requests must never claim a credential was saved or retrieved.
fn handle_request(request: Value) -> Value {
    if let Err(err) = validate_request(&request) {
        return relay_error(&err.request_id, err.code, &err.message);
    }
    let id = request.get("requestId").and_then(Value::as_str).unwrap_or("");
    relay_error(id, "UNAVAILABLE",
        "Vaulty secure daemon relay is unavailable; no credential was accessed or saved")
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

    // This check only rejects malformed input. The untrusted browser-supplied
    // origin MUST NOT authorize any action at the daemon.
    if rest.contains('@') || rest.contains('\\') || rest.contains('%')
        || rest.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(validation_error(request_id, "INVALID_ORIGIN", "malformed origin"));
    }
    let port = if let Some(ip6) = rest.strip_prefix('[') {
        let (address, suffix) = ip6.split_once(']').ok_or_else(||
            validation_error(request_id, "INVALID_ORIGIN", "malformed IPv6 origin"))?;
        if address.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(validation_error(request_id, "INVALID_ORIGIN", "invalid IPv6 host"));
        }
        if suffix.is_empty() { None }
        else { Some(suffix.strip_prefix(':').ok_or_else(||
            validation_error(request_id, "INVALID_ORIGIN", "invalid IPv6 port"))?) }
    } else {
        let (host, port) = match rest.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        };
        if host.len() > 253 || !host.split('.').all(|label|
            !label.is_empty() && label.len() <= 63
            && !label.starts_with('-') && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        {
            return Err(validation_error(request_id, "INVALID_ORIGIN", "invalid DNS host"));
        }
        port
    };
    if port.is_some_and(|p| p.parse::<u16>().map_or(true, |n| n == 0)) {
        return Err(validation_error(request_id, "INVALID_ORIGIN", "invalid port"));
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

/// Reads exactly one bounded native-messaging frame.
fn read_native_message_from<R: Read>(reader: &mut R) -> Result<Value> {
    let mut len = [0u8; 4];
    reader.read_exact(&mut len).context("missing length prefix")?;
    let n = u32::from_ne_bytes(len) as usize;
    if n == 0 || n > MAX_MESSAGE_BYTES { bail!("invalid message length"); }
    let mut bytes = vec![0u8; n];
    reader.read_exact(&mut bytes).context("truncated frame")?;
    serde_json::from_slice(&bytes).context("invalid JSON")
}
fn read_native_message() -> Result<Value> {
    read_native_message_from(&mut std::io::stdin().lock())
}
fn write_native_message_to<W: Write>(writer: &mut W, response: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(response).context("failed to serialize response")?;
    if bytes.len() > MAX_MESSAGE_BYTES { bail!("response too large"); }
    writer.write_all(&(bytes.len() as u32).to_ne_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}
fn write_native_message(response: &Value) -> Result<()> {
    write_native_message_to(&mut std::io::stdout().lock(), response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn framed(body: &[u8]) -> Vec<u8> {
        let mut bytes = (body.len() as u32).to_ne_bytes().to_vec();
        bytes.extend_from_slice(body);
        bytes
    }

    #[test]
    fn native_request_and_error_frame_round_trip() {
        let wire = framed(br#"{"type":"CHECK_LOCK_STATE","requestId":"req_42"}"#);
        let input = read_native_message_from(&mut Cursor::new(wire)).unwrap();
        let response = handle_request(input);
        assert_eq!(response["requestId"], "req_42");
        assert_eq!(response["type"], "RELAY_ERROR");
        assert_eq!(response["ok"], false);
        assert_eq!(response["error"]["code"], "UNAVAILABLE");
        let mut output = Vec::new();
        write_native_message_to(&mut output, &response).unwrap();
        assert_eq!(read_native_message_from(&mut Cursor::new(output)).unwrap(), response);
    }

    #[test]
    fn no_request_type_can_claim_real_secret_or_save() {
        let probes = [
            json!({"type":"GENERATE_PASSWORD","requestId":"g","origin":"https://example.org"}),
            json!({"type":"RETRIEVE_CREDENTIAL","requestId":"r","origin":"https://example.org","purpose":"login_fill"}),
            json!({"type":"SAVE_CREDENTIAL","requestId":"s","origin":"https://example.org",
                   "credential":{"username":"tester","password":"SYNTHETIC_NEVER_ECHO_SECRET"}}),
            json!({"type":"CHECK_LOCK_STATE","requestId":"l"}),
            json!({"type":"CHECK_DUPLICATE_CREDENTIAL","requestId":"d","origin":"https://example.org"}),
        ];
        for request in probes {
            let answer = handle_request(request);
            assert_eq!(answer["ok"], false);
            assert_eq!(answer["type"], "RELAY_ERROR");
            assert_eq!(answer["error"]["code"], "UNAVAILABLE");
            assert!(answer.get("password").is_none());
            assert!(answer.get("credential").is_none());
            assert!(answer.get("status").is_none());
            assert!(answer.get("locked").is_none());
            assert!(!answer.to_string().contains("SYNTHETIC_NEVER_ECHO_SECRET"));
        }
    }

    #[test]
    fn invalid_requests_do_not_reach_unavailable_handler() {
        let requests = [
            json!({"requestId":"x","type":"OWNER_UNLOCK"}),
            json!({"requestId":"bad id","type":"CHECK_LOCK_STATE"}),
            json!({"requestId":9,"type":"CHECK_LOCK_STATE"}),
            json!({"requestId":"x","type":"RETRIEVE_CREDENTIAL","origin":"https://a@b.org"}),
            json!({"requestId":"x","type":"RETRIEVE_CREDENTIAL","origin":"https://example.org/path"}),
            json!({"requestId":"x","type":"RETRIEVE_CREDENTIAL","origin":"https://example.org:zz"}),
            json!({"requestId":"x","type":"RETRIEVE_CREDENTIAL","origin":"https://a..example"}),
            json!({"requestId":"x","type":"RETRIEVE_CREDENTIAL","origin":"file://example.org"}),
            json!({"requestId":"x","type":"SAVE_CREDENTIAL","origin":"https://example.org",
                   "credential":{"username":"user","password":""}}),
            json!({"requestId":"x","type":"GENERATE_PASSWORD","origin":"https://example.org",
                   "policy":{"length":1}}),
        ];
        for request in requests {
            let answer = handle_request(request);
            assert_eq!(answer["ok"], false);
            assert_ne!(answer["error"]["code"], "UNAVAILABLE");
        }
    }

    #[test]
    fn native_frame_length_and_json_errors_are_bounded() {
        let examples = [
            vec![],
            vec![0x01],
            0u32.to_ne_bytes().to_vec(),
            ((MAX_MESSAGE_BYTES + 1) as u32).to_ne_bytes().to_vec(),
            framed(b"this is not JSON"),
            { let mut x = 50u32.to_ne_bytes().to_vec(); x.extend_from_slice(b"{}"); x },
        ];
        for frame in examples {
            assert!(read_native_message_from(&mut Cursor::new(frame)).is_err());
        }
    }

    #[test]
    fn large_request_fields_and_response_rejected() {
        let probes = [
            json!({"requestId":"x".repeat(MAX_REQUEST_ID_CHARS + 1),"type":"CHECK_LOCK_STATE"}),
            json!({"requestId":"x","type":"RETRIEVE_CREDENTIAL",
                  "origin":format!("https://{}.org", "a".repeat(MAX_ORIGIN_CHARS))}),
            json!({"requestId":"x","type":"SAVE_CREDENTIAL","origin":"https://example.org",
                  "credential":{"username":"u","password":"z".repeat(MAX_PASSWORD_CHARS + 1)}}),
        ];
        for request in probes {
            let response = handle_request(request);
            assert_ne!(response["error"]["code"], "UNAVAILABLE");
        }
        let large_response = json!({"payload":"x".repeat(MAX_MESSAGE_BYTES + 1)});
        assert!(write_native_message_to(&mut Vec::new(), &large_response).is_err());
    }

    #[test]
    fn allowed_ipv6_and_port_origin_still_fail_closed() {
        for origin in ["http://[::1]:8080", "https://example.org:443", "https://localhost"] {
            let response = handle_request(json!({
                "type":"RETRIEVE_CREDENTIAL","requestId":"ok","origin":origin
            }));
            assert_eq!(response["error"]["code"], "UNAVAILABLE");
        }
    }
}
