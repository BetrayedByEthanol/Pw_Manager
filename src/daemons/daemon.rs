//! Daemon startup logic for the Vaulty IPC socket.
//!
//! Responsibilities in this module:
//! - Create and lock down the runtime directory.
//! - Detect and clean up stale Unix socket files.
//! - Bind the Vaulty IPC socket.
//! - Start/stop the accept loop.
//! - Serve the temporary mock daemon protocol over length-prefixed JSON.
//!
//! Cargo.toml:
//!   thiserror = "1"
//!   serde_json = "1"
//!
//! Later replacement points:
//! - `handle_connection()` should perform the mTLS/client identity handshake.
//! - `handle_mock_daemon_request()` should be replaced by real Vaulty dispatch.
//! - trusted relay checks should be performed by the daemon against the vault's
//!   trusted-client structs, not by the native host relay.

use serde_json::{json, Value};
use std::fs::{self, DirBuilder};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use thiserror::Error;

const MAX_IPC_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_TYPE_BYTES: usize = 64;
const MAX_ORIGIN_BYTES: usize = 2048;
const MAX_URL_BYTES: usize = 4096;
const MAX_IDENTITY_BYTES: usize = 320;
const MAX_PASSWORD_BYTES: usize = 4096;
const MAX_SOURCE_STRING_BYTES: usize = 256;

const MOCK_USERNAME: &str = "demo@example.com";
const MOCK_PASSWORD: &str = "demo-password";
const MOCK_GENERATED_PASSWORD: &str = "Vaulty-Demo-Generated-Password-123!";

const ALLOWED_DAEMON_REQUESTS: &[&str] = &[
    "GENERATE_PASSWORD",
    "SAVE_CREDENTIAL",
    "CHECK_LOCK_STATE",
    "CHECK_DUPLICATE_CREDENTIAL",
    "RETRIEVE_CREDENTIAL",
];

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("another vaulty daemon is already listening on {0}")]
    AlreadyRunning(PathBuf),

    #[error("invalid ipc message: {0}")]
    InvalidIpc(String),

    #[error("ipc message too large: {actual} bytes, limit is {limit} bytes")]
    MessageTooLarge { actual: usize, limit: usize },

    #[error("daemon accept thread panicked")]
    AcceptThreadPanicked,
}

/// Shared state so other parts of the process can observe/control the daemon
/// lifecycle without reaching back into the accept-loop thread.
pub struct DaemonState {
    running: AtomicBool,
    socket_path: PathBuf,
}

impl DaemonState {
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Flip the running flag and unblock the accept loop's blocking `accept()`
    /// call by connecting to our own socket.
    pub fn shutdown(&self) {
        self.running.store(false, Ordering::SeqCst);
        let _ = UnixStream::connect(&self.socket_path);
    }
}

/// Owning handle for the daemon listener.
///
/// Store this in the main Vaulty app state. Dropping it attempts a best-effort
/// shutdown and socket cleanup.
pub struct DaemonHandle {
    _listener: UnixListener,
    state: Arc<DaemonState>,
    accept_thread: Option<thread::JoinHandle<()>>,
}

impl DaemonHandle {
    pub fn is_running(&self) -> bool {
        self.state.is_running()
    }

    pub fn socket_path(&self) -> &Path {
        self.state.socket_path()
    }

    pub fn state(&self) -> Arc<DaemonState> {
        Arc::clone(&self.state)
    }

    /// Stop the accept loop, wait for it to exit, and remove the socket file.
    pub fn shutdown(mut self) -> Result<(), DaemonError> {
        self.shutdown_inner()
    }

    fn shutdown_inner(&mut self) -> Result<(), DaemonError> {
        self.state.shutdown();

        if let Some(handle) = self.accept_thread.take() {
            handle.join().map_err(|_| DaemonError::AcceptThreadPanicked)?;
        }

        match fs::remove_file(&self.state.socket_path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_err(&self.state.socket_path, e)),
        }

        Ok(())
    }
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        let _ = self.shutdown_inner();
    }
}

fn io_err(path: &Path, source: io::Error) -> DaemonError {
    DaemonError::Io {
        path: path.to_path_buf(),
        source,
    }
}

pub fn runtime_dir(uid: u32) -> PathBuf {
    PathBuf::from(format!("/run/user/{uid}/vaulty"))
}

pub fn socket_path(uid: u32) -> PathBuf {
    runtime_dir(uid).join("vaulty.sock")
}

/// A socket file is stale if nothing is actively listening on it.
fn socket_is_stale(path: &Path) -> io::Result<bool> {
    match UnixStream::connect(path) {
        Ok(_) => Ok(false),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) =>
        {
            Ok(true)
        }
        Err(e) => Err(e),
    }
}

/// Start the daemon for the given uid at:
/// `/run/user/<uid>/vaulty/vaulty.sock`.
pub fn start_daemon(uid: u32) -> Result<DaemonHandle, DaemonError> {
    let dir = runtime_dir(uid);
    let sock_path = socket_path(uid);
    start_daemon_at(&dir, &sock_path)
}

/// Test/dev-friendly start function for a caller-supplied socket path.
///
/// Production code should normally use `start_daemon(uid)`.
pub fn start_daemon_at(dir: &Path, sock_path: &Path) -> Result<DaemonHandle, DaemonError> {
    // 1 & 2. Create runtime dir at 0700 and enforce the mode afterwards in
    // case umask altered the requested mode.
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| io_err(dir, e))?;

    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| io_err(dir, e))?;

    // 3. Remove stale socket if safe. If something is actively listening,
    // refuse to clobber it.
    if sock_path.exists() {
        if socket_is_stale(sock_path).map_err(|e| io_err(sock_path, e))? {
            fs::remove_file(sock_path).map_err(|e| io_err(sock_path, e))?;
        } else {
            return Err(DaemonError::AlreadyRunning(sock_path.to_path_buf()));
        }
    }

    // 4. Bind socket.
    let listener = UnixListener::bind(sock_path).map_err(|e| io_err(sock_path, e))?;

    // 5. Lock down socket permissions.
    fs::set_permissions(sock_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| io_err(sock_path, e))?;

    let state = Arc::new(DaemonState {
        running: AtomicBool::new(true),
        socket_path: sock_path.to_path_buf(),
    });

    // 6. Start accept loop.
    let loop_listener = listener.try_clone().map_err(|e| io_err(sock_path, e))?;
    let loop_state = Arc::clone(&state);
    let accept_thread = thread::spawn(move || accept_loop(loop_listener, loop_state));

    // 7. Startup is complete once the listener is bound and the accept loop is
    // spawned.
    Ok(DaemonHandle {
        _listener: listener,
        state,
        accept_thread: Some(accept_thread),
    })
}

fn accept_loop(listener: UnixListener, state: Arc<DaemonState>) {
    for conn in listener.incoming() {
        if !state.is_running() {
            break;
        }

        match conn {
            Ok(stream) => {
                let conn_state = Arc::clone(&state);
                thread::spawn(move || handle_connection(stream, conn_state));
            }
            Err(e) => {
                if state.is_running() {
                    eprintln!("vaulty: daemon accept error: {e}");
                }
            }
        }
    }
}

fn handle_connection(mut stream: UnixStream, _state: Arc<DaemonState>) {
    // Later:
    // - perform mTLS/client-cert identity check here,
    // - look up the relay identity in the portable vault's trusted-client
    //   structs,
    // - enforce relay capabilities,
    // - then dispatch to real Vaulty handlers.
    let response = match read_ipc_message(&mut stream) {
        Ok(request) => handle_mock_daemon_request(request),
        Err(err) => daemon_error(
            "",
            "INVALID_IPC_MESSAGE",
            &format!("Could not read IPC message: {err}"),
        ),
    };

    let _ = write_ipc_message(&mut stream, &response);
}

fn read_ipc_message(stream: &mut UnixStream) -> Result<Value, DaemonError> {
    let mut len_buf = [0u8; 4];

    stream
        .read_exact(&mut len_buf)
        .map_err(|e| io_err(Path::new("ipc-read-length"), e))?;

    let len = u32::from_ne_bytes(len_buf) as usize;

    if len == 0 {
        return Err(DaemonError::InvalidIpc("empty IPC message".to_string()));
    }

    if len > MAX_IPC_MESSAGE_BYTES {
        return Err(DaemonError::MessageTooLarge {
            actual: len,
            limit: MAX_IPC_MESSAGE_BYTES,
        });
    }

    let mut buffer = vec![0u8; len];

    stream
        .read_exact(&mut buffer)
        .map_err(|e| io_err(Path::new("ipc-read-body"), e))?;

    serde_json::from_slice(&buffer)
        .map_err(|e| DaemonError::InvalidIpc(format!("message body is not valid JSON: {e}")))
}

fn write_ipc_message(stream: &mut UnixStream, value: &Value) -> Result<(), DaemonError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| DaemonError::InvalidIpc(format!("failed to serialize response: {e}")))?;

    if bytes.len() > MAX_IPC_MESSAGE_BYTES {
        return Err(DaemonError::MessageTooLarge {
            actual: bytes.len(),
            limit: MAX_IPC_MESSAGE_BYTES,
        });
    }

    stream
        .write_all(&(bytes.len() as u32).to_ne_bytes())
        .map_err(|e| io_err(Path::new("ipc-write-length"), e))?;

    stream
        .write_all(&bytes)
        .map_err(|e| io_err(Path::new("ipc-write-body"), e))?;

    stream
        .flush()
        .map_err(|e| io_err(Path::new("ipc-flush"), e))?;

    Ok(())
}

fn handle_mock_daemon_request(request: Value) -> Value {
    let payload = match unwrap_relay_payload(request) {
        Ok(payload) => payload,
        Err(response) => return response,
    };

    if let Some(error) = validate_daemon_payload(&payload) {
        return error;
    }

    let request_id = payload
        .get("requestId")
        .and_then(Value::as_str)
        .unwrap_or("");

    let request_type = payload.get("type").and_then(Value::as_str).unwrap_or("");

    match request_type {
        "GENERATE_PASSWORD" => json!({
            "ok": true,
            "type": "GENERATE_PASSWORD_RESULT",
            "requestId": request_id,
            "generatedRequestId": "daemon-mock-generated-request-id",
            "password": MOCK_GENERATED_PASSWORD
        }),

        "RETRIEVE_CREDENTIAL" => json!({
            "ok": true,
            "type": "RETRIEVE_CREDENTIAL_RESULT",
            "requestId": request_id,
            "origin": payload.get("origin").cloned().unwrap_or(Value::Null),
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
            "credentialId": "daemon-mock-credential-id"
        }),

        "CHECK_LOCK_STATE" => json!({
            "ok": true,
            "type": "CHECK_LOCK_STATE_RESULT",
            "requestId": request_id,
            "locked": false,
            "state": "unlocked_daemon_mock"
        }),

        "CHECK_DUPLICATE_CREDENTIAL" => json!({
            "ok": true,
            "type": "CHECK_DUPLICATE_CREDENTIAL_RESULT",
            "requestId": request_id,
            "duplicate": false
        }),

        other => daemon_error(
            request_id,
            "UNKNOWN_REQUEST_TYPE",
            &format!("Unsupported daemon mock request type: {other}"),
        ),
    }
}

/// Accepts either a direct request:
/// `{ "type": "RETRIEVE_CREDENTIAL", ... }`
///
/// or a relay-wrapped request:
/// `{ "type": "RELAY_FORWARD", "payload": { "type": "RETRIEVE_CREDENTIAL", ... } }`.
fn unwrap_relay_payload(request: Value) -> Result<Value, Value> {
    let Some(object) = request.as_object() else {
        return Err(daemon_error(
            "",
            "INVALID_REQUEST",
            "IPC request must be a JSON object",
        ));
    };

    if object.get("type").and_then(Value::as_str) == Some("RELAY_FORWARD") {
        let relay_request_id = object.get("requestId").and_then(Value::as_str).unwrap_or("");

        let Some(payload) = object.get("payload") else {
            return Err(daemon_error(
                relay_request_id,
                "INVALID_RELAY_REQUEST",
                "RELAY_FORWARD is missing payload object",
            ));
        };

        if !payload.is_object() {
            return Err(daemon_error(
                relay_request_id,
                "INVALID_RELAY_REQUEST",
                "RELAY_FORWARD payload must be a JSON object",
            ));
        }

        return Ok(payload.clone());
    }

    Ok(request)
}

fn validate_daemon_payload(payload: &Value) -> Option<Value> {
    let Some(object) = payload.as_object() else {
        return Some(daemon_error(
            "",
            "INVALID_REQUEST",
            "Daemon payload must be a JSON object",
        ));
    };

    let request_id = match object.get("requestId").and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return Some(daemon_error(
                "",
                "INVALID_REQUEST",
                "Missing string field: requestId",
            ));
        }
    };

    if let Err(message) = validate_request_id(request_id) {
        return Some(daemon_error(request_id, "INVALID_REQUEST_ID", &message));
    }

    let request_type = match object.get("type").and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => value,
        _ => {
            return Some(daemon_error(
                request_id,
                "INVALID_REQUEST",
                "Missing string field: type",
            ));
        }
    };

    if request_type.len() > MAX_TYPE_BYTES {
        return Some(daemon_error(
            request_id,
            "INVALID_REQUEST_TYPE",
            "Request type is too long",
        ));
    }

    if !ALLOWED_DAEMON_REQUESTS.contains(&request_type) {
        return Some(daemon_error(
            request_id,
            "REQUEST_TYPE_NOT_ALLOWED",
            &format!("Request type is not allowed by daemon mock: {request_type}"),
        ));
    }

    match request_type {
        "GENERATE_PASSWORD" => validate_generate_password_payload(payload, request_id),
        "RETRIEVE_CREDENTIAL" => validate_retrieve_credential_payload(payload, request_id),
        "SAVE_CREDENTIAL" => validate_save_credential_payload(payload, request_id),
        "CHECK_DUPLICATE_CREDENTIAL" => validate_duplicate_payload(payload, request_id),
        "CHECK_LOCK_STATE" => None,
        _ => Some(daemon_error(
            request_id,
            "UNIMPLEMENTED_VALIDATION",
            "No validation branch exists for this request type",
        )),
    }
}

fn validate_generate_password_payload(payload: &Value, request_id: &str) -> Option<Value> {
    if let Some(error) = validate_origin_field(payload, request_id) {
        return Some(error);
    }

    if let Some(policy) = payload.get("policy") {
        if let Err(message) = validate_policy(policy) {
            return Some(daemon_error(request_id, "INVALID_POLICY", &message));
        }
    }

    None
}

fn validate_retrieve_credential_payload(payload: &Value, request_id: &str) -> Option<Value> {
    if let Some(error) = validate_origin_field(payload, request_id) {
        return Some(error);
    }

    if let Some(purpose) = payload.get("purpose") {
        match purpose.as_str() {
            Some("login_fill") => {}
            Some(_) => {
                return Some(daemon_error(
                    request_id,
                    "INVALID_PURPOSE",
                    "Unsupported retrieve purpose",
                ));
            }
            None => {
                return Some(daemon_error(
                    request_id,
                    "INVALID_PURPOSE",
                    "purpose must be a string when present",
                ));
            }
        }
    }

    None
}

fn validate_save_credential_payload(payload: &Value, request_id: &str) -> Option<Value> {
    if let Some(error) = validate_origin_field(payload, request_id) {
        return Some(error);
    }

    if let Some(url) = payload.get("url") {
        if !url.is_string() {
            return Some(daemon_error(request_id, "INVALID_URL", "url must be a string"));
        }
        if url.as_str().unwrap_or("").len() > MAX_URL_BYTES {
            return Some(daemon_error(request_id, "INVALID_URL", "url is too long"));
        }
    }

    if let Some(allow_overwrite) = payload.get("allowOverwrite") {
        if !allow_overwrite.is_boolean() {
            return Some(daemon_error(
                request_id,
                "INVALID_SAVE_REQUEST",
                "allowOverwrite must be a boolean when present",
            ));
        }
    }

    let Some(credential) = payload.get("credential") else {
        return Some(daemon_error(
            request_id,
            "INVALID_CREDENTIAL",
            "SAVE_CREDENTIAL requires credential object",
        ));
    };

    let Some(credential_object) = credential.as_object() else {
        return Some(daemon_error(
            request_id,
            "INVALID_CREDENTIAL",
            "credential must be a JSON object",
        ));
    };

    let email = string_field(credential_object, "email").unwrap_or("").trim();
    let username = string_field(credential_object, "username").unwrap_or("").trim();
    let password = string_field(credential_object, "password").unwrap_or("");

    if email.is_empty() && username.is_empty() {
        return Some(daemon_error(
            request_id,
            "INVALID_CREDENTIAL",
            "credential requires email or username",
        ));
    }

    if email.len() > MAX_IDENTITY_BYTES || username.len() > MAX_IDENTITY_BYTES {
        return Some(daemon_error(
            request_id,
            "INVALID_CREDENTIAL",
            "credential identity field is too long",
        ));
    }

    if password.is_empty() {
        return Some(daemon_error(
            request_id,
            "INVALID_CREDENTIAL",
            "credential password is required",
        ));
    }

    if password.len() > MAX_PASSWORD_BYTES {
        return Some(daemon_error(
            request_id,
            "INVALID_CREDENTIAL",
            "credential password is too long",
        ));
    }

    for field in ["email", "username", "password"] {
        if let Some(value) = credential_object.get(field) {
            if !value.is_string() {
                return Some(daemon_error(
                    request_id,
                    "INVALID_CREDENTIAL",
                    &format!("credential.{field} must be a string"),
                ));
            }
        }
    }

    if let Some(source) = payload.get("source") {
        if let Err(message) = validate_source(source) {
            return Some(daemon_error(request_id, "INVALID_SOURCE", &message));
        }
    }

    None
}

fn validate_duplicate_payload(payload: &Value, request_id: &str) -> Option<Value> {
    if let Some(error) = validate_origin_field(payload, request_id) {
        return Some(error);
    }

    if let Some(credential) = payload.get("credential") {
        let Some(credential_object) = credential.as_object() else {
            return Some(daemon_error(
                request_id,
                "INVALID_CREDENTIAL",
                "credential must be a JSON object when present",
            ));
        };

        let email = string_field(credential_object, "email").unwrap_or("").trim();
        let username = string_field(credential_object, "username").unwrap_or("").trim();

        if email.is_empty() && username.is_empty() {
            return Some(daemon_error(
                request_id,
                "INVALID_CREDENTIAL",
                "duplicate check credential requires email or username",
            ));
        }
    }

    None
}

fn validate_request_id(request_id: &str) -> Result<(), String> {
    if request_id.len() > MAX_REQUEST_ID_BYTES {
        return Err("requestId is too long".to_string());
    }

    if !request_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("requestId contains invalid characters".to_string());
    }

    Ok(())
}

fn validate_origin_field(payload: &Value, request_id: &str) -> Option<Value> {
    let Some(origin) = payload.get("origin").and_then(Value::as_str) else {
        return Some(daemon_error(
            request_id,
            "INVALID_ORIGIN",
            "Missing string field: origin",
        ));
    };

    if let Err(message) = validate_origin(origin) {
        return Some(daemon_error(request_id, "INVALID_ORIGIN", &message));
    }

    None
}

fn validate_origin(origin: &str) -> Result<(), String> {
    if origin.is_empty() {
        return Err("origin must not be empty".to_string());
    }

    if origin.len() > MAX_ORIGIN_BYTES {
        return Err("origin is too long".to_string());
    }

    if origin.trim() != origin {
        return Err("origin must not contain leading or trailing whitespace".to_string());
    }

    let host_part = if let Some(rest) = origin.strip_prefix("https://") {
        rest
    } else if let Some(rest) = origin.strip_prefix("http://") {
        rest
    } else {
        return Err("origin must start with http:// or https://".to_string());
    };

    if host_part.is_empty() {
        return Err("origin is missing host".to_string());
    }

    if host_part.contains('/') || host_part.contains('?') || host_part.contains('#') {
        return Err("origin must not include path, query, or fragment".to_string());
    }

    if host_part.contains('@') {
        return Err("origin must not contain userinfo".to_string());
    }

    Ok(())
}

fn validate_policy(policy: &Value) -> Result<(), String> {
    let Some(policy_object) = policy.as_object() else {
        return Err("policy must be a JSON object".to_string());
    };

    if let Some(length) = policy_object.get("length") {
        let Some(length) = length.as_u64() else {
            return Err("policy.length must be an unsigned integer".to_string());
        };

        if !(8..=128).contains(&length) {
            return Err("policy.length must be between 8 and 128".to_string());
        }
    }

    let mut saw_class_flag = false;
    let mut at_least_one_enabled = false;

    for field in ["lowercase", "uppercase", "numbers", "symbols"] {
        if let Some(value) = policy_object.get(field) {
            let Some(enabled) = value.as_bool() else {
                return Err(format!("policy.{field} must be a boolean"));
            };

            saw_class_flag = true;
            at_least_one_enabled |= enabled;
        }
    }

    if saw_class_flag && !at_least_one_enabled {
        return Err("policy cannot disable all password character classes".to_string());
    }

    Ok(())
}

fn validate_source(source: &Value) -> Result<(), String> {
    let Some(source_object) = source.as_object() else {
        return Err("source must be a JSON object".to_string());
    };

    for field in ["flow", "passwordSource", "generatedRequestId"] {
        if let Some(value) = source_object.get(field) {
            let Some(text) = value.as_str() else {
                return Err(format!("source.{field} must be a string"));
            };

            if text.len() > MAX_SOURCE_STRING_BYTES {
                return Err(format!("source.{field} is too long"));
            }
        }
    }

    for field in ["generatedAt", "collectedAt"] {
        if let Some(value) = source_object.get(field) {
            if !(value.is_null() || value.is_number()) {
                return Err(format!("source.{field} must be a number or null"));
            }
        }
    }

    if let Some(field_sources) = source_object.get("fieldSources") {
        if !field_sources.is_object() {
            return Err("source.fieldSources must be an object when present".to_string());
        }
    }

    Ok(())
}

fn string_field<'a>(object: &'a serde_json::Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

fn daemon_error(request_id: &str, code: &str, message: &str) -> Value {
    json!({
        "ok": false,
        "type": "DAEMON_ERROR",
        "requestId": request_id,
        "error": {
            "code": code,
            "message": message
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_test_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        std::env::temp_dir().join(format!("vaulty-{name}-{}-{nanos}", std::process::id()))
    }

    fn send_test_message(path: &Path, value: &Value) -> Value {
        let mut stream = UnixStream::connect(path).unwrap();
        let bytes = serde_json::to_vec(value).unwrap();

        stream.write_all(&(bytes.len() as u32).to_ne_bytes()).unwrap();
        stream.write_all(&bytes).unwrap();
        stream.flush().unwrap();

        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).unwrap();
        let len = u32::from_ne_bytes(len_buf) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).unwrap();

        serde_json::from_slice(&body).unwrap()
    }

    #[test]
    fn starts_and_serves_mock_retrieve() {
        let dir = unique_test_path("daemon-dir");
        let sock = dir.join("vaulty.sock");
        let daemon = start_daemon_at(&dir, &sock).unwrap();

        let response = send_test_message(
            &sock,
            &json!({
                "type": "RETRIEVE_CREDENTIAL",
                "requestId": "test-1",
                "origin": "https://example.com",
                "purpose": "login_fill"
            }),
        );

        assert_eq!(response["ok"], true);
        assert_eq!(response["credential"]["username"], MOCK_USERNAME);
        assert_eq!(response["credential"]["password"], MOCK_PASSWORD);

        daemon.shutdown().unwrap();
        assert!(!sock.exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_double_start() {
        let dir = unique_test_path("daemon-double-dir");
        let sock = dir.join("vaulty.sock");
        let daemon = start_daemon_at(&dir, &sock).unwrap();

        let second = start_daemon_at(&dir, &sock);
        assert!(matches!(second, Err(DaemonError::AlreadyRunning(_))));

        daemon.shutdown().unwrap();
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_bad_origin() {
        let response = handle_mock_daemon_request(json!({
            "type": "RETRIEVE_CREDENTIAL",
            "requestId": "test-1",
            "origin": "file:///tmp/test.html",
            "purpose": "login_fill"
        }));

        assert_eq!(response["ok"], false);
        assert_eq!(response["error"]["code"], "INVALID_ORIGIN");
    }
}
