#![allow(dead_code)]

mod crypto;
#[cfg(test)]
mod tests;

use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use clap::Parser;
use crypto::{JweObject, b64url_encode, decrypt_jwe, encrypt_jwe, load_kek};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants & Types
// ---------------------------------------------------------------------------

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Serialize, Deserialize)]
struct HealthResponse {
    status: String,
    version: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
    message: String,
    request_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyRequest {
    #[serde(rename = "use")]
    #[serde(skip_serializing_if = "Option::is_none")]
    use_field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Jwk {
    kty: String,
    k: String,
    alg: String,
    #[serde(rename = "use")]
    use_field: String,
    kid: String,
}

// ---------------------------------------------------------------------------
// CLI via clap (supplements env vars)
// ---------------------------------------------------------------------------

/// Security Encryption API — stateless AES-128 key generation (JWE A128KW + A128GCM)
#[derive(Parser, Debug, Clone)]
#[command(name = "key-provider-api", version = VERSION, about = "Stateless AES-128 key generation service (JWE A128KW + A128GCM)", long_about = None)]
struct Cli {
    /// Key Encryption Key, base64url-encoded 16 bytes (128 bits). Env: KEK_VALUE
    #[arg(long = "kek-value", value_name = "BASE64URL", env = "KEK_VALUE")]
    kek_value: Option<String>,

    /// Alias for --kek-value. Env: KEK
    #[arg(long = "kek", value_name = "BASE64URL", env = "KEK", hide = true)]
    kek: Option<String>,

    /// Full bind address, e.g. 127.0.0.1:3000. Takes precedence over --host/--port. Env: BIND_ADDR
    #[arg(long = "bind-addr", value_name = "ADDR", env = "BIND_ADDR")]
    bind_addr: Option<String>,

    /// Host to listen on. Env: HOST
    #[arg(
        long = "host",
        value_name = "HOST",
        env = "HOST",
        default_value = "0.0.0.0"
    )]
    host: String,

    /// Port to listen on. Env: PORT
    #[arg(
        long = "port",
        value_name = "PORT",
        env = "PORT",
        default_value_t = 3000
    )]
    port: u16,
}

/// Shared application state, provided to handlers via axum `State`.
#[derive(Clone)]
struct AppState {
    /// Pre-shared Key Encryption Key, if configured. `None` means every
    /// `POST /v1/keys` request fails with `500 internal_error`.
    kek: Option<[u8; 16]>,
    /// Per-request logger: each `POST /v1/keys` writes `./<n>.log`.
    key_logger: Arc<KeyLogger>,
}

fn kek_string(cli: &Cli) -> Option<String> {
    if let Some(v) = cli.kek_value.clone().filter(|s| !s.trim().is_empty()) {
        return Some(v);
    }
    if let Some(v) = cli.kek.clone().filter(|s| !s.trim().is_empty()) {
        return Some(v);
    }
    None
}

fn bind_addr(cli: &Cli) -> String {
    if let Some(addr) = cli.bind_addr.clone().filter(|s| !s.trim().is_empty()) {
        return addr;
    }
    format!("{}:{}", cli.host, cli.port)
}

// JOSE crypto primitives (AES-KW, AES-GCM, JWE) live in crypto.rs.

// ---------------------------------------------------------------------------
// Core key-generation logic (framework-agnostic, unit-testable)
// ---------------------------------------------------------------------------

fn new_request_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn status_code_for_error(error: &str) -> StatusCode {
    match error {
        "invalid_request" => StatusCode::BAD_REQUEST,
        "decryption_failed" => StatusCode::BAD_REQUEST,
        "internal_error" => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    }
}

fn error_body(error: &str, message: &str) -> String {
    serde_json::json!({
        "error": error,
        "message": message,
        "request_id": new_request_id()
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// Key-provisioning logs (only POST /v1/keys outcomes, one file per request)
// ---------------------------------------------------------------------------

/// Per-request logger: request N writes `./N.log` (`1.log`, `2.log`, …)
/// containing one `"<code>: <detail>"` line. Numbering starts at 1 on every
/// start. The counter is lock-free (`AtomicU64`), so concurrent requests
/// never share a file number.
struct KeyLogger {
    next: AtomicU64,
}

impl KeyLogger {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            next: AtomicU64::new(1),
        })
    }

    /// Write one request's log line to the next `./<n>.log` file.
    /// Never fails the request: I/O errors are reported to stderr only.
    fn write(&self, line: &str) {
        let n = self.next.fetch_add(1, Ordering::SeqCst);
        let name = format!("{n}.log");
        if let Err(e) = fs::write(&name, format!("{line}\n")) {
            eprintln!("warning: failed to write key log {name}: {e}");
        }
    }
}

/// Build the one-line log detail for a failed request.
/// Decryption failures mean the client KEK did not match, so they are
/// logged as `invalid KEK` (with the underlying reason in parentheses).
fn failure_log_line(status: StatusCode, error: &str, message: &str) -> String {
    if error == "decryption_failed" {
        format!("{}: invalid KEK ({})", status.as_u16(), message)
    } else {
        format!("{}: {}", status.as_u16(), message)
    }
}

/// Pure business logic for POST /v1/keys.
/// Returns (http status, content-type, body string, file log line).
fn process_keys_request(
    kek: Option<&[u8; 16]>,
    raw_body: &[u8],
) -> (StatusCode, &'static str, String, String) {
    if raw_body.is_empty() {
        let msg = "missing body".to_string();
        let log = failure_log_line(StatusCode::BAD_REQUEST, "invalid_request", &msg);
        return (
            StatusCode::BAD_REQUEST,
            "application/json",
            error_body("invalid_request", &msg),
            log,
        );
    }

    let jwe: JweObject = match serde_json::from_slice(raw_body) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("malformed JWE: {}", e);
            let log = failure_log_line(StatusCode::BAD_REQUEST, "invalid_request", &msg);
            return (
                StatusCode::BAD_REQUEST,
                "application/json",
                error_body("invalid_request", &msg),
                log,
            );
        }
    };

    if jwe.protected.is_empty()
        || jwe.encrypted_key.is_empty()
        || jwe.iv.is_empty()
        || jwe.ciphertext.is_empty()
        || jwe.tag.is_empty()
    {
        let msg = "missing JWE fields".to_string();
        let log = failure_log_line(StatusCode::BAD_REQUEST, "invalid_request", &msg);
        return (
            StatusCode::BAD_REQUEST,
            "application/json",
            error_body("invalid_request", &msg),
            log,
        );
    }

    let kek = match kek {
        Some(k) => k,
        None => {
            let msg = "KEK_VALUE not set (provide --kek-value or env KEK_VALUE/KEK)".to_string();
            let log = failure_log_line(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", &msg);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "application/json",
                error_body("internal_error", &msg),
                log,
            );
        }
    };

    let plaintext = match decrypt_jwe(&jwe, &kek) {
        Ok(p) => p,
        Err((err, msg)) => {
            let status = status_code_for_error(&err);
            let log = failure_log_line(status, &err, &msg);
            return (status, "application/json", error_body(&err, &msg), log);
        }
    };

    let key_req: serde_json::Value = match serde_json::from_slice(&plaintext) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("decrypted payload not valid JSON: {}", e);
            let log = failure_log_line(StatusCode::BAD_REQUEST, "invalid_request", &msg);
            return (
                StatusCode::BAD_REQUEST,
                "application/json",
                error_body("invalid_request", &msg),
                log,
            );
        }
    };

    let use_val = key_req
        .get("use")
        .and_then(|v| v.as_str())
        .unwrap_or("enc")
        .to_string();
    if use_val != "enc" && use_val != "sig" {
        let msg = "invalid use field, must be enc or sig".to_string();
        let log = failure_log_line(StatusCode::BAD_REQUEST, "invalid_request", &msg);
        return (
            StatusCode::BAD_REQUEST,
            "application/json",
            error_body("invalid_request", &msg),
            log,
        );
    }
    let kid_val = key_req
        .get("kid")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(new_request_id);

    let mut dek = [0u8; 16];
    if let Err(e) = getrandom::fill(&mut dek) {
        let msg = format!("random generation failed: {:?}", e);
        let log = failure_log_line(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", &msg);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "application/json",
            error_body("internal_error", &msg),
            log,
        );
    }
    let k_b64 = b64url_encode(&dek);

    let jwk = Jwk {
        kty: "oct".to_string(),
        k: k_b64.clone(),
        alg: "A128GCM".to_string(),
        use_field: use_val,
        kid: kid_val,
    };

    let jwk_bytes = match serde_json::to_vec(&jwk) {
        Ok(b) => b,
        Err(e) => {
            let msg = format!("jwk serialize failed: {}", e);
            let log = failure_log_line(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", &msg);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "application/json",
                error_body("internal_error", &msg),
                log,
            );
        }
    };

    match encrypt_jwe(&jwk_bytes, &kek, "jwk+json") {
        Ok(resp_jwe) => match serde_json::to_string(&resp_jwe) {
            Ok(s) => (
                StatusCode::OK,
                "application/jose+json",
                s,
                format!("200: provided with fresh key {}", k_b64),
            ),
            Err(e) => {
                let msg = format!("response serialize failed: {}", e);
                let log =
                    failure_log_line(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", &msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "application/json",
                    error_body("internal_error", &msg),
                    log,
                )
            }
        },
        Err(e) => {
            let msg = format!("response encryption failed: {}", e);
            let log = failure_log_line(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", &msg);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "application/json",
                error_body("internal_error", &msg),
                log,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Axum handlers
// ---------------------------------------------------------------------------

async fn health_handler() -> impl IntoResponse {
    let body = serde_json::json!({
        "status": "ok",
        "version": VERSION
    })
    .to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap()
}

async fn index_handler() -> impl IntoResponse {
    let body = serde_json::json!({
        "name": "key-provider-api",
        "version": VERSION,
        "description": "Stateless AES-128 key generation service. Requests and responses carry key material only inside JWE (RFC 7516); generated keys are returned as JWK (RFC 7517). Keys are ephemeral and never stored.",
        "encryption": {
            "alg": "A128KW",
            "enc": "A128GCM",
            "kek": "pre-shared 128-bit key, base64url-encoded (see --kek-value / KEK_VALUE)"
        },
        "endpoints": [
            {
                "method": "GET",
                "path": "/",
                "description": "This documentation",
                "response": "application/json"
            },
            {
                "method": "GET",
                "path": "/health",
                "description": "Liveness probe, no authentication required",
                "response": "application/json"
            },
            {
                "method": "POST",
                "path": "/v1/keys",
                "description": "Generate a new AES-128 key. Request and response bodies are JWE JSON Serializations encrypted with the pre-shared KEK.",
                "request": "application/jose+json",
                "response": "application/jose+json"
            }
        ]
    })
    .to_string();
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap()
}

async fn keys_handler(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    let start = Instant::now();
    let (status, content_type, resp_body, log_line) =
        process_keys_request(state.kek.as_ref(), &body);
    // Per-request log file (`./<n>.log`): key-provisioning outcomes only.
    state.key_logger.write(&log_line);
    // Stderr: method, path, status, latency - never key material.
    eprintln!(
        "POST /v1/keys {} {}ms",
        status.as_u16(),
        start.elapsed().as_millis()
    );
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .body(axum::body::Body::from(resp_body))
        .unwrap()
}

async fn fallback_404() -> impl IntoResponse {
    let body = error_body("invalid_request", "not found");
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .unwrap()
}

fn app_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index_handler))
        .route("/health", get(health_handler))
        .route("/v1/keys", post(keys_handler))
        .fallback(fallback_404)
        .with_state(state)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cli = Cli::parse();

    // Numbering for per-request log files starts at ./1.log on every start.
    let key_logger = KeyLogger::new();
    let state = match load_kek(kek_string(&cli)) {
        Ok(kek) => AppState {
            kek: Some(kek),
            key_logger,
        },
        Err(e) => {
            eprintln!("warning: {e}; requests to /v1/keys will fail with 500 until configured");
            AppState {
                kek: None,
                key_logger,
            }
        }
    };

    let app = app_router(state);

    let addr = bind_addr(&cli);
    eprintln!("key-provider-api v{VERSION} listening on {addr}");
    // run our app with hyper, listening globally
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

    axum::serve(listener, app).await.unwrap();
}
