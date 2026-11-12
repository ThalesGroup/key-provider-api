//! Unit tests for the key-provider API (crypto primitives, request logic, handlers).

use super::crypto::{
    JweObject, aes_gcm_decrypt, aes_gcm_encrypt, b64url_decode, decrypt_jwe, encrypt_jwe,
    kw_unwrap, kw_wrap,
};
use super::{
    AppState, KeyLogger, fallback_404, health_handler, index_handler, keys_handler,
    process_keys_request,
};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

fn test_kek() -> [u8; 16] {
    // deterministic 0x00..0x0f
    let mut k = [0u8; 16];
    for i in 0..16 {
        k[i] = i as u8;
    }
    k
}

fn test_state() -> AppState {
    AppState {
        kek: Some(test_kek()),
        key_logger: KeyLogger::new(),
    }
}

// The per-request logger writes ./<n>.log into the process working directory,
// which all tests share. Tests that trigger handler/logger writes serialize
// on this lock and remove their files afterwards, so parallel tests never
// race on the same numbers.
static LOG_FILE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_log_files() -> std::sync::MutexGuard<'static, ()> {
    LOG_FILE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn remove_numbered_logs() {
    for n in 1..=16 {
        let _ = std::fs::remove_file(format!("{n}.log"));
    }
}

async fn response_json(res: axum::response::Response) -> (StatusCode, serde_json::Value) {
    let status = res.status();
    let ctype = res
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert_eq!(ctype, "application/json");
    let body = axum::body::to_bytes(res.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    (status, v)
}

// ---------------------------------------------------------------------------
// Crypto primitives
// ---------------------------------------------------------------------------

#[test]
fn test_kw_roundtrip() {
    let kek = test_kek();
    let cek = [0x11u8; 16];
    let wrapped = kw_wrap(&kek, &cek).unwrap();
    let unwrapped = kw_unwrap(&kek, &wrapped).unwrap();
    assert_eq!(cek.to_vec(), unwrapped);
}

#[test]
fn test_gcm_roundtrip() {
    let cek = [0x02u8; 16];
    let iv = [0x03u8; 12];
    let plaintext = b"hello world";
    let aad = b"test-aad";
    let (ct, tag) = aes_gcm_encrypt(&cek, &iv, plaintext, aad).unwrap();
    let dec = aes_gcm_decrypt(&cek, &iv, &ct, &tag, aad).unwrap();
    assert_eq!(plaintext.to_vec(), dec);
}

#[test]
fn test_jwe_roundtrip() {
    let kek = test_kek();
    let payload = br#"{"use":"enc","kid":"test123"}"#;
    let jwe = encrypt_jwe(payload, &kek, "application/json").unwrap();
    let dec = decrypt_jwe(&jwe, &kek).unwrap();
    assert_eq!(payload.to_vec(), dec);
}

#[test]
fn test_full_flow() {
    let kek = test_kek();
    let payload = br#"{"use":"sig"}"#;
    let req_jwe = encrypt_jwe(payload, &kek, "application/json").unwrap();
    let req_bytes = serde_json::to_vec(&req_jwe).unwrap();
    // Simulate decrypt
    let jwe: JweObject = serde_json::from_slice(&req_bytes).unwrap();
    let dec = decrypt_jwe(&jwe, &kek).unwrap();
    let val: serde_json::Value = serde_json::from_slice(&dec).unwrap();
    assert_eq!(val.get("use").unwrap().as_str().unwrap(), "sig");
}

// ---------------------------------------------------------------------------
// Request logic
// ---------------------------------------------------------------------------

#[test]
fn test_process_keys_missing_body() {
    let kek = test_kek();
    let (status, _ct, body, log_line) = process_keys_request(Some(&kek), b"");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"], "invalid_request");
    assert!(log_line.starts_with("400:"));
}

#[test]
fn test_process_keys_malformed() {
    let kek = test_kek();
    let (status, _ct, body, log_line) = process_keys_request(Some(&kek), b"notjson");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"], "invalid_request");
    assert!(log_line.starts_with("400:"));
}

#[test]
fn test_process_keys_no_kek_configured() {
    // Well-formed JWE envelope so validation reaches the KEK check.
    let raw = br#"{"protected":"a","encrypted_key":"b","iv":"c","ciphertext":"d","tag":"e"}"#;
    let (status, _ct, body, log_line) = process_keys_request(None, raw);
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["error"], "internal_error");
    assert!(log_line.starts_with("500:"));
}

// ---------------------------------------------------------------------------
// Handlers (called directly, no HTTP stack needed)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_health_handler() {
    let (status, v) = response_json(health_handler().await.into_response()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["status"], "ok");
}

#[tokio::test]
async fn test_index_handler_returns_docs() {
    let (status, v) = response_json(index_handler().await.into_response()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(v["name"], "key-provider-api");
    assert!(
        v.get("endpoints")
            .and_then(|e| e.as_array())
            .is_some_and(|a| !a.is_empty())
    );
}

#[tokio::test]
async fn test_fallback_404() {
    let (status, v) = response_json(fallback_404().await.into_response()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(v["error"], "invalid_request");
}

#[tokio::test]
async fn test_keys_handler_malformed_body() {
    let _guard = lock_log_files();
    let res = keys_handler(State(test_state()), Bytes::from("notjson"))
        .await
        .into_response();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["error"], "invalid_request");
    remove_numbered_logs();
}

#[tokio::test]
async fn test_keys_handler_full_flow() {
    let _guard = lock_log_files();
    let kek = test_kek();
    // Encrypt a request payload the same way a client would.
    let payload = br#"{"use":"sig","kid":"handler-test-kid"}"#;
    let req_jwe = encrypt_jwe(payload, &kek, "application/json").unwrap();
    let req_bytes = Bytes::from(serde_json::to_vec(&req_jwe).unwrap());

    let res = keys_handler(State(test_state()), req_bytes)
        .await
        .into_response();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(
        res.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/jose+json")
    );
    let body = axum::body::to_bytes(res.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let resp_jwe: JweObject = serde_json::from_slice(&body).unwrap();
    let pt = decrypt_jwe(&resp_jwe, &kek).unwrap();
    let jwk: serde_json::Value = serde_json::from_slice(&pt).unwrap();
    assert_eq!(jwk["kty"], "oct");
    assert_eq!(jwk["alg"], "A128GCM");
    assert_eq!(jwk["use"], "sig");
    assert_eq!(jwk["kid"], "handler-test-kid");
    assert_eq!(b64url_decode(jwk["k"].as_str().unwrap()).unwrap().len(), 16);
    remove_numbered_logs();
}

#[test]
fn test_process_keys_success_log_contains_fresh_key() {
    let kek = test_kek();
    let payload = br#"{"use":"enc"}"#;
    let req_jwe = encrypt_jwe(payload, &kek, "application/json").unwrap();
    let req_bytes = serde_json::to_vec(&req_jwe).unwrap();
    let (status, _ct, body, log_line) = process_keys_request(Some(&kek), &req_bytes);
    assert_eq!(status, StatusCode::OK);
    // Log line must be "200: provided with fresh key XXXX" where XXXX == JWK k.
    assert!(log_line.starts_with("200: provided with fresh key "));
    let logged_k = log_line.strip_prefix("200: provided with fresh key ").unwrap();
    let resp_jwe: JweObject = serde_json::from_slice(body.as_bytes()).unwrap();
    let pt = decrypt_jwe(&resp_jwe, &kek).unwrap();
    let jwk: serde_json::Value = serde_json::from_slice(&pt).unwrap();
    assert_eq!(jwk["k"].as_str().unwrap(), logged_k);
}

#[test]
fn test_process_keys_wrong_kek_logs_invalid_kek() {
    let kek = test_kek();
    let mut wrong_kek = test_kek();
    wrong_kek[0] ^= 0xff;
    let payload = br#"{"use":"enc"}"#;
    let req_jwe = encrypt_jwe(payload, &kek, "application/json").unwrap();
    let req_bytes = serde_json::to_vec(&req_jwe).unwrap();
    let (status, _ct, _body, log_line) = process_keys_request(Some(&wrong_kek), &req_bytes);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(log_line, format!("400: invalid KEK ({})", {
        // decrypt must fail; reproduce message via decrypt_jwe for assertion stability
        let jwe: JweObject = serde_json::from_slice(&req_bytes).unwrap();
        decrypt_jwe(&jwe, &wrong_kek).unwrap_err().1
    }));
}

#[test]
fn test_key_logger_writes_numbered_files() {
    let _guard = lock_log_files();
    remove_numbered_logs();
    let logger = KeyLogger::new();
    logger.write("200: provided with fresh key TESTKEY");
    logger.write("400: invalid KEK (test)");
    assert_eq!(
        std::fs::read_to_string("1.log").unwrap(),
        "200: provided with fresh key TESTKEY\n"
    );
    assert_eq!(
        std::fs::read_to_string("2.log").unwrap(),
        "400: invalid KEK (test)\n"
    );
    remove_numbered_logs();
}

#[test]
fn test_key_logger_starts_from_one_each_init() {
    let _guard = lock_log_files();
    remove_numbered_logs();
    // Simulate files left by a previous run.
    std::fs::write("1.log", "200: old\n").unwrap();
    std::fs::write("2.log", "200: old\n").unwrap();
    // A new logger numbers from 1 again (previous files get overwritten).
    let logger = KeyLogger::new();
    logger.write("400: missing body");
    assert_eq!(
        std::fs::read_to_string("1.log").unwrap(),
        "400: missing body\n"
    );
    logger.write("400: missing body");
    assert_eq!(
        std::fs::read_to_string("2.log").unwrap(),
        "400: missing body\n"
    );
    remove_numbered_logs();
}

#[tokio::test]
async fn test_keys_handler_writes_one_file_per_request() {
    let _guard = lock_log_files();
    remove_numbered_logs();
    let state = test_state();
    for _ in 0..2 {
        let res = keys_handler(State(state.clone()), Bytes::from("notjson"))
            .await
            .into_response();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }
    assert!(std::fs::read_to_string("1.log")
        .unwrap()
        .starts_with("400: malformed JWE:"));
    assert!(std::fs::read_to_string("2.log")
        .unwrap()
        .starts_with("400: malformed JWE:"));
    remove_numbered_logs();
}
