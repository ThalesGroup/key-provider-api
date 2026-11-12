//! JOSE cryptographic operations (RFC 7516 JWE + RFC 3394 AES Key Wrap).
//!
//! All key transport in this service uses `A128KW` (wrap of a fresh CEK with
//! the pre-shared KEK) + `A128GCM` (payload encryption). This module owns
//! the JWE envelope type and every primitive; it never logs key material.

use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// JWE envelope type
// ---------------------------------------------------------------------------

/// JWE JSON Serialization object (RFC 7516 §7.2).
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct JweObject {
    pub(crate) protected: String,
    pub(crate) encrypted_key: String,
    pub(crate) iv: String,
    pub(crate) ciphertext: String,
    pub(crate) tag: String,
}

// ---------------------------------------------------------------------------
// Base64URL helpers
// ---------------------------------------------------------------------------

pub(crate) fn b64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub(crate) fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    // Try URL_SAFE_NO_PAD first, then with padding variants, then standard
    // base64 to be liberal in accepting KEK values.
    if let Ok(v) = URL_SAFE_NO_PAD.decode(s) {
        return Ok(v);
    }
    // Try with padding added
    let mut padded = s.to_string();
    let rem = padded.len() % 4;
    if rem != 0 {
        padded.extend(std::iter::repeat('=').take(4 - rem));
    }
    if let Ok(v) = base64::engine::general_purpose::URL_SAFE.decode(&padded) {
        return Ok(v);
    }
    if let Ok(v) = base64::engine::general_purpose::STANDARD.decode(s) {
        return Ok(v);
    }
    if let Ok(v) = base64::engine::general_purpose::STANDARD_NO_PAD.decode(s) {
        return Ok(v);
    }
    Err(format!("invalid base64url: {}", s))
}

// ---------------------------------------------------------------------------
// KEK loading
// ---------------------------------------------------------------------------

/// Decode and validate the pre-shared Key Encryption Key (16 bytes).
pub(crate) fn load_kek(raw: Option<String>) -> Result<[u8; 16], String> {
    let raw = raw.filter(|s| !s.trim().is_empty()).ok_or_else(|| {
        "KEK_VALUE not set (provide --kek-value or env KEK_VALUE/KEK)".to_string()
    })?;
    let trimmed = raw.trim();
    let decoded = b64url_decode(trimmed).or_else(|_| Err("invalid KEK encoding".to_string()))?;
    if decoded.len() != 16 {
        return Err(format!(
            "KEK must be 16 bytes (128 bits), got {} bytes",
            decoded.len()
        ));
    }
    let mut kek = [0u8; 16];
    kek.copy_from_slice(&decoded);
    Ok(kek)
}

// ---------------------------------------------------------------------------
// AES-KW helpers (RFC 3394 A128KW)
// ---------------------------------------------------------------------------

pub(crate) fn kw_wrap(kek: &[u8; 16], cek: &[u8]) -> Result<Vec<u8>, String> {
    kw_wrap_manual(kek, cek)
}

pub(crate) fn kw_unwrap(kek: &[u8; 16], wrapped: &[u8]) -> Result<Vec<u8>, String> {
    kw_unwrap_manual(kek, wrapped)
}

// Manual RFC 3394 implementation using the aes crate ECB primitive.
#[allow(unused_imports)]
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit as AesKeyInit};

fn kw_wrap_manual(kek: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    if plaintext.len() % 8 != 0 {
        return Err("plaintext length must be multiple of 8".into());
    }
    if plaintext.len() < 16 {
        return Err("plaintext too short".into());
    }
    let n = plaintext.len() / 8;
    // Initial value A = 0xA6A6A6A6A6A6A6
    let mut a: [u8; 8] = [0xA6; 8];
    // Split plaintext into R[1..n]
    let mut blocks: Vec<[u8; 8]> = Vec::with_capacity(n);
    for i in 0..n {
        let mut block = [0u8; 8];
        block.copy_from_slice(&plaintext[i * 8..(i + 1) * 8]);
        blocks.push(block);
    }

    let cipher = aes::Aes128::new_from_slice(kek).map_err(|e| format!("aes init: {:?}", e))?;

    // 6 rounds
    for j in 0..6 {
        for i in 0..n {
            // B = AES(K, A || R[i])
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&a);
            b[8..].copy_from_slice(&blocks[i]);
            let mut block = aes::cipher::generic_array::GenericArray::from(b);
            cipher.encrypt_block(&mut block);
            let encrypted = block.as_slice();
            // A = MSB(64, B) ^ t where t = (n*j)+i+1
            let t = ((n * j) + (i + 1)) as u64;
            let mut new_a = [0u8; 8];
            new_a.copy_from_slice(&encrypted[..8]);
            // XOR with t (big endian)
            let t_bytes = t.to_be_bytes();
            for k in 0..8 {
                new_a[k] ^= t_bytes[k];
            }
            a = new_a;
            let mut new_r = [0u8; 8];
            new_r.copy_from_slice(&encrypted[8..]);
            blocks[i] = new_r;
        }
    }

    let mut out = Vec::with_capacity((n + 1) * 8);
    out.extend_from_slice(&a);
    for b in blocks {
        out.extend_from_slice(&b);
    }
    Ok(out)
}

fn kw_unwrap_manual(kek: &[u8; 16], wrapped: &[u8]) -> Result<Vec<u8>, String> {
    if wrapped.len() % 8 != 0 {
        return Err("wrapped length must be multiple of 8".into());
    }
    if wrapped.len() < 24 {
        return Err("wrapped too short".into());
    }
    let n = (wrapped.len() / 8) - 1;
    let mut a = [0u8; 8];
    a.copy_from_slice(&wrapped[..8]);
    let mut blocks: Vec<[u8; 8]> = Vec::with_capacity(n);
    for i in 0..n {
        let mut block = [0u8; 8];
        block.copy_from_slice(&wrapped[8 + i * 8..8 + (i + 1) * 8]);
        blocks.push(block);
    }

    let cipher = aes::Aes128::new_from_slice(kek).map_err(|e| format!("aes init: {:?}", e))?;

    for j in (0..6).rev() {
        for i in (0..n).rev() {
            let t = ((n * j) + (i + 1)) as u64;
            let mut ata = a;
            let t_bytes = t.to_be_bytes();
            for k in 0..8 {
                ata[k] ^= t_bytes[k];
            }
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&ata);
            b[8..].copy_from_slice(&blocks[i]);
            let mut block = aes::cipher::generic_array::GenericArray::from(b);
            cipher.decrypt_block(&mut block);
            let decrypted = block.as_slice();
            a.copy_from_slice(&decrypted[..8]);
            let mut new_r = [0u8; 8];
            new_r.copy_from_slice(&decrypted[8..]);
            blocks[i] = new_r;
        }
    }

    // Check IV
    if a != [0xA6; 8] {
        return Err("integrity check failed (A mismatch)".into());
    }

    let mut out = Vec::with_capacity(n * 8);
    for b in blocks {
        out.extend_from_slice(&b);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// AES-GCM helpers (A128GCM)
// ---------------------------------------------------------------------------

pub(crate) fn aes_gcm_encrypt(
    cek: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    if cek.len() != 16 {
        return Err("CEK must be 16 bytes".into());
    }
    if iv.len() != 12 {
        return Err("IV must be 12 bytes".into());
    }
    let key = aes_gcm::Key::<Aes128Gcm>::from_slice(cek);
    let cipher = Aes128Gcm::new(key);
    let nonce = aes_gcm::Nonce::from_slice(iv);
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let mut combined = cipher
        .encrypt(nonce, payload)
        .map_err(|e| format!("encrypt failed: {:?}", e))?;
    // combined = ciphertext || tag (tag is 16 bytes appended)
    if combined.len() < 16 {
        return Err("encrypt produced too short output".into());
    }
    let tag = combined.split_off(combined.len() - 16);
    let ciphertext = combined;
    Ok((ciphertext, tag))
}

pub(crate) fn aes_gcm_decrypt(
    cek: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    if cek.len() != 16 {
        return Err("CEK must be 16 bytes".into());
    }
    if iv.len() != 12 {
        return Err("IV must be 12 bytes".into());
    }
    if tag.len() != 16 {
        return Err("tag must be 16 bytes".into());
    }
    let key = aes_gcm::Key::<Aes128Gcm>::from_slice(cek);
    let cipher = Aes128Gcm::new(key);
    let nonce = aes_gcm::Nonce::from_slice(iv);
    let mut combined = Vec::with_capacity(ciphertext.len() + tag.len());
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(tag);
    let payload = Payload {
        msg: &combined,
        aad,
    };
    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| "gcm decrypt failed (auth tag mismatch)".to_string())?;
    Ok(plaintext)
}

// ---------------------------------------------------------------------------
// JWE encrypt/decrypt
// ---------------------------------------------------------------------------

pub(crate) fn decrypt_jwe(
    jwe: &JweObject,
    kek: &[u8; 16],
) -> Result<Vec<u8>, (String, String)> {
    // Validate protected header
    let protected_bytes = b64url_decode(&jwe.protected).map_err(|e| {
        (
            "invalid_request".to_string(),
            format!("invalid protected header base64: {}", e),
        )
    })?;

    let protected_json: serde_json::Value =
        serde_json::from_slice(&protected_bytes).map_err(|e| {
            (
                "invalid_request".to_string(),
                format!("invalid protected header json: {}", e),
            )
        })?;

    let alg = protected_json
        .get("alg")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let enc = protected_json
        .get("enc")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if alg != "A128KW" || enc != "A128GCM" {
        return Err((
            "invalid_request".to_string(),
            format!("unsupported alg/enc: {}/{}", alg, enc),
        ));
    }

    let encrypted_key_bytes = b64url_decode(&jwe.encrypted_key).map_err(|e| {
        (
            "decryption_failed".to_string(),
            format!("invalid encrypted_key: {}", e),
        )
    })?;
    let iv_bytes = b64url_decode(&jwe.iv).map_err(|e| {
        (
            "decryption_failed".to_string(),
            format!("invalid iv: {}", e),
        )
    })?;
    let ciphertext_bytes = b64url_decode(&jwe.ciphertext).map_err(|e| {
        (
            "decryption_failed".to_string(),
            format!("invalid ciphertext: {}", e),
        )
    })?;
    let tag_bytes = b64url_decode(&jwe.tag).map_err(|e| {
        (
            "decryption_failed".to_string(),
            format!("invalid tag: {}", e),
        )
    })?;

    if iv_bytes.len() != 12 {
        return Err((
            "decryption_failed".to_string(),
            "iv must be 12 bytes".to_string(),
        ));
    }
    if tag_bytes.len() != 16 {
        return Err((
            "decryption_failed".to_string(),
            "tag must be 16 bytes".to_string(),
        ));
    }

    // Unwrap CEK
    let cek = kw_unwrap(kek, &encrypted_key_bytes).map_err(|e| {
        (
            "decryption_failed".to_string(),
            format!("key unwrap failed: {}", e),
        )
    })?;

    if cek.len() != 16 {
        return Err((
            "decryption_failed".to_string(),
            format!("CEK must be 16 bytes, got {}", cek.len()),
        ));
    }

    // Decrypt with AAD = protected header string bytes (base64url encoded protected field)
    let aad = jwe.protected.as_bytes();
    let plaintext = aes_gcm_decrypt(&cek, &iv_bytes, &ciphertext_bytes, &tag_bytes, aad)
        .map_err(|e| ("decryption_failed".to_string(), e))?;

    Ok(plaintext)
}

pub(crate) fn encrypt_jwe(
    plaintext: &[u8],
    kek: &[u8; 16],
    cty: &str,
) -> Result<JweObject, String> {
    // Generate CEK 16 bytes
    let mut cek = [0u8; 16];
    getrandom::fill(&mut cek).map_err(|e| format!("random CEK failed: {:?}", e))?;
    // Generate IV 12 bytes
    let mut iv = [0u8; 12];
    getrandom::fill(&mut iv).map_err(|e| format!("random IV failed: {:?}", e))?;

    // Protected header
    let protected_json = format!(r#"{{"alg":"A128KW","enc":"A128GCM","cty":"{}"}}"#, cty);
    let protected_b64 = b64url_encode(protected_json.as_bytes());

    // Wrap CEK
    let wrapped = kw_wrap(kek, &cek)?;

    // Encrypt plaintext
    let aad = protected_b64.as_bytes();
    let (ciphertext_bytes, tag_bytes) = aes_gcm_encrypt(&cek, &iv, plaintext, aad)?;

    Ok(JweObject {
        protected: protected_b64,
        encrypted_key: b64url_encode(&wrapped),
        iv: b64url_encode(&iv),
        ciphertext: b64url_encode(&ciphertext_bytes),
        tag: b64url_encode(&tag_bytes),
    })
}
