//! # pixa-vault
//!
//! Post-quantum hardened secure vault for Pixagram.
//!
//! Replaces PBKDF2 with a modern cryptographic stack designed to protect
//! short PINs (6+ characters) against GPU/ASIC brute-force attacks:
//!
//! | Layer          | Old (v3.x)              | New (v4.0)                         |
//! |----------------|-------------------------|------------------------------------|
//! | KDF            | PBKDF2-SHA512 (1M iter) | **Argon2id** (64 MiB, 3 iter)      |
//! | Encryption     | AES-GCM (Web Crypto)    | **ChaCha20-Poly1305** (WASM)       |
//! | PIN verify     | PBKDF2 + purpose salt   | **BLAKE3** over HKDF sub-key       |
//! | Domain sep.    | Salt suffix byte        | **HKDF-SHA512** purpose strings    |
//! | Memory safety  | None (JS heap)          | **zeroize** on drop                |
//! | AAD binding    | None                    | **Account name** bound to ciphertext|
//!
//! ## Architecture
//!
//! ```text
//! PIN (6+ chars)
//!   │
//!   ▼
//! ┌──────────────────────────────────────────┐
//! │  Argon2id(pin, salt, 64MiB, t=3, p=1)   │  ← Memory-hard KDF
//! └──────────────────┬───────────────────────┘
//!                    │ master_key (32 bytes, zeroized after use)
//!                    │
//!         ┌──────────┼──────────┐
//!         ▼          ▼          ▼
//!   HKDF("encrypt") HKDF("verify") HKDF("session")
//!         │          │          │
//!         ▼          ▼          ▼
//!   ChaCha20-Poly1305  BLAKE3 hash   Session AES key
//!   (vault encrypt)    (stored in    (in-memory
//!                       IndexedDB)    encryption)
//! ```

pub mod cipher;
pub mod error;
pub mod kdf;
pub mod vault;
pub mod verify;

use wasm_bindgen::prelude::*;
use hex;
use zeroize::Zeroize;

use kdf::KdfParams;

// ============================================================
// WASM Exports — called from JavaScript via wasm-bindgen
// ============================================================

/// Generate a cryptographic salt (hex-encoded).
/// Default: 32 bytes = 64 hex chars.
#[wasm_bindgen(js_name = "generateSalt")]
pub fn generate_salt(byte_length: Option<usize>) -> String {
    let len = byte_length.unwrap_or(32);
    let mut salt = vec![0u8; len];
    getrandom::getrandom(&mut salt).expect("CSPRNG failed");
    let result = hex::encode(&salt);
    salt.zeroize();
    result
}

/// Derive the encryption key from PIN + salt using Argon2id + HKDF.
///
/// Returns hex-encoded 32-byte encryption key.
///
/// Parameters:
///   - `pin`: User's PIN string (6+ chars)
///   - `salt_hex`: Hex-encoded salt (from generateSalt)
///   - `memory_kib`: Argon2 memory cost in KiB (default: 65536 = 64MiB)
///   - `iterations`: Argon2 time cost (default: 3)
///
/// This is the core replacement for `pbkdf2Derive()`.
#[wasm_bindgen(js_name = "deriveEncryptionKey")]
pub fn derive_encryption_key(
    pin: &str,
    salt_hex: &str,
    memory_kib: Option<u32>,
    iterations: Option<u32>,
) -> Result<String, JsValue> {
    let salt = hex::decode(salt_hex)
        .map_err(|_| JsValue::from_str("Invalid hex salt"))?;

    let params = KdfParams {
        memory_kib: memory_kib.unwrap_or(65536),
        iterations: iterations.unwrap_or(3),
        parallelism: 1,
        key_length: 32,
    };

    let mut master = kdf::derive_master_key(pin.as_bytes(), &salt, &params)?;
    let enc_key = kdf::derive_subkey(&master, verify::PURPOSE_ENCRYPT, 32)?;
    master.zeroize();

    let result = hex::encode(&enc_key);
    Ok(result)
}

/// Generate a PIN verification hash (hex-encoded BLAKE3).
///
/// Store this in IndexedDB. It cannot be used to derive the encryption key
/// (domain separation via HKDF).
///
/// Replaces `_derivePinVerifyHash()`.
#[wasm_bindgen(js_name = "generatePinVerifyHash")]
pub fn generate_pin_verify_hash(
    pin: &str,
    salt_hex: &str,
    memory_kib: Option<u32>,
    iterations: Option<u32>,
) -> Result<String, JsValue> {
    let salt = hex::decode(salt_hex)
        .map_err(|_| JsValue::from_str("Invalid hex salt"))?;

    let params = KdfParams {
        memory_kib: memory_kib.unwrap_or(65536),
        iterations: iterations.unwrap_or(3),
        parallelism: 1,
        key_length: 32,
    };

    let hash = verify::generate_pin_verify_hash(pin.as_bytes(), &salt, &params)?;
    Ok(hash)
}

/// Verify a PIN against a stored hash.
///
/// Returns `true` if the PIN matches, `false` otherwise.
/// Timing is dominated by Argon2id (~1s), making timing attacks irrelevant.
#[wasm_bindgen(js_name = "verifyPin")]
pub fn verify_pin(
    pin: &str,
    salt_hex: &str,
    stored_hash: &str,
    memory_kib: Option<u32>,
    iterations: Option<u32>,
) -> Result<bool, JsValue> {
    let salt = hex::decode(salt_hex)
        .map_err(|_| JsValue::from_str("Invalid hex salt"))?;

    let params = KdfParams {
        memory_kib: memory_kib.unwrap_or(65536),
        iterations: iterations.unwrap_or(3),
        parallelism: 1,
        key_length: 32,
    };

    let result = verify::verify_pin(pin.as_bytes(), &salt, stored_hash, &params)?;
    Ok(result)
}

/// Encrypt a string value using ChaCha20-Poly1305.
///
/// Parameters:
///   - `key_hex`: Hex-encoded 32-byte key (from deriveEncryptionKey)
///   - `plaintext`: UTF-8 string to encrypt
///   - `aad`: Optional additional authenticated data (e.g., account name)
///
/// Returns base64-encoded ciphertext (nonce || encrypted || tag).
#[wasm_bindgen(js_name = "encrypt")]
pub fn wasm_encrypt(
    key_hex: &str,
    plaintext: &str,
    aad: Option<String>,
) -> Result<String, JsValue> {
    let key_bytes = hex::decode(key_hex)
        .map_err(|_| JsValue::from_str("Invalid hex key"))?;
    if key_bytes.len() != 32 {
        return Err(JsValue::from_str("Key must be 32 bytes"));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    let result = cipher::encrypt_string(
        &key,
        plaintext,
        aad.as_deref().map(|s| s.as_bytes()),
    )?;

    key.zeroize();
    Ok(result)
}

/// Decrypt a base64-encoded ciphertext back to a string.
///
/// Returns the plaintext string, or throws on wrong key / tampered data.
#[wasm_bindgen(js_name = "decrypt")]
pub fn wasm_decrypt(
    key_hex: &str,
    ciphertext_b64: &str,
    aad: Option<String>,
) -> Result<String, JsValue> {
    let key_bytes = hex::decode(key_hex)
        .map_err(|_| JsValue::from_str("Invalid hex key"))?;
    if key_bytes.len() != 32 {
        return Err(JsValue::from_str("Key must be 32 bytes"));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    let result = cipher::decrypt_string(
        &key,
        ciphertext_b64,
        aad.as_deref().map(|s| s.as_bytes()),
    )?;

    key.zeroize();
    Ok(result)
}

/// Full vault seal: PIN → Argon2id → HKDF → ChaCha20-Poly1305.
///
/// Encrypts `plaintext` in one shot, using `account` as AAD binding.
/// Returns a JSON string containing the SealedRecord.
///
/// This replaces the entire LacertaDB `getSecureDatabase` flow for
/// individual secret storage.
#[wasm_bindgen(js_name = "sealSecret")]
pub fn seal_secret(
    pin: &str,
    salt_hex: &str,
    account: &str,
    plaintext: &str,
    memory_kib: Option<u32>,
    iterations: Option<u32>,
) -> Result<String, JsValue> {
    let salt = hex::decode(salt_hex)
        .map_err(|_| JsValue::from_str("Invalid hex salt"))?;

    let params = KdfParams {
        memory_kib: memory_kib.unwrap_or(65536),
        iterations: iterations.unwrap_or(3),
        parallelism: 1,
        key_length: 32,
    };

    let sealed = vault::seal(pin.as_bytes(), &salt, account, plaintext.as_bytes(), &params)?;
    serde_json::to_string(&sealed)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Full vault unseal: PIN → Argon2id → HKDF → ChaCha20-Poly1305 decrypt.
///
/// Decrypts a JSON SealedRecord string back to plaintext.
#[wasm_bindgen(js_name = "unsealSecret")]
pub fn unseal_secret(
    pin: &str,
    salt_hex: &str,
    sealed_json: &str,
    memory_kib: Option<u32>,
    iterations: Option<u32>,
) -> Result<String, JsValue> {
    let salt = hex::decode(salt_hex)
        .map_err(|_| JsValue::from_str("Invalid hex salt"))?;

    let params = KdfParams {
        memory_kib: memory_kib.unwrap_or(65536),
        iterations: iterations.unwrap_or(3),
        parallelism: 1,
        key_length: 32,
    };

    let record: vault::SealedRecord = serde_json::from_str(sealed_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid sealed record: {}", e)))?;

    let plaintext = vault::unseal(pin.as_bytes(), &salt, &record, &params)?;
    Ok(plaintext)
}

/// Seal multiple keys at once (posting, active, memo, owner).
///
/// Parameters:
///   - `keys_json`: JSON object `{ "posting": "5J...", "active": "5J...", ... }`
///
/// Returns a JSON string with sealed records for each key type.
/// Each key type gets its own AAD binding: `{account}:{type}`.
#[wasm_bindgen(js_name = "sealKeys")]
pub fn seal_keys(
    pin: &str,
    salt_hex: &str,
    account: &str,
    keys_json: &str,
    memory_kib: Option<u32>,
    iterations: Option<u32>,
) -> Result<String, JsValue> {
    let salt = hex::decode(salt_hex)
        .map_err(|_| JsValue::from_str("Invalid hex salt"))?;

    let params = KdfParams {
        memory_kib: memory_kib.unwrap_or(65536),
        iterations: iterations.unwrap_or(3),
        parallelism: 1,
        key_length: 32,
    };

    let keys: std::collections::HashMap<String, String> = serde_json::from_str(keys_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid keys JSON: {}", e)))?;

    let sealed = vault::seal_keys(pin.as_bytes(), &salt, account, &keys, &params)?;
    Ok(sealed)
}

/// Unseal multiple keys from a sealed JSON blob.
///
/// Returns a JSON object `{ "posting": "5J...", "active": "5J...", ... }`.
#[wasm_bindgen(js_name = "unsealKeys")]
pub fn unseal_keys(
    pin: &str,
    salt_hex: &str,
    sealed_json: &str,
    memory_kib: Option<u32>,
    iterations: Option<u32>,
) -> Result<String, JsValue> {
    let salt = hex::decode(salt_hex)
        .map_err(|_| JsValue::from_str("Invalid hex salt"))?;

    let params = KdfParams {
        memory_kib: memory_kib.unwrap_or(65536),
        iterations: iterations.unwrap_or(3),
        parallelism: 1,
        key_length: 32,
    };

    let keys = vault::unseal_keys(pin.as_bytes(), &salt, sealed_json, &params)?;
    serde_json::to_string(&keys)
        .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
}

/// Return the vault version and crypto parameters as JSON.
///
/// Useful for migration detection: if the stored version differs from
/// the current version, the frontend knows to re-encrypt vault data.
#[wasm_bindgen(js_name = "getVaultInfo")]
pub fn get_vault_info() -> String {
    serde_json::json!({
        "version": 1,
        "crate_version": env!("CARGO_PKG_VERSION"),
        "kdf": "argon2id",
        "cipher": "chacha20-poly1305",
        "hash": "blake3",
        "domain_sep": "hkdf-sha512",
        "default_memory_kib": 65536,
        "default_iterations": 3,
        "key_size_bits": 256,
        "nonce_size_bits": 96,
        "tag_size_bits": 128,
    })
    .to_string()
}

/// Quick BLAKE3 hash of arbitrary data. Returns hex-encoded 32-byte hash.
/// Useful for fingerprinting, integrity checks, etc.
#[wasm_bindgen(js_name = "blake3Hash")]
pub fn blake3_hash(data: &str) -> String {
    blake3::hash(data.as_bytes()).to_hex().to_string()
}
