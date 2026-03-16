use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::cipher;
use crate::error::VaultError;
use crate::kdf::{derive_master_key, derive_subkey, KdfParams};
use crate::verify::{PURPOSE_ENCRYPT, PURPOSE_SESSION, PURPOSE_VERIFY};

/// A sealed vault record: encrypted key material bound to an account.
///
/// Stored in IndexedDB / LacertaDB. The `ciphertext` field contains
/// ChaCha20-Poly1305 output (nonce || ct || tag), base64-encoded.
/// The `aad_account` field records which account the ciphertext is
/// bound to via AAD — prevents cross-account key theft.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SealedRecord {
    /// Format version for future migration
    pub version: u8,
    /// Base64-encoded ChaCha20-Poly1305 output: nonce(12) || ciphertext || tag(16)
    pub ciphertext: String,
    /// Account name used as AAD (Additional Authenticated Data)
    pub aad_account: String,
    /// BLAKE3 hash of the encryption sub-key (for integrity check, NOT secret)
    pub key_fingerprint: String,
    /// Timestamp of encryption
    pub created_at: u64,
}

/// Seal (encrypt) a secret value into a vault record.
///
/// Pipeline:
///   PIN → Argon2id(salt) → master_key
///   master_key → HKDF("encrypt") → enc_key
///   enc_key + nonce → ChaCha20-Poly1305(plaintext, aad=account) → ciphertext
///
/// The `account` parameter is used as AAD (Additional Authenticated Data)
/// to bind the ciphertext to a specific account. Decrypting with a
/// different account name will fail, preventing cross-account replay.
pub fn seal(
    pin: &[u8],
    salt: &[u8],
    account: &str,
    plaintext: &[u8],
    params: &KdfParams,
) -> Result<SealedRecord, VaultError> {
    // Derive master → encryption key
    let mut master = derive_master_key(pin, salt, params)?;
    let enc_key_vec = derive_subkey(&master, PURPOSE_ENCRYPT, 32)?;
    master.zeroize();

    let mut enc_key = [0u8; 32];
    enc_key.copy_from_slice(&enc_key_vec);

    // Key fingerprint (public, non-secret)
    let fingerprint = blake3::hash(&enc_key).to_hex().to_string();

    // Encrypt with account as AAD
    let ciphertext = cipher::encrypt_string(&enc_key, 
        std::str::from_utf8(plaintext).map_err(|_| VaultError::SerializationError("Not UTF-8".into()))?,
        Some(account.as_bytes()))?;
    enc_key.zeroize();

    Ok(SealedRecord {
        version: 1,
        ciphertext,
        aad_account: account.to_string(),
        key_fingerprint: fingerprint,
        created_at: now_millis(),
    })
}

/// Unseal (decrypt) a vault record back to plaintext.
///
/// Returns the decrypted secret as a UTF-8 string.
/// Fails with `DecryptionFailed` if the PIN is wrong or data is tampered.
pub fn unseal(
    pin: &[u8],
    salt: &[u8],
    record: &SealedRecord,
    params: &KdfParams,
) -> Result<String, VaultError> {
    let mut master = derive_master_key(pin, salt, params)?;
    let enc_key_vec = derive_subkey(&master, PURPOSE_ENCRYPT, 32)?;
    master.zeroize();

    let mut enc_key = [0u8; 32];
    enc_key.copy_from_slice(&enc_key_vec);

    let result = cipher::decrypt_string(&enc_key, &record.ciphertext, Some(record.aad_account.as_bytes()));
    enc_key.zeroize();

    result
}

/// Seal multiple key-value pairs (e.g., all 4 derived keys for an account).
///
/// Each key type gets its own AAD binding: `{account}:{type}`.
/// Returns a JSON string containing the sealed map.
pub fn seal_keys(
    pin: &[u8],
    salt: &[u8],
    account: &str,
    keys: &std::collections::HashMap<String, String>,
    params: &KdfParams,
) -> Result<String, VaultError> {
    // Derive encryption key once
    let mut master = derive_master_key(pin, salt, params)?;
    let enc_key_vec = derive_subkey(&master, PURPOSE_ENCRYPT, 32)?;
    master.zeroize();

    let mut enc_key = [0u8; 32];
    enc_key.copy_from_slice(&enc_key_vec);

    let mut sealed_map: std::collections::HashMap<String, SealedRecord> =
        std::collections::HashMap::new();

    let fingerprint = blake3::hash(&enc_key).to_hex().to_string();
    let now = now_millis();

    for (key_type, key_value) in keys {
        let aad = format!("{}:{}", account, key_type);
        let ciphertext = cipher::encrypt_string(&enc_key, key_value, Some(aad.as_bytes()))?;

        sealed_map.insert(
            key_type.clone(),
            SealedRecord {
                version: 1,
                ciphertext,
                aad_account: aad,
                key_fingerprint: fingerprint.clone(),
                created_at: now,
            },
        );
    }

    enc_key.zeroize();

    serde_json::to_string(&sealed_map)
        .map_err(|e| VaultError::SerializationError(e.to_string()))
}

/// Unseal multiple key-value pairs from a JSON string produced by `seal_keys`.
pub fn unseal_keys(
    pin: &[u8],
    salt: &[u8],
    sealed_json: &str,
    params: &KdfParams,
) -> Result<std::collections::HashMap<String, String>, VaultError> {
    let sealed_map: std::collections::HashMap<String, SealedRecord> =
        serde_json::from_str(sealed_json)
            .map_err(|e| VaultError::SerializationError(e.to_string()))?;

    // Derive encryption key once
    let mut master = derive_master_key(pin, salt, params)?;
    let enc_key_vec = derive_subkey(&master, PURPOSE_ENCRYPT, 32)?;
    master.zeroize();

    let mut enc_key = [0u8; 32];
    enc_key.copy_from_slice(&enc_key_vec);

    let mut result = std::collections::HashMap::new();

    for (key_type, record) in &sealed_map {
        let plaintext = cipher::decrypt_string(
            &enc_key,
            &record.ciphertext,
            Some(record.aad_account.as_bytes()),
        )?;
        result.insert(key_type.clone(), plaintext);
    }

    enc_key.zeroize();
    Ok(result)
}

/// Derive a session encryption key from PIN (for in-memory AES-GCM encryption).
///
/// This replaces the randomly-generated `_sessionCryptoKey` with a
/// deterministically derived key, so re-entering the PIN can reconstruct
/// the same session key without re-reading the vault.
///
/// Returns 32 raw bytes (suitable for importing as AES-GCM or ChaCha20 key).
pub fn derive_session_key(
    pin: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<Vec<u8>, VaultError> {
    let mut master = derive_master_key(pin, salt, params)?;
    let session_key = derive_subkey(&master, PURPOSE_SESSION, 32)?;
    master.zeroize();
    Ok(session_key)
}

fn now_millis() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now() as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> KdfParams {
        KdfParams {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
            key_length: 32,
        }
    }

    #[test]
    fn test_seal_unseal() {
        let params = test_params();
        let pin = b"123456";
        let salt = b"0123456789abcdef0123456789abcdef";
        let account = "alice";
        let secret = b"5JExamplePrivateKeyWIF";

        let sealed = seal(pin, salt, account, secret, &params).unwrap();
        let unsealed = unseal(pin, salt, &sealed, &params).unwrap();
        assert_eq!(unsealed, "5JExamplePrivateKeyWIF");
    }

    #[test]
    fn test_wrong_pin_fails() {
        let params = test_params();
        let salt = b"0123456789abcdef0123456789abcdef";
        let sealed = seal(b"123456", salt, "alice", b"secret", &params).unwrap();
        assert!(unseal(b"654321", salt, &sealed, &params).is_err());
    }

    #[test]
    fn test_wrong_account_fails() {
        let params = test_params();
        let pin = b"123456";
        let salt = b"0123456789abcdef0123456789abcdef";
        let sealed = seal(pin, salt, "alice", b"secret", &params).unwrap();

        // Tamper with the AAD account
        let mut tampered = sealed.clone();
        tampered.aad_account = "bob".to_string();
        assert!(unseal(pin, salt, &tampered, &params).is_err());
    }

    #[test]
    fn test_seal_unseal_keys() {
        let params = test_params();
        let pin = b"123456";
        let salt = b"0123456789abcdef0123456789abcdef";

        let mut keys = std::collections::HashMap::new();
        keys.insert("posting".to_string(), "5JPost...".to_string());
        keys.insert("active".to_string(), "5JActive...".to_string());
        keys.insert("memo".to_string(), "5JMemo...".to_string());

        let sealed_json = seal_keys(pin, salt, "alice", &keys, &params).unwrap();
        let unsealed = unseal_keys(pin, salt, &sealed_json, &params).unwrap();

        assert_eq!(unsealed.get("posting").unwrap(), "5JPost...");
        assert_eq!(unsealed.get("active").unwrap(), "5JActive...");
        assert_eq!(unsealed.get("memo").unwrap(), "5JMemo...");
    }
}
