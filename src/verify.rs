use zeroize::Zeroize;

use crate::error::VaultError;
use crate::kdf::{derive_master_key, derive_subkey, KdfParams};

/// Purpose string for PIN verification sub-key.
/// Domain-separated from the encryption key via HKDF.
pub const PURPOSE_VERIFY: &[u8] = b"pixa-vault-verify-v1";

/// Purpose string for the encryption sub-key.
pub const PURPOSE_ENCRYPT: &[u8] = b"pixa-vault-encrypt-v1";

/// Purpose string for session encryption sub-key.
pub const PURPOSE_SESSION: &[u8] = b"pixa-vault-session-v1";

/// Generate a PIN verification hash.
///
/// Pipeline: PIN → Argon2id(salt) → master_key → HKDF("verify") → verify_key → BLAKE3(verify_key)
///
/// The final BLAKE3 hash is safe to store in plaintext (IndexedDB).
/// An attacker with the hash gains no advantage — they'd still need to
/// reverse Argon2id to find the master key, and the HKDF domain separation
/// ensures the encryption key can't be derived from the verify hash.
///
/// Returns hex-encoded BLAKE3 hash (64 chars).
pub fn generate_pin_verify_hash(
    pin: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<String, VaultError> {
    let mut master = derive_master_key(pin, salt, params)?;
    let mut verify_key = derive_subkey(&master, PURPOSE_VERIFY, 32)?;
    master.zeroize();

    let hash = blake3::hash(&verify_key);
    verify_key.zeroize();

    Ok(hash.to_hex().to_string())
}

/// Verify a PIN against a stored verification hash.
///
/// Returns `true` if the PIN produces the same hash, `false` otherwise.
/// Timing: dominated by Argon2id (~1s), so timing side-channels are irrelevant.
pub fn verify_pin(
    pin: &[u8],
    salt: &[u8],
    stored_hash: &str,
    params: &KdfParams,
) -> Result<bool, VaultError> {
    let computed = generate_pin_verify_hash(pin, salt, params)?;
    // Constant-time comparison to be thorough, even though Argon2id dominates timing
    Ok(constant_time_eq(computed.as_bytes(), stored_hash.as_bytes()))
}

/// Constant-time byte comparison (prevents timing attacks on the hash comparison).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_correct_pin() {
        let params = KdfParams {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
            key_length: 32,
        };
        let pin = b"123456";
        let salt = b"0123456789abcdef0123456789abcdef";

        let hash = generate_pin_verify_hash(pin, salt, &params).unwrap();
        assert!(verify_pin(pin, salt, &hash, &params).unwrap());
    }

    #[test]
    fn test_verify_wrong_pin() {
        let params = KdfParams {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
            key_length: 32,
        };
        let salt = b"0123456789abcdef0123456789abcdef";

        let hash = generate_pin_verify_hash(b"123456", salt, &params).unwrap();
        assert!(!verify_pin(b"654321", salt, &hash, &params).unwrap());
    }

    #[test]
    fn test_deterministic_hash() {
        let params = KdfParams {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
            key_length: 32,
        };
        let pin = b"abc123";
        let salt = b"fedcba9876543210fedcba9876543210";

        let h1 = generate_pin_verify_hash(pin, salt, &params).unwrap();
        let h2 = generate_pin_verify_hash(pin, salt, &params).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // BLAKE3 hex = 64 chars
    }
}
