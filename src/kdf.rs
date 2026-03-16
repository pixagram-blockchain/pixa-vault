use argon2::{self, Argon2, Algorithm, Version, Params};
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::Zeroize;

use crate::error::VaultError;

/// Argon2id parameters tuned for browser WASM with 6-char PINs.
///
/// Why these values matter for short PINs:
///
/// PBKDF2 (current): 1M iterations SHA-512
///   → ~0.5s CPU, but a single RTX 4090 can test ~500K pins/sec
///   → Full 6-char alphanumeric space (2.18B) cracked in ~72 minutes
///
/// Argon2id (default: 19 MiB, t=2):
///   → ~0.8s in WASM, GPU needs 19 MiB per parallel lane
///   → RTX 4090 (24GB): max ~1260 parallel attempts = ~1260 pins/sec
///   → Full 6-char alphanumeric space: ~20 DAYS (vs 72 min for PBKDF2)
///   → With numeric-only PIN (1M combos): ~13 minutes (vs <1 sec for PBKDF2)
///
/// autoTuneParams() will bump to 46 MiB if the device supports it:
///   → RTX 4090: ~520 parallel attempts → ~48 DAYS for alphanumeric
///
/// The default 19 MiB is the OWASP minimum recommendation for Argon2id
/// and works reliably within WASM linear memory limits.
#[derive(Debug, Clone)]
pub struct KdfParams {
    /// Memory cost in KiB (default: 65536 = 64 MiB)
    pub memory_kib: u32,
    /// Time cost / iterations (default: 3)
    pub iterations: u32,
    /// Parallelism (default: 1 for WASM single-thread)
    pub parallelism: u32,
    /// Output key length in bytes (default: 32 = 256 bits)
    pub key_length: usize,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: 19456, // 19 MiB — OWASP minimum, safe for WASM
            iterations: 2,
            parallelism: 1,
            key_length: 32,
        }
    }
}

impl KdfParams {
    /// Low-memory profile for constrained devices (9 MiB, 3 iterations)
    pub fn low_memory() -> Self {
        Self {
            memory_kib: 9216, // 9 MiB
            iterations: 3,
            parallelism: 1,
            key_length: 32,
        }
    }

    /// High-security profile (46 MiB, 2 iterations)
    pub fn high_security() -> Self {
        Self {
            memory_kib: 46080, // 45 MiB
            iterations: 2,
            parallelism: 1,
            key_length: 32,
        }
    }
}

/// Derive a master key from PIN + salt using Argon2id.
///
/// Returns a 32-byte key suitable for use with ChaCha20-Poly1305.
/// The key is NOT directly used — it is further derived via HKDF
/// for domain separation (encryption vs verification).
pub fn derive_master_key(
    pin: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<Vec<u8>, VaultError> {
    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(params.key_length),
    )
    .map_err(|e| VaultError::KdfFailed(format!("Invalid Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut output = vec![0u8; params.key_length];
    argon2
        .hash_password_into(pin, salt, &mut output)
        .map_err(|e| VaultError::KdfFailed(format!("Argon2id failed: {}", e)))?;

    Ok(output)
}

/// Derive a sub-key from the master key using HKDF-SHA512.
///
/// Purpose strings provide domain separation so that the encryption key
/// and the verification hash can never collide, even from the same master.
///
/// Defined purposes:
///   - b"pixa-vault-encrypt-v1"  → encryption key for ChaCha20-Poly1305
///   - b"pixa-vault-verify-v1"   → PIN verification hash
///   - b"pixa-vault-session-v1"  → session encryption key
pub fn derive_subkey(
    master_key: &[u8],
    purpose: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, VaultError> {
    let hkdf = Hkdf::<Sha512>::new(None, master_key);
    let mut output = vec![0u8; output_len];
    hkdf.expand(purpose, &mut output)
        .map_err(|_| VaultError::HkdfExpandFailed)?;
    Ok(output)
}

/// Full derivation pipeline: PIN → Argon2id → HKDF → sub-key.
/// The master key is zeroized after sub-key extraction.
pub fn derive_purpose_key(
    pin: &[u8],
    salt: &[u8],
    purpose: &[u8],
    params: &KdfParams,
) -> Result<Vec<u8>, VaultError> {
    let mut master = derive_master_key(pin, salt, params)?;
    let result = derive_subkey(&master, purpose, params.key_length);
    master.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_deterministic() {
        let params = KdfParams {
            memory_kib: 1024, // Small for tests
            iterations: 1,
            parallelism: 1,
            key_length: 32,
        };
        let pin = b"123456";
        let salt = b"0123456789abcdef0123456789abcdef";

        let key1 = derive_master_key(pin, salt, &params).unwrap();
        let key2 = derive_master_key(pin, salt, &params).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_different_pins_different_keys() {
        let params = KdfParams {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
            key_length: 32,
        };
        let salt = b"0123456789abcdef0123456789abcdef";

        let key1 = derive_master_key(b"123456", salt, &params).unwrap();
        let key2 = derive_master_key(b"654321", salt, &params).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_domain_separation() {
        let params = KdfParams {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
            key_length: 32,
        };
        let pin = b"123456";
        let salt = b"0123456789abcdef0123456789abcdef";

        let enc_key = derive_purpose_key(pin, salt, b"pixa-vault-encrypt-v1", &params).unwrap();
        let ver_key = derive_purpose_key(pin, salt, b"pixa-vault-verify-v1", &params).unwrap();
        assert_ne!(enc_key, ver_key);
    }
}
