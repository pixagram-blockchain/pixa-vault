use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use zeroize::Zeroize;

use crate::error::VaultError;

/// Nonce size for ChaCha20-Poly1305 (96 bits / 12 bytes)
pub const NONCE_SIZE: usize = 12;

/// Auth tag size (128 bits / 16 bytes, appended by the AEAD)
pub const TAG_SIZE: usize = 16;

/// Encrypt plaintext using ChaCha20-Poly1305.
///
/// Returns: nonce (12 bytes) || ciphertext+tag
///
/// The nonce is generated from a CSPRNG and prepended to the output
/// so the caller doesn't need to manage it separately.
///
/// Optional `aad` (Additional Authenticated Data) binds the ciphertext
/// to a context (e.g., account name) so it can't be moved between records.
pub fn encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, VaultError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| VaultError::EncryptionFailed(format!("Invalid key: {}", e)))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = if let Some(aad_data) = aad {
        cipher
            .encrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad: aad_data,
                },
            )
            .map_err(|e| VaultError::EncryptionFailed(format!("ChaCha20-Poly1305 encrypt: {}", e)))?
    } else {
        cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| VaultError::EncryptionFailed(format!("ChaCha20-Poly1305 encrypt: {}", e)))?
    };

    // Prepend nonce to ciphertext: [nonce(12) | ciphertext+tag]
    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypt a blob produced by `encrypt()`.
///
/// Input format: nonce (12 bytes) || ciphertext+tag
///
/// Returns plaintext on success, `DecryptionFailed` on wrong key or tampering.
pub fn decrypt(
    key: &[u8; 32],
    data: &[u8],
    aad: Option<&[u8]>,
) -> Result<Vec<u8>, VaultError> {
    if data.len() < NONCE_SIZE + TAG_SIZE {
        return Err(VaultError::InvalidCiphertext);
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|e| VaultError::EncryptionFailed(format!("Invalid key: {}", e)))?;

    let plaintext = if let Some(aad_data) = aad {
        cipher
            .decrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: ciphertext,
                    aad: aad_data,
                },
            )
            .map_err(|_| VaultError::DecryptionFailed)?
    } else {
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| VaultError::DecryptionFailed)?
    };

    Ok(plaintext)
}

/// Encrypt a UTF-8 string, returning base64-encoded output for JSON storage.
pub fn encrypt_string(
    key: &[u8; 32],
    plaintext: &str,
    aad: Option<&[u8]>,
) -> Result<String, VaultError> {
    use base64::Engine;
    let encrypted = encrypt(key, plaintext.as_bytes(), aad)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(&encrypted))
}

/// Decrypt a base64-encoded blob back to a UTF-8 string.
pub fn decrypt_string(
    key: &[u8; 32],
    b64_data: &str,
    aad: Option<&[u8]>,
) -> Result<String, VaultError> {
    use base64::Engine;
    let data = base64::engine::general_purpose::STANDARD
        .decode(b64_data)
        .map_err(|_| VaultError::InvalidCiphertext)?;
    let mut plaintext = decrypt(key, &data, aad)?;
    let result = String::from_utf8(plaintext.clone())
        .map_err(|_| VaultError::DecryptionFailed)?;
    plaintext.zeroize();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"5JExample...WIF-private-key";
        let encrypted = encrypt(&key, plaintext, None).unwrap();
        let decrypted = decrypt(&key, &encrypted, None).unwrap();
        assert_eq!(plaintext.as_slice(), &decrypted);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [42u8; 32];
        let key2 = [99u8; 32];
        let encrypted = encrypt(&key1, b"secret", None).unwrap();
        assert!(decrypt(&key2, &encrypted, None).is_err());
    }

    #[test]
    fn test_aad_binding() {
        let key = [42u8; 32];
        let plaintext = b"secret";
        let encrypted = encrypt(&key, plaintext, Some(b"alice")).unwrap();
        // Correct AAD works
        assert!(decrypt(&key, &encrypted, Some(b"alice")).is_ok());
        // Wrong AAD fails (ciphertext bound to "alice", not "bob")
        assert!(decrypt(&key, &encrypted, Some(b"bob")).is_err());
    }

    #[test]
    fn test_string_roundtrip() {
        let key = [42u8; 32];
        let encrypted = encrypt_string(&key, "hello vault", None).unwrap();
        let decrypted = decrypt_string(&key, &encrypted, None).unwrap();
        assert_eq!(decrypted, "hello vault");
    }

    #[test]
    fn test_tamper_detection() {
        let key = [42u8; 32];
        let mut encrypted = encrypt(&key, b"secret", None).unwrap();
        // Flip a bit in the ciphertext
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x01;
        assert!(decrypt(&key, &encrypted, None).is_err());
    }
}
