use thiserror::Error;

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("PIN too short: minimum {min} characters required")]
    PinTooShort { min: usize },

    #[error("Key derivation failed: {0}")]
    KdfFailed(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: invalid PIN or corrupted data")]
    DecryptionFailed,

    #[error("PIN verification failed")]
    PinVerifyFailed,

    #[error("Invalid salt: expected {expected} hex chars, got {got}")]
    InvalidSalt { expected: usize, got: usize },

    #[error("Invalid ciphertext format")]
    InvalidCiphertext,

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("HKDF expand failed")]
    HkdfExpandFailed,
}

impl From<VaultError> for wasm_bindgen::JsValue {
    fn from(e: VaultError) -> Self {
        wasm_bindgen::JsValue::from_str(&e.to_string())
    }
}
