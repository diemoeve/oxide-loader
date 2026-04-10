//! Crypto module - AES-256-GCM decryption for implant payload.

use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, KeyInit}};
use crate::constants::*;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("data too short for decryption")]
    TooShort,
    #[error("decryption failed")]
    DecryptFailed,
}

/// Decrypt implant payload.
pub fn decrypt_payload(psk: &str, salt: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < NONCE_SIZE + 16 {
        return Err(CryptoError::TooShort);
    }

    let mut key = [0u8; AES_KEY_SIZE];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
        psk.as_bytes(),
        salt,
        PBKDF2_ITERATIONS,
        &mut key,
    );

    let cipher = Aes256Gcm::new_from_slice(&key)
        .expect("valid key size");

    let nonce = Nonce::from_slice(&data[..NONCE_SIZE]);
    let plaintext = cipher
        .decrypt(nonce, &data[NONCE_SIZE..])
        .map_err(|_| CryptoError::DecryptFailed)?;

    Ok(plaintext)
}
