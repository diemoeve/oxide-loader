//! Crypto module for payload encryption.
//!
//! Uses AES-256-GCM with PBKDF2 key derivation, compatible with oxide-shared.

use aes_gcm::{Aes256Gcm, Nonce, aead::{Aead, KeyInit}};
use rand::{RngCore, thread_rng};
use crate::constants::*;

/// Generate random salt.
pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    thread_rng().fill_bytes(&mut salt);
    salt
}

/// Generate random XOR key for Stage 1.
pub fn generate_xor_key(len: usize) -> Vec<u8> {
    let mut key = vec![0u8; len];
    thread_rng().fill_bytes(&mut key);
    key
}

/// Encrypt payload using AES-256-GCM with PBKDF2 key derivation.
///
/// Returns: [nonce (12 bytes)][ciphertext + tag]
pub fn encrypt_payload(psk: &str, salt: &[u8], plaintext: &[u8]) -> Vec<u8> {
    // Derive key
    let mut key = [0u8; AES_KEY_SIZE];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
        psk.as_bytes(),
        salt,
        PBKDF2_ITERATIONS,
        &mut key,
    );

    let cipher = Aes256Gcm::new_from_slice(&key)
        .expect("valid key size");

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .expect("encryption should not fail");

    // Prepend nonce
    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    output
}

/// XOR encrypt payload (for Stage 1 size constraints).
pub fn xor_encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    plaintext
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}
