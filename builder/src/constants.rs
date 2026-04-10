//! Constants matching oxide-shared for crypto compatibility.

pub const AES_KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const PBKDF2_ITERATIONS: u32 = 600_000;
pub const SALT_SIZE: usize = 32;

/// Stage 1 config magic value
pub const STAGE1_MAGIC: u32 = 0x4F584944;  // "OXID"
