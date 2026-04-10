//! Constants matching oxide-shared for crypto compatibility.
//!
//! These values MUST match /home/gnom/prj/oxide/shared/src/constants.rs

pub const AES_KEY_SIZE: usize = 32;           // AES-256
pub const NONCE_SIZE: usize = 12;             // GCM standard
pub const DIRECTION_PREFIX_SIZE: usize = 4;
pub const PBKDF2_ITERATIONS: u32 = 600_000;   // OWASP 2023
