//! Debugger Detection Module
//!
//! Techniques:
//! - IsDebuggerPresent API (Windows)
//! - PEB.BeingDebugged field (Windows)
//! - NtQueryInformationProcess (Windows)
//! - /proc/self/status TracerPid (Linux)
//!
//! Detection artifacts:
//! - ETW: Debug API calls
//! - Sysmon: Process access for NtQueryInformationProcess

use super::AnalysisEnvironment;

/// Run all debugger detection checks.
pub fn check() -> Result<(), AnalysisEnvironment> {
    #[cfg(windows)]
    {
        if check_is_debugger_present() {
            return Err(AnalysisEnvironment::Debugger("IsDebuggerPresent".into()));
        }

        if check_peb_being_debugged() {
            return Err(AnalysisEnvironment::Debugger("PEB.BeingDebugged".into()));
        }

        if check_nt_query_debug_port() {
            return Err(AnalysisEnvironment::Debugger("DebugPort".into()));
        }
    }

    #[cfg(unix)]
    {
        if check_tracer_pid() {
            return Err(AnalysisEnvironment::Debugger("TracerPid".into()));
        }

        if check_ptrace_self() {
            return Err(AnalysisEnvironment::Debugger("ptrace".into()));
        }
    }

    Ok(())
}

/// Windows: Call IsDebuggerPresent API.
#[cfg(windows)]
fn check_is_debugger_present() -> bool {
    use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
    unsafe { IsDebuggerPresent().as_bool() }
}

/// Windows: Read PEB.BeingDebugged directly.
#[cfg(windows)]
fn check_peb_being_debugged() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let being_debugged: u32;
        unsafe {
            // PEB is at gs:[0x60], BeingDebugged is at offset 0x2
            std::arch::asm!(
                "mov rax, gs:[0x60]",
                "movzx {0:e}, byte ptr [rax + 0x2]",
                out(reg) being_debugged,
                out("rax") _,
            );
        }
        being_debugged != 0
    }
    #[cfg(target_arch = "x86")]
    {
        let being_debugged: u32;
        unsafe {
            // PEB is at fs:[0x30], BeingDebugged is at offset 0x2
            std::arch::asm!(
                "mov eax, fs:[0x30]",
                "movzx {0:e}, byte ptr [eax + 0x2]",
                out(reg) being_debugged,
                out("eax") _,
            );
        }
        being_debugged != 0
    }
}

/// Windows: Check debug port via NtQueryInformationProcess.
#[cfg(windows)]
fn check_nt_query_debug_port() -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Threading::GetCurrentProcess;

    // ProcessDebugPort = 7
    const PROCESS_DEBUG_PORT: u32 = 7;

    #[link(name = "ntdll")]
    extern "system" {
        fn NtQueryInformationProcess(
            ProcessHandle: HANDLE,
            ProcessInformationClass: u32,
            ProcessInformation: *mut std::ffi::c_void,
            ProcessInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> i32;
    }

    unsafe {
        let handle = GetCurrentProcess();
        let mut debug_port: isize = 0;
        let mut return_length: u32 = 0;

        let status = NtQueryInformationProcess(
            handle,
            PROCESS_DEBUG_PORT,
            &mut debug_port as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<isize>() as u32,
            &mut return_length,
        );

        // STATUS_SUCCESS = 0
        if status == 0 && debug_port != 0 {
            return true;
        }
    }

    false
}

/// Linux: Check /proc/self/status for TracerPid.
#[cfg(unix)]
fn check_tracer_pid() -> bool {
    use std::fs;

    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("TracerPid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(pid) = parts[1].parse::<u32>() {
                        return pid != 0;
                    }
                }
            }
        }
    }
    false
}

/// Linux: Try to ptrace self (will fail if already being traced).
#[cfg(unix)]
fn check_ptrace_self() -> bool {
    use std::os::raw::c_long;

    #[cfg(target_os = "linux")]
    {
        extern "C" {
            fn ptrace(request: c_long, pid: i32, addr: *mut std::ffi::c_void, data: *mut std::ffi::c_void) -> c_long;
        }

        const PTRACE_TRACEME: c_long = 0;

        unsafe {
            // If we're being traced, ptrace(TRACEME) will fail
            let result = ptrace(PTRACE_TRACEME, 0, std::ptr::null_mut(), std::ptr::null_mut());
            if result == -1 {
                return true;  // Already being traced
            }
            // Detach if we successfully attached
            // PTRACE_DETACH = 17 on Linux
            const PTRACE_DETACH: c_long = 17;
            ptrace(PTRACE_DETACH, 0, std::ptr::null_mut(), std::ptr::null_mut());
        }
    }

    false
}
