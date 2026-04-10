//! Sandbox Detection Module
//!
//! Techniques:
//! - Process count (sandboxes often have few processes)
//! - Username patterns (sandbox, malware, test, etc.)
//! - Known sandbox files/directories
//! - Window count (sandboxes may have few windows)
//!
//! Detection artifacts:
//! - Sysmon: Process enumeration
//! - Sysmon: File/directory access

use super::AnalysisEnvironment;

/// Minimum expected process count on a real system
const MIN_PROCESS_COUNT: usize = 50;

/// Suspicious usernames common in sandboxes
const SANDBOX_USERNAMES: &[&str] = &[
    "sandbox",
    "malware",
    "virus",
    "sample",
    "test",
    "vmware",
    "user",
    "admin",
    "administrator",
    "john",
    "peter",
    "currentuser",
    "cuckoo",
    "analysis",
];

/// Known sandbox file indicators
#[cfg(windows)]
const SANDBOX_FILES: &[&str] = &[
    r"C:\analysis",
    r"C:\sandbox",
    r"C:\sample",
    r"C:\virus",
    r"C:\malware",
    r"C:\insidetm",
    r"C:\windows\system32\drivers\vmmouse.sys",
    r"C:\windows\system32\drivers\vmhgfs.sys",
    r"C:\windows\system32\drivers\vboxmouse.sys",
    r"C:\windows\system32\drivers\vboxguest.sys",
];

#[cfg(unix)]
const SANDBOX_FILES: &[&str] = &[
    "/tmp/cuckoo-analysis",
    "/tmp/malware",
    "/tmp/analysis",
];

/// Run all sandbox detection checks.
pub fn check() -> Result<(), AnalysisEnvironment> {
    // Process count check
    let proc_count = get_process_count();
    if proc_count < MIN_PROCESS_COUNT {
        return Err(AnalysisEnvironment::Sandbox(
            format!("Low process count: {}", proc_count)
        ));
    }

    // Username check
    if let Some(username) = get_username() {
        let username_lower = username.to_lowercase();
        for pattern in SANDBOX_USERNAMES {
            if username_lower.contains(pattern) {
                return Err(AnalysisEnvironment::Sandbox(
                    format!("Suspicious username: {}", username)
                ));
            }
        }
    }

    // File check
    if let Some(path) = check_sandbox_files() {
        return Err(AnalysisEnvironment::Sandbox(
            format!("Sandbox file: {}", path)
        ));
    }

    // Window count (Windows only)
    #[cfg(windows)]
    {
        let window_count = get_window_count();
        if window_count < 10 {
            return Err(AnalysisEnvironment::Sandbox(
                format!("Low window count: {}", window_count)
            ));
        }
    }

    Ok(())
}

/// Get running process count.
fn get_process_count() -> usize {
    #[cfg(windows)]
    {
        get_process_count_windows()
    }
    #[cfg(unix)]
    {
        get_process_count_unix()
    }
}

#[cfg(windows)]
fn get_process_count_windows() -> usize {
    use windows::Win32::System::Diagnostics::ToolHelp::*;
    use windows::Win32::Foundation::INVALID_HANDLE_VALUE;

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return 0;
        }

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let mut count = 0;
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            count += 1;
            while Process32NextW(snapshot, &mut entry).is_ok() {
                count += 1;
            }
        }

        windows::Win32::Foundation::CloseHandle(snapshot);
        count
    }
}

#[cfg(unix)]
fn get_process_count_unix() -> usize {
    use std::fs;

    if let Ok(entries) = fs::read_dir("/proc") {
        entries
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_str()
                    .map(|s| s.chars().all(|c| c.is_ascii_digit()))
                    .unwrap_or(false)
            })
            .count()
    } else {
        0
    }
}

/// Get current username.
fn get_username() -> Option<String> {
    #[cfg(windows)]
    {
        std::env::var("USERNAME").ok()
    }
    #[cfg(unix)]
    {
        std::env::var("USER").ok()
    }
}

/// Check for known sandbox files.
fn check_sandbox_files() -> Option<String> {
    use std::path::Path;

    for path_str in SANDBOX_FILES {
        if Path::new(path_str).exists() {
            return Some(path_str.to_string());
        }
    }
    None
}

/// Get visible window count (Windows only).
#[cfg(windows)]
fn get_window_count() -> usize {
    use windows::Win32::UI::WindowsAndMessaging::*;
    use windows::Win32::Foundation::{BOOL, HWND, LPARAM};

    static mut WINDOW_COUNT: usize = 0;

    unsafe extern "system" fn enum_callback(_hwnd: HWND, _lparam: LPARAM) -> BOOL {
        WINDOW_COUNT += 1;
        BOOL(1)  // Continue enumeration
    }

    unsafe {
        WINDOW_COUNT = 0;
        EnumWindows(Some(enum_callback), LPARAM(0));
        WINDOW_COUNT
    }
}
