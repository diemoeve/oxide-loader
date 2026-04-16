//! Undocumented NT API declarations for Waiting Thread Hijacking (WTH) and process hollowing.
#![allow(non_snake_case, dead_code)]

use windows_sys::Win32::Foundation::HANDLE;

pub const STATUS_SUCCESS: i32 = 0;
pub const STATUS_NO_MORE_ENTRIES: i32 = 0x8000001Au32 as i32;
pub const THREAD_GET_CONTEXT: u32 = 0x0008;
pub const THREAD_QUERY_INFORMATION: u32 = 0x0040;
pub const PROCESS_VM_OPERATION: u32 = 0x0008;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_VM_WRITE: u32 = 0x0020;
pub const PROCESS_CREATE_THREAD: u32 = 0x0002;
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;

#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: HANDLE,
    pub ObjectName: *const core::ffi::c_void,
    pub Attributes: u32,
    pub SecurityDescriptor: *const core::ffi::c_void,
    pub SecurityQualityOfService: *const core::ffi::c_void,
}

impl OBJECT_ATTRIBUTES {
    pub fn empty() -> Self {
        Self {
            Length: core::mem::size_of::<Self>() as u32,
            RootDirectory: core::ptr::null_mut(),
            ObjectName: core::ptr::null(),
            Attributes: 0,
            SecurityDescriptor: core::ptr::null(),
            SecurityQualityOfService: core::ptr::null(),
        }
    }
}

#[repr(C)]
pub struct CLIENT_ID {
    pub UniqueProcess: HANDLE,
    pub UniqueThread: HANDLE,
}

extern "system" {
    pub fn NtGetNextThread(
        ProcessHandle: HANDLE,
        ThreadHandle: HANDLE,
        DesiredAccess: u32,
        HandleAttributes: u32,
        Flags: u32,
        NewThreadHandle: *mut HANDLE,
    ) -> i32;

    pub fn NtOpenProcess(
        ProcessHandle: *mut HANDLE,
        DesiredAccess: u32,
        ObjectAttributes: *const OBJECT_ATTRIBUTES,
        ClientId: *const CLIENT_ID,
    ) -> i32;

    pub fn ZwUnmapViewOfSection(
        ProcessHandle: HANDLE,
        BaseAddress: *mut core::ffi::c_void,
    ) -> i32;
}
