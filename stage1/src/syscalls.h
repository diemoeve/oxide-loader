/*
 * Indirect syscalls via Hell's Hall (S34).
 *
 * Resolves the System Service Number (SSN) for each target Nt* function by
 * reading the first bytes of its ntdll stub at runtime (Hell's Gate path)
 * and cross-validates against a FreshyCalls-style VA-sorted index of all
 * Nt and Zw exports (RecycledGate pattern). Locates a `syscall; ret` gadget
 * inside ntdll's own .text section and caches the pointer globally. Every
 * target Nt* is invoked by a naked asm trampoline that loads the cached
 * SSN into EAX, performs the `mov r10, rcx` the x64 syscall ABI requires,
 * and `jmp`s to the ntdll-resident gadget. Execution lands in the kernel
 * with RIP inside ntdll -- not inside stage1's own .text. This defeats
 * userland inline hooks and the "syscall from outside ntdll" module-
 * boundary check. It does not defeat full call-stack unwinding.
 *
 * Detection artifacts: djb2 hashes for NtAllocateVirtualMemory /
 * NtProtectVirtualMemory in .rodata; prologue-scan loop reading `4C 8B D1`
 * bytes; gadget-scan loop matching `0F 05 C3`. Paired YARA:
 * detection/yara/stage1_hellshall_ssn_resolve.yar.
 *
 * Windows x86_64 only.
 */

#ifndef SYSCALLS_H
#define SYSCALLS_H

#ifdef _WIN32

#include <stdint.h>
#include <stddef.h>
#include <windows.h>

/*
 * Populate the SSN cache and gadget pointer. Must be called after
 * peb_find_module(H_NTDLL_DLL) succeeds, and before any hh_* wrapper is
 * invoked. Returns 0 on success.
 *
 * Return codes:
 *   0 = success
 *   1 = ntdll not found in PEB
 *   2 = NtAllocateVirtualMemory export not found
 *   3 = NtProtectVirtualMemory export not found
 *   4 = SSN resolve disagreement (Hell's Gate vs FreshyCalls)
 *   5 = syscall;ret gadget not located in ntdll .text
 */
int syscalls_init(void);

/*
 * NtAllocateVirtualMemory wrapper. Signature matches the ntdll export
 * exactly; caller uses standard Win64 ABI.
 */
extern NTSTATUS NTAPI hh_NtAllocateVirtualMemory(
    HANDLE    ProcessHandle,
    PVOID    *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect);

/*
 * NtProtectVirtualMemory wrapper.
 */
extern NTSTATUS NTAPI hh_NtProtectVirtualMemory(
    HANDLE   ProcessHandle,
    PVOID   *BaseAddress,
    PSIZE_T  NumberOfBytesToProtect,
    ULONG    NewAccessProtection,
    PULONG   OldAccessProtection);

/*
 * Exposed for test harness: the two SSN slots and the gadget pointer.
 * Populated by syscalls_init. Globals so the asm trampolines can reference
 * them rip-relative.
 */
extern uint32_t g_ssn_nt_alloc;
extern uint32_t g_ssn_nt_protect;
extern void    *g_syscall_gadget;

#endif /* _WIN32 */
#endif /* SYSCALLS_H */
