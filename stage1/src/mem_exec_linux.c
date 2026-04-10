/*
 * Memory Execution Implementation - Linux
 *
 * Uses mmap with PROT_READ|PROT_WRITE|PROT_EXEC for RWX allocation.
 * This is a common technique detectable via /proc/pid/maps analysis.
 *
 * Detection artifact: Anonymous RWX mapping
 * Memory forensics: ELF in unbacked memory region
 */

#ifdef __linux__

#include "mem_exec.h"
#include <sys/mman.h>
#include <string.h>

int mem_run(const uint8_t *code, size_t len)
{
    if (!code || len == 0) {
        return -1;
    }

    /*
     * Allocate anonymous RWX memory.
     * MAP_ANONYMOUS + PROT_EXEC is suspicious and detectable.
     */
    void *mem = mmap(
        NULL,
        len,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0);

    if (mem == MAP_FAILED) {
        return -1;
    }

    /* Copy code to executable memory */
    memcpy(mem, code, len);

    /* Cast to function pointer and call */
    void (*entry)(void) = (void (*)(void))mem;
    entry();

    /* If we return, unmap and succeed */
    munmap(mem, len);
    return 0;
}

#endif /* __linux__ */
