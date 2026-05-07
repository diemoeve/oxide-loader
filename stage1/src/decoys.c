#ifdef _WIN32

#include "decoys.h"

#include <windows.h>

/*
 * Tier A — pure decoys. The linker resolves these names against
 * kernel32 because (a) `used` blocks compiler DCE so the array survives
 * to the linker, and (b) the array is anchored from decoys_run() below,
 * which keeps its (-fdata-sections) section through --gc-sections. No
 * call site for any Tier A entry is ever emitted in stage1's .text;
 * each address simply lives as a relocation against a kernel32 import.
 *
 * (PE-COFF on MinGW does not honour __attribute__((retain)) /
 * SHF_GNU_RETAIN — that is ELF-only — so reachability is the
 * mechanism here, not section flags.)
 */
__attribute__((used))
static void *const decoy_a_refs[] = {
    (void *)GetCommandLineA,
    (void *)GetUserDefaultLocaleName,
    (void *)HeapAlloc,
    (void *)HeapFree,
    (void *)GetSystemTimeAsFileTime,
    (void *)GetCurrentThreadId,
    (void *)GetModuleHandleA,
};

/* Sink — every Tier B/C result is XORed in so the optimiser cannot
 * prove the calls dead. Read once via decoys_run's return value. */
static volatile uint32_t g_decoy_sink;

uint32_t decoys_run(void)
{
    /* Tier B — light touch. Routine init shape in disassembly. */
    DWORD ticks = GetTickCount();
    DWORD pid   = GetCurrentProcessId();
    g_decoy_sink ^= ((uint32_t)ticks ^ (uint32_t)pid);

    /* Tier C — CRT-utility shape. */
    SetUnhandledExceptionFilter(NULL);

    static const WCHAR k_dummy[] = L"x";
    char mb[4] = {0};
    int  conv = WideCharToMultiByte(CP_ACP, 0, k_dummy, 1,
                                    mb, (int)sizeof(mb), NULL, NULL);
    g_decoy_sink ^= (uint32_t)conv;

    DWORD err = GetLastError();
    g_decoy_sink ^= (uint32_t)err;

    /* Anchor — read every Tier A entry so the array's section is
     * reachable from used code. Linker keeps it under --gc-sections,
     * resolving each pointer against a kernel32 IAT slot. The reads
     * never invoke; the addresses are XORed into the sink. */
    for (size_t i = 0;
         i < sizeof(decoy_a_refs) / sizeof(decoy_a_refs[0]);
         i++) {
        g_decoy_sink ^= (uint32_t)(uintptr_t)decoy_a_refs[i];
    }

    return g_decoy_sink;
}

#endif /* _WIN32 */
