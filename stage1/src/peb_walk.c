/*
 * PEB walker implementation — x86_64 Windows.
 *
 * Offsets (ABI-stable; see winternl.h for field names, Microsoft PE
 * documentation for layout). winternl.h obscures some fields behind
 * Reserved[N] arrays, so offsets are given explicitly here:
 *
 *   TEB + 0x60   = ProcessEnvironmentBlock            (winternl.h:101)
 *   PEB + 0x18   = Ldr (PPEB_LDR_DATA)                 (winternl.h:82)
 *   PEB_LDR_DATA + 0x20 = InMemoryOrderModuleList     (winternl.h:47)
 *   LDR_DATA_TABLE_ENTRY + 0x10 = InMemoryOrderLinks  (winternl.h:52)
 *   LDR_DATA_TABLE_ENTRY + 0x30 = DllBase              (winternl.h:54)
 *   LDR_DATA_TABLE_ENTRY + 0x58 = BaseDllName.Length  (after FullDllName@0x48)
 *   LDR_DATA_TABLE_ENTRY + 0x60 = BaseDllName.Buffer
 *
 * The BaseDllName field is not named in mingw winternl.h but lies
 * immediately after FullDllName (UNICODE_STRING, 16 bytes on x64).
 */

#ifdef _WIN32

#include "peb_walk.h"
#include "hash.h"

#include <windows.h>

#define TEB_PEB_OFFSET                0x60
#define PEB_LDR_OFFSET                0x18
#define LDR_INMEMORDER_LIST_OFFSET    0x20
#define ENTRY_INMEMORDER_LINKS_OFFSET 0x10
#define ENTRY_DLLBASE_OFFSET          0x30
#define ENTRY_BASEDLLNAME_LENGTH      0x58
#define ENTRY_BASEDLLNAME_BUFFER      0x60

typedef struct _LE {
    struct _LE *Flink;
    struct _LE *Blink;
} LE;

static inline void *get_peb(void) {
    void *peb;
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb));
    return peb;
}

void *peb_find_module(uint32_t name_hash) {
    unsigned char *peb = (unsigned char *)get_peb();
    if (!peb) return 0;

    unsigned char *ldr = *(unsigned char **)(peb + PEB_LDR_OFFSET);
    if (!ldr) return 0;

    LE *head = (LE *)(ldr + LDR_INMEMORDER_LIST_OFFSET);
    LE *cur = head->Flink;

    while (cur && cur != head) {
        unsigned char *entry = (unsigned char *)cur - ENTRY_INMEMORDER_LINKS_OFFSET;
        uint16_t name_len_bytes = *(uint16_t *)(entry + ENTRY_BASEDLLNAME_LENGTH);
        uint16_t *name_buf = *(uint16_t **)(entry + ENTRY_BASEDLLNAME_BUFFER);

        if (name_buf && name_len_bytes > 0) {
            size_t nchars = name_len_bytes / 2;
            if (djb2i_wide(name_buf, nchars) == name_hash) {
                return *(void **)(entry + ENTRY_DLLBASE_OFFSET);
            }
        }
        cur = cur->Flink;
    }
    return 0;
}

void *peb_find_export(void *dll_base, uint32_t fn_hash) {
    if (!dll_base) return 0;

    unsigned char *base = (unsigned char *)dll_base;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    IMAGE_DATA_DIRECTORY *exp_dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp_dir->VirtualAddress == 0 || exp_dir->Size == 0) return 0;

    IMAGE_EXPORT_DIRECTORY *exp =
        (IMAGE_EXPORT_DIRECTORY *)(base + exp_dir->VirtualAddress);

    uint32_t *names   = (uint32_t *)(base + exp->AddressOfNames);
    uint16_t *ords    = (uint16_t *)(base + exp->AddressOfNameOrdinals);
    uint32_t *funcs   = (uint32_t *)(base + exp->AddressOfFunctions);

    for (uint32_t i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (const char *)(base + names[i]);
        if (djb2i_ascii(name) == fn_hash) {
            uint32_t rva = funcs[ords[i]];
            /* Forwarder: RVA lies inside the export directory range.
             * We do not resolve forwarders here — caller falls back to
             * the forwarded module (e.g. kernelbase for memory APIs). */
            if (rva >= exp_dir->VirtualAddress &&
                rva <  exp_dir->VirtualAddress + exp_dir->Size) {
                return 0;
            }
            return base + rva;
        }
    }
    return 0;
}

#endif /* _WIN32 */
