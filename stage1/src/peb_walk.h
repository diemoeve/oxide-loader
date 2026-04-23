/*
 * PEB walk — runtime module and export resolution without touching IAT.
 *
 * Replaces LoadLibrary + GetProcAddress. Reads loaded modules from the
 * PEB Ldr InMemoryOrderModuleList, matches module names by
 * case-insensitive djb2 over the UTF-16 BaseDllName, then walks the
 * target module's export directory and matches export names by
 * case-insensitive djb2 over the ASCII name string.
 *
 * Detection artifact: gs:[0x60] PEB load followed by LDR walk + djb2
 * shift-add loop. Paired YARA rule: detection/yara/stage1_peb_walk.yar.
 *
 * Windows x86_64 only. Uses hardcoded ABI offsets (winternl.h abstracts
 * the relevant fields behind Reserved[N]).
 */

#ifndef PEB_WALK_H
#define PEB_WALK_H

#ifdef _WIN32

#include <stdint.h>
#include <stddef.h>

/*
 * Locate a loaded module by name hash (case-insensitive djb2 XOR over
 * the ASCII low-byte of each UTF-16 code unit in BaseDllName).
 *
 * @param name_hash  Precomputed djb2 hash (see stage1/src/hash.h H_* constants)
 * @return           Module base address, or NULL if not found
 */
void *peb_find_module(uint32_t name_hash);

/*
 * Resolve an export in an already-loaded module.
 *
 * @param dll_base   Module base from peb_find_module
 * @param fn_hash    Precomputed djb2 hash of the export name
 * @return           Function pointer, or NULL if not found or
 *                   forwarder-resolution failed
 */
void *peb_find_export(void *dll_base, uint32_t fn_hash);

#endif /* _WIN32 */
#endif /* PEB_WALK_H */
