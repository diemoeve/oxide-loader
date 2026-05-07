/*
 * Oxide Loader Stage 1 — Decoy IAT Shape Detection
 *
 * Pairs with the S39 IAT-cosmetic refactor: stage1 now imports a 12-15
 * entry kernel32-only set chosen to mimic a small Windows console
 * utility (GetCommandLineA, HeapAlloc/Free, WideCharToMultiByte,
 * SetUnhandledExceptionFilter, GetTickCount, ...). The offensive APIs
 * remain hidden — resolve_apis() walks the PEB and resolves every
 * VirtualAlloc / wininet / Nt* by djb2 hash at runtime, never through
 * the IAT.
 *
 * The detection signal is the IAT *silhouette* — a small PE whose
 * imports look like a routine OEM utility — combined with the djb2
 * runtime-resolution code pattern in .text. Either signal alone is
 * weak; the conjunction is selective.
 *
 * MITRE ATT&CK:
 *   T1027.007  Dynamic API Resolution
 *   T1480      Execution Guardrails / environmental sanity probes
 *
 * False-positive rate — measured intent:
 *   - Tiny, non-network OEM utilities (RtkAud, sysinternals, etc.):
 *       low/medium — they share the kernel32-utility shape but lack
 *       the djb2 prologue.
 *   - Custom-stub Rust/Go release PEs that walk PEB themselves: low.
 *   - Packed/protected benigns (UPX, VMProtect): packed binaries
 *       usually retain a packer-generated IAT that does NOT match the
 *       common-utility decoy set, so the conjunction holds.
 *   - Mitigation: chain with detection/sigma/stage1_minimal_iat.yml
 *       (post-enrichment ImportedFunctionCount + name-set check).
 */

import "pe"

rule Oxide_Stage1_Decoy_IAT_Shape_x64
{
    meta:
        description  = "Stage1: kernel32-only decoy IAT shape + djb2 runtime resolution"
        author       = "diemoeve"
        date         = "2026-05-07"
        reference    = "oxide-loader/stage1/src/decoys.c"
        mitre_attack = "T1027.007,T1480"
        severity     = "high"
        filetype     = "pe"
        notes        = "Conjunction rule — IAT silhouette + djb2 prologue + no-network. Chain with Sigma stage1_minimal_iat for post-enrichment confirmation."

    strings:
        /* djb2 seed load — `mov $0x1505, %eax` (5381 decimal). The PEB
         * walker initialises its hash accumulator with this constant
         * before iterating. Same prologue lives in stage1_peb_walk.yar
         * but here it complements the IAT-shape check rather than the
         * PEB-reach check. */
        $djb2_seed_eax = { B8 05 15 00 00 }
        $djb2_seed_r32 = { 41 B? 05 15 00 00 }

        /* mov %gs:0x60,%r?? — TEB.ProcessEnvironmentBlock fetch.
         * Required because a benign utility with the IAT shape below
         * would not also reach for the PEB. */
        $peb_load = { 65 48 8B [1-3] 60 00 00 00 }

    condition:
        pe.is_pe and
        pe.machine == pe.MACHINE_AMD64 and
        filesize < 16KB and

        /* IAT silhouette — kernel32 only, network/loader DLLs absent.
         * pe.imports(dll_name) is case-insensitive on the DLL name and
         * returns the number of imported functions; nonzero coerces to
         * true under YARA's boolean rules. */
        pe.number_of_imports == 1 and
        pe.imports("kernel32.dll") > 0 and
        pe.imports("ws2_32.dll") == 0 and
        pe.imports("wininet.dll") == 0 and
        pe.imports("winhttp.dll") == 0 and
        pe.imports("urlmon.dll") == 0 and
        pe.imports("ntdll.dll") == 0 and

        /* Common-utility decoy set — at least 3 of the canonical
         * "small console utility" kernel32 names must be present.
         * Mirrors decoy_a_refs[] + the Tier B/C calls in
         * stage1/src/decoys.c, with IsDebuggerPresent kept as an
         * alternative for variants that include an anti-debug knob.
         * pe.imports(dll, fn) returns 1 when present, 0 when absent;
         * summing across the candidate set gives a hit count. */
        (pe.imports("kernel32.dll", "GetTickCount") +
         pe.imports("kernel32.dll", "GetSystemTimeAsFileTime") +
         pe.imports("kernel32.dll", "GetCommandLineA") +
         pe.imports("kernel32.dll", "GetUserDefaultLocaleName") +
         pe.imports("kernel32.dll", "GetCurrentProcessId") +
         pe.imports("kernel32.dll", "HeapAlloc") +
         pe.imports("kernel32.dll", "HeapFree") +
         pe.imports("kernel32.dll", "WideCharToMultiByte") +
         pe.imports("kernel32.dll", "SetUnhandledExceptionFilter") +
         pe.imports("kernel32.dll", "IsDebuggerPresent")) >= 3 and

        /* Hidden-API code pattern — djb2 seed load AND a PEB reach.
         * Either alone is benign; the pair inside a 16KB PE that
         * imports only kernel32-utility functions is the selectivity. */
        ($djb2_seed_eax or $djb2_seed_r32) and
        $peb_load
}
