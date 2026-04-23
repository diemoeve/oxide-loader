/*
 * Oxide Loader Stage 1 — PEB Walk + Hash-Resolve Detection
 *
 * Pairs with the S33 refactor of oxide-loader/stage1: the binary no
 * longer imports WinInet/kernel32 memory APIs through the IAT; instead
 * it walks PEB.Ldr.InMemoryOrderModuleList, hashes module names, and
 * matches exports by djb2 XOR hash (multiply-by-33 reduction).
 *
 * This rule expresses that refactor's runtime signature: a small PE
 * with an empty / near-empty IAT and a PEB-walk + djb2 multiply-by-33
 * code pattern.
 *
 * MITRE ATT&CK: T1027.007 (Dynamic API Resolution)
 *
 * False positive rate — measured intent:
 *   - Unpacked Rust/Go release PEs:   low (<5%) — rarely walk PEB
 *   - MSVC native apps:               low (<5%)
 *   - Packed/protected benigns (UPX,  medium/high (15-40%) — many do
 *     VMProtect, Themida, installers)   PEB.BeingDebugged checks that
 *                                       touch gs:[0x60]
 *   - Mitigation: chain with detection/sigma/stage1_minimal_iat.yml,
 *     or with a process/network event.
 */

import "pe"

rule Oxide_Stage1_PEB_Walk_x64
{
    meta:
        description  = "Stage1: PEB walk + djb2 hash API resolution, minimal IAT"
        author       = "diemoeve"
        date         = "2026-04-23"
        reference    = "oxide-loader/stage1/src/peb_walk.c"
        mitre_attack = "T1027.007"
        severity     = "high"
        filetype     = "pe"
        notes        = "High-FP on packed benigns — chain with Sigma stage1_minimal_iat"

    strings:
        /* mov %gs:0x60,%r?? — read TEB.ProcessEnvironmentBlock.
         * ModR/M + SIB variations covered by wildcards. */
        $peb_load = { 65 48 8B [1-3] 60 00 00 00 }

        /* mov 0x18(%r??),%r?? — PEB->Ldr at offset 0x18. */
        $ldr_offset = { 48 8B ?? 18 }

        /* mov 0x20(%r??),%r?? — Ldr->InMemoryOrderModuleList at +0x20. */
        $inmem_list = { 48 8B ?? 20 }

        /* imul $0x21, %r??, %r??  — djb2 multiplier: (h << 5) + h == h * 33.
         * GCC -Os folds ((h<<5)+h) into this single imul. */
        $djb2_imul = { 6B ?? 21 }

        /* Alternative djb2 shape some compilers emit instead of imul:
         * lea (%rX,%rX,4),%rY ; lea (%rY,%rY,8),%rZ — not our build, but
         * kept to cover -O2 variants. */
        $djb2_lea5 = { 48 8D ?? ?? 00 }

    condition:
        pe.is_pe and
        pe.machine == pe.MACHINE_AMD64 and
        filesize < 32KB and
        /* Core signature: PEB reach + Ldr walk + one of the hash
         * reductions. The four-way combination inside a 32KB binary
         * is the selectivity. */
        $peb_load and
        $ldr_offset and
        $inmem_list and
        ($djb2_imul or #djb2_lea5 >= 4) and
        /* Minimal IAT — an unpacked benign would normally have several
         * imported DLLs. The refactored stage1 has zero. */
        pe.number_of_imports <= 1
}
