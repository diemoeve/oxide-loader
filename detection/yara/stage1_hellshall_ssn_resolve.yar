/*
 * Oxide Loader Stage 1 -- Hell's Hall SSN Resolve + Indirect Syscall
 *
 * Pairs with the S34 addition to oxide-loader/stage1: the binary resolves
 * SSNs for a pair of Nt* calls (NtAllocateVirtualMemory,
 * NtProtectVirtualMemory) at runtime by reading the ntdll stub bytes
 * (Hell's Gate `4C 8B D1 B8` prologue check) with FreshyCalls sort-index
 * cross-validation, then jumps to a `syscall; ret` gadget inside ntdll's
 * own .text.
 *
 * This rule catches that composite pattern: three co-occurring byte
 * constants in the loader's own code (the stub prologue check, the
 * FreshyCalls 'N','t' prefix filter, the gadget-scan constants) plus the
 * two precomputed djb2 hashes for the resolved Nt* names.
 *
 * MITRE ATT&CK:
 *   - T1106  Native API (Nt* direct invocation)
 *   - T1027.007  Dynamic API Resolution (hash-resolved exports)
 *   - T1055  Process Injection (via W^X allocation pattern downstream)
 *
 * False positive profile (intent):
 *   - Legit signed OEM utilities: very low (<2%) -- stub-byte literals
 *     are extremely rare in production userland code.
 *   - Other Hell's Hall / HellHall / SysWhispers-family loaders:
 *     expected high overlap; this rule is a technique-family detector,
 *     not a specific-loader detector.
 *   - MinGW/MSVC that happen to read ntdll memory for unrelated reasons:
 *     possible but unusual; chain with stage1_minimal_iat.yml Sigma for
 *     path + behavioral context before alerting.
 *
 * Reference sources:
 *   - https://maldev-academy.github.io/HellHall/
 *   - https://github.com/am0nsec/HellsGate
 *   - https://trickster0.github.io/posts/Halo's-Gate-Evolves-to-Tartarus-Gate/
 *   - https://github.com/JoasASantos/SysWhispers4 (FreshyCalls sort-index)
 */

import "pe"

rule Oxide_Stage1_HellsHall_SSN_Resolve_x64
{
    meta:
        description  = "Stage1: Hell's Gate prologue scan + FreshyCalls sort-index + ntdll gadget indirect syscall"
        author       = "diemoeve"
        date         = "2026-04-23"
        reference    = "oxide-loader/stage1/src/syscalls.c"
        mitre_attack = "T1106,T1027.007"
        severity     = "high"
        filetype     = "pe"
        notes        = "Technique-family detector. Chain with minimal-IAT + path context for alerting."

    strings:
        /* Hell's Gate prologue check: four contiguous immediate-byte
         * comparisons against `4c`, `8b`, `d1`, `b8`. GCC -Os emits these
         * as `cmpb $0x4c, (%r??)` / `$0x8b, 1(%r??)` etc. ModR/M byte
         * wildcarded. The four bytes together are the selectivity. */
        $hg_4c = { 80 ?? 4c }
        $hg_8b = { 80 ?? [0-2] 8b }
        $hg_d1 = { 80 ?? [0-2] d1 }
        $hg_b8 = { 80 ?? [0-2] b8 }

        /* FreshyCalls Nt-prefix filter: cmpb $'N', (%r??) + cmpb $'t', 1(%r??).
         * 0x4e = 'N', 0x74 = 't'. */
        $fc_N = { 80 ?? 4e }
        $fc_t = { 80 ?? [1-3] 74 }

        /* Gadget scan constants: three bytes of the gadget pattern appear
         * as compare-immediate values inside the scan loop: 0x0f, 0x05,
         * 0xc3. The 0xc3 literal is common (ret opcode), so require all
         * three plus the hex-scan shape. GCC emits the scan as
         * cmpb-with-SIB: `80 3c 10 0f` / `80 7c 10 01 05` / `80 7c 10 02
         * c3`. The [0-3] gap covers both the no-SIB `80 ?? imm8` (3-byte)
         * form and the SIB `80 ?? SIB [disp8] imm8` (4-5 byte) form. */
        $ga_0f = { 80 ?? [0-2] 0f }
        $ga_05 = { 80 ?? [0-3] 05 }
        $ga_c3 = { 80 ?? [0-3] c3 }

        /* Precomputed djb2 hashes for NtAllocateVirtualMemory (0x83ffec22)
         * and NtProtectVirtualMemory (0x10a4db54), little-endian.
         * Emitted as 32-bit immediates in the g_api init path. */
        $h_nt_alloc   = { 22 ec ff 83 }
        $h_nt_protect = { 54 db a4 10 }

    condition:
        pe.is_pe and
        pe.machine == pe.MACHINE_AMD64 and
        filesize < 32KB and

        /* Hell's Gate prologue check -- all four bytes must appear as
         * compare-immediates in the loader code. */
        $hg_4c and $hg_8b and $hg_d1 and $hg_b8 and

        /* FreshyCalls N/t prefix filter -- both bytes as compare-imms. */
        $fc_N and $fc_t and

        /* Gadget scan 0F 05 C3 as compare-imms in a scan loop. */
        $ga_0f and $ga_05 and $ga_c3 and

        /* Both djb2 hashes as rodata immediates. The combination of hash
         * constants + stub-byte constants is what narrows the FP surface. */
        $h_nt_alloc and $h_nt_protect and

        /* Minimal IAT (loader pattern continues from S33). */
        pe.number_of_imports <= 1
}
