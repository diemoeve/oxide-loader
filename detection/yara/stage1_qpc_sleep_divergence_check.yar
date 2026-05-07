/*
 * Oxide Loader Stage 1 — QPC/Sleep Divergence Check (S40 anti-emu)
 *
 * Pairs with the S40 anti-emulation timing probe in
 * stage1/src/anti_emu.c. The probe brackets a Sleep(8000) call with
 * QueryPerformanceCounter reads, then computes
 *
 *     elapsed_ms = (T1 - T0) * 1000 / freq
 *
 * and compares the result against a small floor (3200 ms for Guard 1,
 * 1500 ms for Guard 2's wall-clock window). On real hardware Sleep
 * never returns earlier than requested and the threshold is cleared
 * with massive headroom; on Sleep-skip / iteration-bounded emulators
 * the elapsed-ms comparison falls below the floor and the binary
 * self-terminates via ExitProcess(0).
 *
 * The detection signal is the divergence-arithmetic block itself:
 *
 *     sub rax, QWORD PTR [rsp+...]   ; delta = T_late - T_early
 *     xor edx, edx                   ; clear high half for div
 *     imul rax, rax, 0x3E8           ; *1000 (the smoking gun)
 *     div QWORD PTR [rsp+...]        ; / freq
 *     cmp rax, <small imm32>         ; vs threshold
 *
 * The combination "imul ?, ?, 0x3E8" followed within a short window
 * by "div [rsp+...]" and "cmp ?, <small>" is the signature emitted by
 * compilers when a programmer writes the canonical QPC-elapsed-ms
 * formula. It is not unique on its own — long-running benign
 * benchmarks emit it too — but inside a kernel32-only sub-16KB PE
 * (the S39 silhouette) the conjunction is selective.
 *
 * MITRE ATT&CK:
 *   T1497.003  Time Based Evasion
 *   T1480      Execution Guardrails
 *
 * False-positive notes:
 *   - Profilers and microbenchmarks (e.g. Google Benchmark stubs)
 *     emit the same arithmetic. Filtered by the small-PE size cap
 *     and the no-network-DLL constraint.
 *   - Compilers may instead emit "shl + lea" sequences for *1000.
 *     The MinGW -Os build at the supported optimisation level emits
 *     the imul form; this rule targets that build. Variant-form
 *     coverage is left to a follow-on rule once the deployment matrix
 *     is fixed.
 */

import "pe"

rule Oxide_Stage1_QPC_Sleep_Divergence_Check_x64
{
    meta:
        description  = "Stage1 S40: QPC-bracketed Sleep + divergence-arithmetic block (anti-emu probe)"
        author       = "diemoeve"
        date         = "2026-05-07"
        reference    = "oxide-loader/stage1/src/anti_emu.c"
        mitre_attack = "T1497.003,T1480"
        severity     = "high"
        filetype     = "pe"
        notes        = "Conjunction rule — divergence arithmetic + Sleep(8000) immediate + IAT silhouette. Chain with stage1_decoy_iat_shape.yar for code-pattern confirmation."

    strings:
        /*
         * Divergence arithmetic, 64-bit form. Two consecutive
         * occurrences inside the same code region indicate the
         * Guard 1 (Sleep) and Guard 2 (CPU-loop) blocks emitted by
         * anti_emu_run().
         *
         *   48 69 c0 e8 03 00 00  imul rax, rax, 0x3E8
         *   48 f7 74 24 ??        div QWORD PTR [rsp+OFFS]
         *   48 3d ?? ?? 00 00     cmp rax, imm32
         */
        $div_arith_a = {
            48 69 C0 E8 03 00 00
            48 F7 74 24 ??
            48 3D ?? ?? 00 00
        }

        /*
         * Same arithmetic, second instance — kept as a separate
         * pattern so the rule fires on a single-guard variant too.
         * Allows up to a small instruction prefix (sub + xor) before
         * the imul to absorb scheduler-driven spilling differences.
         */
        $div_arith_b = {
            48 2B 44 24 ??
            31 D2
            48 69 C0 E8 03 00 00
            48 F7 74 24 ??
        }

        /*
         * Sleep request immediate. 0x1F40 = 8000 ms — the probe's
         * fixed wait. Loaded into ECX as the Win64 first arg, with
         * the resolved fn pointer already in a register, before an
         * indirect call. Compiler ordering varies; cover the two
         * common shapes:
         *
         *   48 8B 44 24 ??       mov rax, [rsp+OFFS] (load fn ptr)
         *   b9 40 1f 00 00       mov ecx, 0x1F40
         *   ff d?                call <reg>
         *
         * and the immediate-first variant
         *
         *   b9 40 1f 00 00       mov ecx, 0x1F40
         *   <reg load>
         *   ff d?                call <reg>
         */
        $sleep_8000_a = {
            48 8B 44 24 ??
            B9 40 1F 00 00
            FF D?
        }
        $sleep_8000_b = {
            B9 40 1F 00 00
            [0-8]
            FF D?
        }

        /*
         * Iteration-floor compare. cmp rax, 0xF423F = 999999 — the
         * "iter < 1_000_000" floor encoded as "<= 999999" by the
         * optimiser. Distinctive enough to anchor the rule in the
         * absence of other markers.
         */
        $iter_floor = {
            48 3D 3F 42 0F 00
        }

        /*
         * Inline CPUID leaf 1 + ECX bit-31 mask. Guard 3
         * informational HV-bit read.
         *
         *   b8 01 00 00 00        mov eax, 1
         *   0f a2                 cpuid
         *   ...
         *   81 e1 00 00 00 80     and ecx, 0x80000000
         */
        $cpuid_hv_bit = {
            B8 01 00 00 00
            0F A2
            [0-12]
            81 E1 00 00 00 80
        }

    condition:
        pe.is_pe and
        pe.machine == pe.MACHINE_AMD64 and
        filesize < 16KB and

        /*
         * IAT silhouette — kernel32-only, no network/loader DLLs.
         * Mirrors the S39 stage1_decoy_iat_shape rule's selectors.
         * Without it, the divergence-arithmetic patterns above match
         * benign benchmarks and profilers.
         */
        pe.number_of_imports == 1 and
        pe.imports("kernel32.dll") > 0 and
        pe.imports("ws2_32.dll") == 0 and
        pe.imports("wininet.dll") == 0 and
        pe.imports("winhttp.dll") == 0 and
        pe.imports("urlmon.dll") == 0 and
        pe.imports("ntdll.dll") == 0 and

        /*
         * QPC and Sleep are absent from the IAT (PEB-walked at
         * runtime by anti_emu.c). Their presence here would mean
         * either a different build configuration or a benign
         * timing-sensitive utility — both of which we want to
         * exclude.
         */
        pe.imports("kernel32.dll", "QueryPerformanceCounter") == 0 and
        pe.imports("kernel32.dll", "QueryPerformanceFrequency") == 0 and
        pe.imports("kernel32.dll", "Sleep") == 0 and

        /*
         * Code patterns. At least one divergence-arithmetic block
         * AND the Sleep(8000) immediate, plus the iter floor or
         * the CPUID HV-bit read for additional anchoring.
         */
        ($div_arith_a or $div_arith_b) and
        ($sleep_8000_a or $sleep_8000_b) and
        ($iter_floor or $cpuid_hv_bit)
}
