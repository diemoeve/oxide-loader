/*
 * Oxide Loader Stage 2 - Anti-Debug Detection
 *
 * Detects debugger detection patterns and strings.
 *
 * Coverage: Static detection of anti-debug code
 * False positive risk: Medium - some patterns are used by legitimate software
 */

import "pe"

rule Oxide_Stage2_IsDebuggerPresent_Import
{
    meta:
        description = "Detects IsDebuggerPresent import in suspicious context"
        author = "diemoeve"
        date = "2026-04-10"
        reference = "oxide-loader/stage2/src/anti_analysis/debugger.rs"
        mitre_attack = "T1622"  // Debugger Evasion
        severity = "medium"
        filetype = "pe"

    condition:
        pe.is_pe and
        pe.imports("kernel32.dll", "IsDebuggerPresent") and
        // Suspicious: small binary with debugger check
        filesize < 2MB
}

rule Oxide_Stage2_PEB_BeingDebugged
{
    meta:
        description = "Detects direct PEB.BeingDebugged access pattern"
        author = "diemoeve"
        date = "2026-04-10"
        reference = "oxide-loader/stage2/src/anti_analysis/debugger.rs"
        mitre_attack = "T1622"
        severity = "high"

    strings:
        // x64: mov rax, gs:[0x60]; movzx reg, byte ptr [rax+2]
        $peb_x64 = {
            65 48 8B 04 25 60 00 00 00  // mov rax, gs:[0x60]
            [0-10]
            0F B6 ?? 02                  // movzx r32, byte ptr [rax+2]
        }

        // x86: mov eax, fs:[0x30]; movzx reg, byte ptr [eax+2]
        $peb_x86 = {
            64 A1 30 00 00 00           // mov eax, fs:[0x30]
            [0-10]
            0F B6 ?? 02                  // movzx r32, byte ptr [eax+2]
        }

    condition:
        any of them
}

rule Oxide_Stage2_NtQueryInformationProcess
{
    meta:
        description = "Detects NtQueryInformationProcess debug port check"
        author = "diemoeve"
        date = "2026-04-10"
        reference = "oxide-loader/stage2/src/anti_analysis/debugger.rs"
        mitre_attack = "T1622"
        severity = "high"

    strings:
        // String reference
        $api_name = "NtQueryInformationProcess" ascii wide

        // ProcessDebugPort constant (7)
        // Often seen as: mov ecx/edx, 7
        $debug_port_const = { B? 07 00 00 00 }  // mov r32, 7

    condition:
        $api_name and $debug_port_const
}

rule Oxide_Stage2_Linux_TracerPid
{
    meta:
        description = "Detects TracerPid check in Linux binaries"
        author = "diemoeve"
        date = "2026-04-10"
        reference = "oxide-loader/stage2/src/anti_analysis/debugger.rs"
        mitre_attack = "T1622"
        severity = "medium"
        filetype = "elf"

    strings:
        $proc_status = "/proc/self/status" ascii
        $tracer_pid = "TracerPid" ascii

    condition:
        uint32(0) == 0x464C457F and  // ELF magic
        all of them
}

rule Oxide_Stage2_Ptrace_Self
{
    meta:
        description = "Detects ptrace(PTRACE_TRACEME) anti-debug pattern"
        author = "diemoeve"
        date = "2026-04-10"
        reference = "oxide-loader/stage2/src/anti_analysis/debugger.rs"
        mitre_attack = "T1622"
        severity = "medium"
        filetype = "elf"

    strings:
        $ptrace = "ptrace" ascii

    condition:
        uint32(0) == 0x464C457F and
        $ptrace and
        filesize < 5MB
}
