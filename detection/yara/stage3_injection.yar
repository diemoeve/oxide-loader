/*
 * Oxide Loader Stage 3 - Process Injection Detection
 *
 * Detects process injection patterns and API imports.
 *
 * Coverage: Static detection of injection capabilities
 * False positive risk: Low when combined - legitimate apps rarely need all these APIs
 */

import "pe"

rule Oxide_Stage3_PE_Injection_Imports
{
    meta:
        description = "Detects Stage 3 by classic injection API imports"
        author = "diemoeve"
        date = "2026-04-10"
        reference = "oxide-loader/stage3/src/injection/windows.rs"
        mitre_attack = "T1055.002"  // Process Injection: Portable Executable Injection
        severity = "high"
        filetype = "pe"

    condition:
        pe.is_pe and
        // Classic CreateRemoteThread injection
        pe.imports("kernel32.dll", "OpenProcess") and
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        pe.imports("kernel32.dll", "CreateRemoteThread") and
        // Additional indicators
        (
            pe.imports("kernel32.dll", "CreateToolhelp32Snapshot") or
            pe.imports("kernel32.dll", "Process32First") or
            pe.imports("kernel32.dll", "Process32FirstW")
        )
}

rule Oxide_Stage3_Injection_Strings
{
    meta:
        description = "Detects Stage 3 by injection-related strings"
        author = "diemoeve"
        date = "2026-04-10"
        reference = "oxide-loader/stage3/src/injection/"
        mitre_attack = "T1055"
        severity = "medium"

    strings:
        // Windows target process
        $target_explorer = "explorer.exe" ascii wide nocase

        // Error strings from injection code
        $err_process = "failed to find target process" ascii
        $err_open = "failed to open target process" ascii
        $err_alloc = "failed to allocate memory" ascii
        $err_write = "failed to write memory" ascii
        $err_thread = "failed to create thread" ascii

        // Linux memfd strings
        $memfd_path = "/proc/self/fd/" ascii
        $memfd_failed = "memfd_create failed" ascii

    condition:
        3 of them
}

rule Oxide_Stage3_Linux_Memfd
{
    meta:
        description = "Detects Stage 3 Linux fileless execution pattern"
        author = "diemoeve"
        date = "2026-04-10"
        reference = "oxide-loader/stage3/src/injection/linux.rs"
        mitre_attack = "T1055"  // Process Injection
        severity = "high"
        filetype = "elf"

    strings:
        // memfd_create syscall number (319 on x86_64)
        // mov eax, 319 pattern
        $syscall_num = { B8 3F 01 00 00 }  // mov eax, 0x13f (319)

        // /proc/self/fd/ path
        $proc_fd = "/proc/self/fd/" ascii

        // memfd string (often empty but detectable)
        $mfd_cloexec = { 01 00 00 00 }  // MFD_CLOEXEC flag

    condition:
        uint32(0) == 0x464C457F and  // ELF magic
        $proc_fd and
        ($syscall_num or $mfd_cloexec)
}

rule Oxide_Stage3_Memory_PE_Unbacked
{
    meta:
        description = "Detects PE header in memory without disk backing"
        author = "diemoeve"
        date = "2026-04-10"
        reference = "Memory forensics pattern"
        mitre_attack = "T1055"
        severity = "critical"

    strings:
        // MZ header
        $mz = "MZ"

        // PE signature
        $pe_sig = "PE\x00\x00"

        // Common PE sections
        $text = ".text" ascii
        $rdata = ".rdata" ascii
        $data = ".data" ascii

    condition:
        $mz at 0 and
        $pe_sig and
        2 of ($text, $rdata, $data)
}
