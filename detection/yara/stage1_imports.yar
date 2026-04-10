/*
 * Oxide Loader Stage 1 - Import Table Detection
 *
 * Detects suspicious import combinations typical of Stage 1 loaders:
 * - Network functions (WinHTTP/sockets)
 * - Memory allocation with execute permissions
 * - No legitimate application functionality
 *
 * Coverage: Static detection via PE import table
 * False positive risk: Low when combined - legitimate apps rarely need this exact combo
 */

import "pe"

rule Oxide_Stage1_PE_Imports
{
    meta:
        description = "Detects Oxide Stage 1 by suspicious PE import combination"
        author = "diemoeve"
        date = "2026-04-10"
        reference = "oxide-loader/stage1/src/"
        mitre_attack = "T1106"  // Native API
        severity = "high"
        filetype = "pe"

    condition:
        pe.is_pe and

        // Must have WinHTTP for staging fetch
        (
            pe.imports("winhttp.dll", "WinHttpOpen") and
            pe.imports("winhttp.dll", "WinHttpConnect") and
            pe.imports("winhttp.dll", "WinHttpOpenRequest") and
            pe.imports("winhttp.dll", "WinHttpSendRequest") and
            pe.imports("winhttp.dll", "WinHttpReceiveResponse")
        )
        and
        // Must have VirtualAlloc for RWX memory
        pe.imports("kernel32.dll", "VirtualAlloc")
        and
        // Small binary (< 100KB typical for stubs)
        pe.number_of_sections <= 5 and
        filesize < 100KB
}

rule Oxide_Stage1_PE_Imports_Minimal
{
    meta:
        description = "Detects minimal loader with network + memory execution imports"
        author = "diemoeve"
        date = "2026-04-10"
        mitre_attack = "T1106"
        severity = "medium"
        filetype = "pe"

    condition:
        pe.is_pe and
        // Network capability
        (
            pe.imports("winhttp.dll", "WinHttpOpen") or
            pe.imports("wininet.dll", "InternetOpenA") or
            pe.imports("ws2_32.dll", "connect")
        )
        and
        // Memory execution capability
        pe.imports("kernel32.dll", "VirtualAlloc")
        and
        // Suspicious: no common legitimate imports
        not pe.imports("user32.dll", "MessageBoxA") and
        not pe.imports("gdi32.dll", "CreateFontA") and
        not pe.imports("shell32.dll", "ShellExecuteA")
        and
        filesize < 100KB
}

rule Oxide_Stage1_ELF_Symbols
{
    meta:
        description = "Detects Oxide Stage 1 ELF by suspicious symbol combination"
        author = "diemoeve"
        date = "2026-04-10"
        mitre_attack = "T1106"
        severity = "medium"
        filetype = "elf"

    strings:
        // Socket functions
        $socket = "socket" ascii
        $connect = "connect" ascii
        $send = "send" ascii
        $recv = "recv" ascii
        $gethostbyname = "gethostbyname" ascii

        // Memory mapping
        $mmap = "mmap" ascii

        // HTTP staging path pattern
        $staging_path = "/api/staging/" ascii

    condition:
        uint32(0) == 0x464C457F and  // ELF magic
        all of ($socket, $connect, $send, $recv, $gethostbyname) and
        $mmap and
        $staging_path and
        filesize < 100KB
}
