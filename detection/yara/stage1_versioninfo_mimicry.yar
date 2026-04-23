/*
 * Oxide Loader Stage 1 -- VERSIONINFO Mimicry Detection
 *
 * Pairs with the S34 cosmetic layer: the binary presents populated
 * VERSIONINFO strings resembling a niche OEM vendor utility (Realtek
 * Semiconductor as shipped, but the rule covers the broader persona
 * class documented in the research wave) while carrying the behavioral
 * fingerprint of a custom loader (MinGW linker artifacts, minimal IAT,
 * no Rich header).
 *
 * Intent: fire when the cosmetic persona does not match the structural
 * reality of the binary. A genuine Realtek binary has:
 *   - An actual MSVC Rich header (Microsoft Visual C++ linker signature)
 *   - A non-minimal IAT (Realtek utilities import multiple DLLs)
 *   - A valid Microsoft-issued code-signing chain
 *
 * This rule matches when Realtek-like CompanyName / ProductName strings
 * appear in a binary missing all three of those structural markers.
 *
 * MITRE ATT&CK:
 *   - T1036.005  Masquerading: Match Legitimate Name or Location
 *
 * False positive profile (intent + measured):
 *   - Real Realtek/Synaptics/Dell utilities: very low -- they have
 *     proper Rich headers and multi-DLL imports.
 *   - MinGW-built hobby tools claiming OEM VERSIONINFO: possible.
 *     Acceptable; such tools are themselves unusual and warrant inspection.
 *   - Stripped open-source releases masquerading as OEM software:
 *     intended catch surface.
 *
 * Reference research:
 *   - ~/obsidian/04-Projects/offensive-infra-knowledge/research/
 *     technical-evasion/versioninfo-mimicry-detection_RESEARCH.md
 *   - https://labs.withsecure.com/publications/masquerading-as-a-windows-
 *     system-binary-using-digital-signatures
 */

import "pe"

rule Oxide_Stage1_VersionInfo_Mimicry_x64
{
    meta:
        description  = "Stage1: OEM persona VERSIONINFO without matching structural fingerprint"
        author       = "diemoeve"
        date         = "2026-04-23"
        reference    = "oxide-loader/stage1/resources/stage1.rc"
        mitre_attack = "T1036.005"
        severity     = "medium"
        filetype     = "pe"
        notes        = "Persona/reality mismatch detector. Tune OEM list per deployment."

    strings:
        /* Niche OEM vendor names that appear in current stage1.rc or
         * plausible variants. VERSIONINFO strings are stored as UTF-16LE
         * in the RT_VERSION resource -- `wide` modifier required; `ascii`
         * kept for manifest + non-resource embeddings. Case-insensitive
         * so that Realtek's own mixed-case variations all match. */
        $v_realtek   = "Realtek Semiconductor" ascii wide nocase
        $v_synaptics = "Synaptics Incorporated" ascii wide nocase
        $v_conexant  = "Conexant" ascii wide nocase
        $v_asus      = "ASUS AI Suite" ascii wide nocase
        $v_dell      = "Dell Inc." ascii wide nocase

        /* Rich header magic. MSVC-linked PEs have the 4-byte "Rich"
         * token before the PE signature in the DOS stub region; MinGW
         * does not emit it. Absence of this string within the first
         * 1 KB is a MinGW-linker signal. */
        $rich_magic  = "Rich"

    condition:
        pe.is_pe and
        pe.machine == pe.MACHINE_AMD64 and
        filesize < 64KB and

        /* At least one niche OEM vendor string present */
        1 of ($v_*) and

        /* No Rich header within DOS stub region (MinGW stance). */
        not $rich_magic in (0..1024) and

        /* Minimal IAT -- a legit OEM utility imports many DLLs. */
        pe.number_of_imports <= 2
}
