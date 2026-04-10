/*
 * Oxide Loader Stage 1 - Magic Bytes Detection
 *
 * Detects the embedded configuration magic value 0x4F584944 ("OXID")
 * that identifies Stage 1 loader binaries.
 *
 * Coverage: Static detection of Stage 1 binary on disk or in memory
 * False positive risk: Low - magic combined with structure is distinctive
 */

rule Oxide_Stage1_Magic_Bytes
{
    meta:
        description = "Detects Oxide Stage 1 loader by config magic bytes"
        author = "diemoeve"
        date = "2026-04-10"
        reference = "oxide-loader/stage1/src/config.h"
        mitre_attack = "T1027.009"  // Embedded Payloads
        severity = "high"
        filetype = "executable"

    strings:
        /*
         * Magic value 0x4F584944 in little-endian ("DIOXO" reversed)
         * Followed by config structure: flags(4) + port(2) + stage(2)
         */
        $magic = { 44 49 58 4F }  // "OXID" as bytes

        /*
         * Full config header pattern:
         * magic(4) + flags(4) + port(2) + stage_num(2)
         * Looking for magic followed by reasonable port value
         */
        $config_header = { 44 49 58 4F [4] [0-1] (1F | 20 | 3F | 50 | 90 | 1B | BB) }

    condition:
        uint16(0) == 0x5A4D or     // MZ header (PE)
        uint32(0) == 0x464C457F    // ELF magic
        and
        ($magic or $config_header)
}

rule Oxide_Stage1_Config_Structure
{
    meta:
        description = "Detects Oxide Stage 1 config structure in memory"
        author = "diemoeve"
        date = "2026-04-10"
        reference = "oxide-loader/stage1/src/config.h"
        mitre_attack = "T1027.009"
        severity = "high"

    strings:
        /*
         * Config structure pattern:
         * - magic: 0x4F584944 (4 bytes)
         * - flags: typically 0 (4 bytes)
         * - port: 1-65535 (2 bytes)
         * - stage: 2 or 3 (2 bytes)
         * - xor_key: 1-32 bytes
         * - xor_key_len: 1-32 (1 byte)
         * - followed by hostname string
         */
        $config_with_localhost = { 44 49 58 4F 00 00 00 00 [2] (02|03) 00 [1-32] [1-32] 00 00 00 31 32 37 2E 30 2E 30 2E 31 }

    condition:
        $config_with_localhost
}
