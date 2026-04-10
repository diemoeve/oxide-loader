/*
 * Oxide Loader Stage 1 - XOR Loop Detection
 *
 * Detects the rolling XOR decryption loop pattern.
 * The compiler generates characteristic opcodes for: data[i] ^= key[i % keylen]
 *
 * Coverage: Static detection of XOR decryption routine
 * False positive risk: Medium - XOR loops are common, combine with other indicators
 */

rule Oxide_Stage1_XOR_Decrypt_x64
{
    meta:
        description = "Detects Oxide Stage 1 XOR decryption loop (x64)"
        author = "diemoeve"
        date = "2026-04-10"
        reference = "oxide-loader/stage1/src/xor.c"
        mitre_attack = "T1140"  // Deobfuscate/Decode Files or Information
        severity = "medium"
        arch = "x64"

    strings:
        /*
         * x64 XOR loop pattern:
         * - Division/modulo for key index (div or idiv)
         * - XOR operation
         * - Memory access pattern
         *
         * Common GCC output for: data[i] ^= key[i % keylen]
         */

        // Pattern 1: Using div instruction for modulo
        // xor edx, edx; div rcx; movzx eax, byte [key + rdx]; xor byte [data + rsi], al
        $xor_div_pattern = {
            31 D2           // xor edx, edx
            48 F7 ??        // div r64
            [0-8]
            30 ??           // xor byte ptr [r64], r8
        }

        // Pattern 2: Using multiplication trick for modulo (compiler optimization)
        // Common when keylen is constant
        $xor_mul_pattern = {
            48 89 ??        // mov r64, r64
            48 F7 E?        // mul r64
            [0-12]
            30 ??           // xor byte ptr, r8
        }

        // Pattern 3: Simple loop with XOR
        $xor_loop_generic = {
            (0F B6 | 44 0F B6)  // movzx (zero-extend byte)
            [0-8]
            (30 | 32)       // xor r8, r/m8 or xor r/m8, r8
            [0-4]
            (48 | 49) FF C? // inc r64
            [0-8]
            (48 | 49) 39    // cmp r64
        }

    condition:
        (uint16(0) == 0x5A4D or uint32(0) == 0x464C457F)
        and any of ($xor_*)
}

rule Oxide_Stage1_XOR_Decrypt_x86
{
    meta:
        description = "Detects Oxide Stage 1 XOR decryption loop (x86)"
        author = "diemoeve"
        date = "2026-04-10"
        reference = "oxide-loader/stage1/src/xor.c"
        mitre_attack = "T1140"
        severity = "medium"
        arch = "x86"

    strings:
        // x86 XOR loop with modulo
        $xor_loop_x86 = {
            31 D2           // xor edx, edx
            F7 ??           // div e32
            [0-6]
            30 ??           // xor byte ptr, r8
            [0-4]
            4?              // inc e32
        }

    condition:
        uint16(0) == 0x5A4D
        and $xor_loop_x86
}
