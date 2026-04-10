/*
 * XOR Decryption Implementation
 *
 * Rolling XOR with variable-length key.
 * This pattern is detectable via YARA opcode matching.
 *
 * Detection artifact: XOR loop with modulo key index
 * YARA signature target: stage1_xor.yar
 */

#include "xor.h"

void xor_decrypt(uint8_t *data, size_t len, const uint8_t *key, size_t keylen)
{
    if (!data || !key || keylen == 0) {
        return;
    }

    /*
     * Rolling XOR - each byte XORed with key[i % keylen]
     * This produces a characteristic loop pattern in disassembly.
     */
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key[i % keylen];
    }
}
