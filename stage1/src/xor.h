/*
 * XOR Decryption Header
 *
 * Detection artifact: Rolling XOR loop pattern
 * YARA signature target: stage1_xor.yar
 */

#ifndef XOR_H
#define XOR_H

#include <stdint.h>
#include <stddef.h>

/*
 * In-place XOR decryption with rolling key.
 *
 * @param data   Buffer to decrypt (modified in place)
 * @param len    Length of data
 * @param key    XOR key bytes
 * @param keylen Length of key
 */
void xor_decrypt(uint8_t *data, size_t len, const uint8_t *key, size_t keylen);

#endif /* XOR_H */
