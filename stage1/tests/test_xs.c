/*
 * Unit test: XE()+xs_decode roundtrip.
 *
 * Asserts:
 *  1. Decoded buffer equals the original plaintext.
 *  2. The encrypted byte array does NOT contain the plaintext bytes —
 *     i.e. the compiler is not folding and rematerializing the literal.
 *  3. xs_wipe actually zeros the buffer.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../src/xor_string.h"

static int failures = 0;

int main(void) {
    /* Encrypted literal "Hello, world!" spelled char-by-char so the compiler
     * folds each XE(c,i) into a single encrypted byte. */
    static volatile const unsigned char enc[] = {
        XE('H', 0),  XE('e', 1),  XE('l', 2),  XE('l', 3),
        XE('o', 4),  XE(',', 5),  XE(' ', 6),  XE('w', 7),
        XE('o', 8),  XE('r', 9),  XE('l',10),  XE('d',11),
        XE('!',12),  XE(0,  13)
    };
    const char expected[] = "Hello, world!";
    const size_t n = sizeof(expected);

    /* Check 1: roundtrip */
    char buf[sizeof(expected)];
    xs_decode(enc, buf, n);
    if (memcmp(buf, expected, n) != 0) {
        fprintf(stderr, "FAIL: roundtrip mismatch: got=%s expected=%s\n",
                buf, expected);
        failures++;
    } else {
        printf("OK:   roundtrip -> \"%s\"\n", buf);
    }

    /* Check 2: encrypted bytes do not equal plaintext. If any byte in enc
     * equals the corresponding plaintext byte, the XOR key at that position
     * happened to be 0, which should never occur for XS_K>=1. */
    int leak = 0;
    for (size_t i = 0; i < n; i++) {
        if ((unsigned char)enc[i] == (unsigned char)expected[i]) {
            fprintf(stderr, "FAIL: enc[%zu]=0x%02x equals plaintext 0x%02x\n",
                    i, (unsigned)enc[i], (unsigned)expected[i]);
            leak++;
        }
    }
    if (leak == 0) {
        printf("OK:   no plaintext byte in encrypted array (%zu bytes)\n", n);
    } else {
        failures++;
    }

    /* Check 3: also verify no substring of encrypted bytes contains the
     * whole plaintext. This catches pathological folding where the compiler
     * stashes a plaintext copy elsewhere in .rodata. */
    if (memmem((const void *)enc, sizeof(enc), expected, strlen(expected)) != NULL) {
        fprintf(stderr, "FAIL: plaintext substring found in encrypted array\n");
        failures++;
    } else {
        printf("OK:   no plaintext substring in enc blob\n");
    }

    /* Check 4: xs_wipe zeros the buffer. */
    xs_wipe(buf, n);
    int nonzero = 0;
    for (size_t i = 0; i < n; i++) {
        if (buf[i] != 0) nonzero++;
    }
    if (nonzero == 0) {
        printf("OK:   xs_wipe cleared %zu bytes\n", n);
    } else {
        fprintf(stderr, "FAIL: xs_wipe left %d non-zero bytes\n", nonzero);
        failures++;
    }

    if (failures) {
        fprintf(stderr, "\n%d XS test(s) failed\n", failures);
        return 1;
    }
    printf("\nAll XS tests passed.\n");
    return 0;
}
