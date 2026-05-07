#include "xor_string.h"

/* noinline: prevents the compiler from proving the post-decode buffer
 * contents and constant-folding plaintext back into .rodata. */
__attribute__((noinline))
void xs_decode(const volatile unsigned char *enc, char *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        out[i] = (char)((unsigned char)enc[i] ^ (unsigned char)(XS_SEED[i & 31] + i));
    }
}

__attribute__((noinline))
void xs_wipe(char *buf, size_t n) {
    volatile char *p = (volatile char *)buf;
    for (size_t i = 0; i < n; i++) {
        p[i] = 0;
    }
}
