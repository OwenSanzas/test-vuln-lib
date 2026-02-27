#include "vuln_lib.h"
#include <stdlib.h>
#include <string.h>

int buffer_copy(char *dst, size_t dst_size, const char *src) {
    if (!dst || !src || dst_size == 0) return -1;
    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
    return 0;
}

int buffer_concat(char *dst, size_t dst_size, const char *src) {
    if (!dst || !src) return -1;
    size_t current_len = strlen(dst);
    if (current_len >= dst_size) return -1;
    strncat(dst, src, dst_size - current_len - 1);
    return 0;
}

char *buffer_alloc(size_t size) {
    if (size == 0) return NULL;
    char *buf = (char *)malloc(size);
    if (buf) memset(buf, 0, size);
    return buf;
}

void buffer_free(char *buf) {
    free(buf);
}

#include <arpa/inet.h>

int buffer_parse_length_prefixed(const char *input, size_t input_len,
                                  char *out, size_t out_size) {
    if (!input || !out || input_len < 4) return -1;
    uint32_t payload_len;
    memcpy(&payload_len, input, 4);
    payload_len = ntohl(payload_len);
    /* BUG: missing check that payload_len <= input_len - 4 */
    if (payload_len > out_size) return -1;
    memcpy(out, input + 4, payload_len);
    return (int)payload_len;
}
