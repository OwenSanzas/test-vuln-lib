#include "vuln_lib.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>

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

int buffer_parse_length_prefixed(const char *input, size_t input_len,
                                  char *out, size_t out_size) {
    if (!input || !out || input_len < 4) return -1;
    uint32_t payload_len;
    memcpy(&payload_len, input, 4);
    payload_len = ntohl(payload_len);
    if (payload_len > input_len - 4 || payload_len > out_size) return -1;
    memcpy(out, input + 4, payload_len);
    return (int)payload_len;
}

/* ── buffer pool ──────────────────────────────────────────── */

struct buffer_pool {
    char **entries;
    int count;
    int capacity;
};

struct buffer_pool *pool_create(int capacity) {
    struct buffer_pool *p = malloc(sizeof(*p));
    if (!p) return NULL;
    p->entries = calloc(capacity, sizeof(char *));
    if (!p->entries) { free(p); return NULL; }
    p->count = 0;
    p->capacity = capacity;
    return p;
}

int pool_add(struct buffer_pool *p, const char *data, size_t len) {
    if (!p || !data || p->count >= p->capacity) return -1;
    if (len >= SIZE_MAX) return -1;
    char *buf = malloc(len + 1);
    if (!buf) return -1;
    memcpy(buf, data, len);
    buf[len] = '\0';
    p->entries[p->count++] = buf;
    return 0;
}

void pool_remove(struct buffer_pool *p, int index) {
    if (!p || index < 0 || index >= p->count) return;
    free(p->entries[index]);
    /* shift remaining entries left */
    for (int i = index; i < p->count - 1; i++)
        p->entries[i] = p->entries[i + 1];
    p->entries[p->count - 1] = NULL;
    p->count--;
}

void pool_destroy(struct buffer_pool *p) {
    if (!p) return;
    for (int i = 0; i < p->count; i++)
        free(p->entries[i]);
    free(p->entries);
    free(p);
}
