#include "vuln_lib.h"
#include <stdlib.h>
#include <string.h>

int buffer_copy(char *dst, size_t dst_size, const char *src) {
    if (!dst || !src) return -1;
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
    return (char *)malloc(size);
}

void buffer_free(char *buf) {
    free(buf);
}
