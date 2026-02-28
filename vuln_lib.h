#ifndef VULN_LIB_H
#define VULN_LIB_H

#include <stddef.h>
#include <stdint.h>

/* Simple buffer operations library. */
int buffer_copy(char *dst, size_t dst_size, const char *src);
int buffer_concat(char *dst, size_t dst_size, const char *src);
char *buffer_alloc(size_t size);
void buffer_free(char *buf);

/* Parse a length-prefixed buffer: first 4 bytes = length (network byte order). */
int buffer_parse_length_prefixed(const char *input, size_t input_len,
                                  char *out, size_t out_size);

/* Buffer pool for managing multiple allocations. */
struct buffer_pool;
struct buffer_pool *pool_create(int capacity);
int pool_add(struct buffer_pool *p, const char *data, size_t len);
void pool_remove(struct buffer_pool *p, int index);
void pool_destroy(struct buffer_pool *p);

#endif /* VULN_LIB_H */
