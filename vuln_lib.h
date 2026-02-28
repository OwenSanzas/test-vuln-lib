#ifndef VULN_LIB_H
#define VULN_LIB_H

#include <stddef.h>

/*/* Simple buffer operations library. */
int buffer_copy(char *dst, size_t dst_size, const char *src);
int buffer_concat(char *dst, size_t dst_size, const char *src);
char *buffer_alloc(size_t size);
void buffer_free(char *buf);

#endif /* VULN_LIB_H */

/* Parse a length-prefixed buffer: first 4 bytes = length (network byte order) */
int buffer_parse_length_prefixed(const char *input, size_t input_len,
                                  char *out, size_t out_size);
