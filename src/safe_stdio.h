/* Safe stdio wrappers replacing gnulib helpers.
 * src/safe_stdio.h
 */

#ifndef WGET_SAFE_STDIO_H
#define WGET_SAFE_STDIO_H

#include <stdbool.h>
#include <stdio.h>

FILE* wget_safe_fopen(const char* path, const char* mode);
FILE* wget_safe_fdopen(int fd, const char* mode);
int wget_flush_stream(FILE* stream);
int wget_close_stream(FILE* stream);
bool wget_fwrite_all(FILE* stream, const void* data, size_t len);

#endif /* WGET_SAFE_STDIO_H */
