/* Minimal allocation helpers that abort on OOM.  */
#ifndef WGET_XALLOC_H
#define WGET_XALLOC_H

#include <stddef.h>

void xalloc_die(const char* context, size_t amount);
void* xmalloc(size_t n);
void* xcalloc(size_t count, size_t size);
void* xrealloc(void* ptr, size_t n);
char* xstrdup(const char* s);
char* xstrndup(const char* s, size_t n);
void* xmemdup(const void* src, size_t n);
char* xmemdup0(const void* src, size_t n);

#endif /* WGET_XALLOC_H */
