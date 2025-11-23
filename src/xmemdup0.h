/* NUL-terminating memory duplication helper
 * src/xmemdup0.h
 */

#ifndef WGET_XMEMDUP0_H
#define WGET_XMEMDUP0_H

#include <stddef.h>

char* xmemdup0(const void* src, size_t n);

#endif /* WGET_XMEMDUP0_H */
