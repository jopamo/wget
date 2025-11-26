/* Case insensitive comparison helpers
 * src/c-strcase.h
 */
#ifndef WGET_C_STRCASE_H
#define WGET_C_STRCASE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int c_strcasecmp(const char* a, const char* b);
int c_strncasecmp(const char* a, const char* b, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* WGET_C_STRCASE_H */
