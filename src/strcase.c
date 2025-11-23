/* Case insensitive helpers replacing gnulib pieces.
 * src/strcase.c
 */

#include "wget.h"
#include "c-strcase.h"
#include "c-strcasestr.h"

#include <string.h>

int c_strcasecmp(const char* a, const char* b) {
  unsigned char ca, cb;
  while (*a && *b) {
    ca = (unsigned char)*a++;
    cb = (unsigned char)*b++;
    int diff = c_tolower(ca) - c_tolower(cb);
    if (diff)
      return diff;
  }
  return c_tolower((unsigned char)*a) - c_tolower((unsigned char)*b);
}

int c_strncasecmp(const char* a, const char* b, size_t n) {
  while (n--) {
    unsigned char ca = (unsigned char)*a++;
    unsigned char cb = (unsigned char)*b++;
    int diff = c_tolower(ca) - c_tolower(cb);
    if (diff || !ca || !cb)
      return diff;
  }
  return 0;
}

char* c_strcasestr(const char* haystack, const char* needle) {
  if (!*needle)
    return (char*)haystack;

  size_t needle_len = strlen(needle);
  for (; *haystack; ++haystack) {
    if (c_tolower((unsigned char)*haystack) == c_tolower((unsigned char)*needle)) {
      if (c_strncasecmp(haystack, needle, needle_len) == 0)
        return (char*)haystack;
    }
  }
  return NULL;
}
