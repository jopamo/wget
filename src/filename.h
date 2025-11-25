/* Path helpers derived from gnulib functionality.  */
#ifndef WGET_FILENAME_H
#define WGET_FILENAME_H

#include <stddef.h>

#define ISSLASH(C) ((C) == '/')

static inline size_t FILE_SYSTEM_PREFIX_LEN(const char* name) {
  (void)name;
  return 0;
}

char* last_component(char* path);

#endif /* WGET_FILENAME_H */
