/* Path helpers derived from gnulib functionality.
 * src/filename.h
 */

#ifndef WGET_FILENAME_H
#define WGET_FILENAME_H

#include <stddef.h>

#ifdef WINDOWS
#define ISSLASH(C) ((C) == '/' || (C) == '\\')
#else
#define ISSLASH(C) ((C) == '/')
#endif

static inline size_t FILE_SYSTEM_PREFIX_LEN(const char* name) {
#ifdef WINDOWS
  if (!name)
    return 0;
  if (((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z')) && name[1] == ':' && ISSLASH(name[2]))
    return 3;
  if (ISSLASH(name[0]) && ISSLASH(name[1])) {
    const char* p = name + 2;
    while (*p && !ISSLASH(*p))
      ++p;
    while (*p && ISSLASH(*p))
      ++p;
    while (*p && !ISSLASH(*p))
      ++p;
    return p - name;
  }
  if (((name[0] >= 'a' && name[0] <= 'z') || (name[0] >= 'A' && name[0] <= 'Z')) && name[1] == ':')
    return 2;
#else
  (void)name;
#endif
  return 0;
}

char* last_component(char* path);

#endif /* WGET_FILENAME_H */
