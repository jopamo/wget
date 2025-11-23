/* Minimal basename/dirname helpers.  */

#include "wget.h"
#include "dirname.h"
#include "filename.h"

#include <string.h>

char* last_component(char* path) {
  if (!path)
    return NULL;

  char* p = path;
  size_t prefix = FILE_SYSTEM_PREFIX_LEN(path);
  p += prefix;

  char* last = p;
  while (*p) {
    if (ISSLASH(*p)) {
      while (ISSLASH(*p))
        ++p;
      if (*p)
        last = p;
      continue;
    }
    ++p;
  }
  return last;
}

static void strip_trailing_slashes(const char* start, const char** end) {
  while (*end > start && ISSLASH((*end)[-1]))
    --(*end);
}

char* base_name(const char* path) {
  if (!path || !*path)
    return xstrdup(".");

  const char* start = path + FILE_SYSTEM_PREFIX_LEN(path);
  const char* end = path + strlen(path);
  strip_trailing_slashes(start, &end);

  const char* last = end;
  while (last > start && !ISSLASH(last[-1]))
    --last;

  if (last == start && FILE_SYSTEM_PREFIX_LEN(path) && !*last)
    return xstrdup(path);

  if (last == end && ISSLASH(*last))
    return xstrdup("/");

  return xstrndup(last, (size_t)(end - last));
}

char* dir_name(const char* path) {
  if (!path || !*path)
    return xstrdup(".");

  const char* start = path + FILE_SYSTEM_PREFIX_LEN(path);
  const char* end = path + strlen(path);
  strip_trailing_slashes(start, &end);

  while (end > start && !ISSLASH(end[-1]))
    --end;
  strip_trailing_slashes(start, &end);

  if (end == path)
    return xstrdup("/");
  if (end == start)
    return xstrdup(".");
  return xstrndup(path, (size_t)(end - path));
}
