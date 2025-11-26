/* Minimal basename/dirname helpers
 * src/path.c
 */

#include "wget.h"
#include "dirname.h"
#include "filename.h"

#include <string.h>

char* last_component(char* path) {
  if (!path || !*path)
    return path;

  char* p = path;
  char* last = path;

  while (*p) {
    if (*p == '/') {
      while (*p == '/')
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
  while (*end > start && (*end)[-1] == '/')
    --(*end);
}

char* base_name(const char* path) {
  if (!path || !*path)
    return xstrdup(".");

  const char* start = path;
  const char* end = path + strlen(path);

  strip_trailing_slashes(start, &end);

  /* path was all slashes */
  if (end == start)
    return xstrdup("/");

  const char* last = end;
  while (last > start && last[-1] != '/')
    --last;

  return xstrndup(last, (size_t)(end - last));
}

char* dir_name(const char* path) {
  if (!path || !*path)
    return xstrdup(".");

  const char* start = path;
  const char* end = path + strlen(path);

  strip_trailing_slashes(start, &end);

  /* path was all slashes */
  if (end == start)
    return xstrdup("/");

  /* strip final component */
  while (end > start && end[-1] != '/')
    --end;

  /* drop any extra slashes from the directory portion */
  strip_trailing_slashes(start, &end);

  /* no directory component, just a name */
  if (end == start)
    return xstrdup(".");

  return xstrndup(path, (size_t)(end - path));
}
