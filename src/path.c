/* Minimal basename/dirname helpers.  */

#include "wget.h"
#include "utils.h"
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

static bool segment_is_dot(const char* segment) {
  return segment[0] == '.' && segment[1] == '\0';
}

static bool segment_is_dotdot(const char* segment) {
  return segment[0] == '.' && segment[1] == '.' && segment[2] == '\0';
}

char* canonicalize_path(const char* path) {
  if (!path || !*path)
    return xstrdup(".");

  size_t prefix_len = FILE_SYSTEM_PREFIX_LEN(path);
  char* scratch = xstrdup(path);
#ifdef WINDOWS
  for (char* p = scratch; *p; ++p) {
    if (*p == '\\')
      *p = '/';
  }
#endif

  bool absolute = scratch[0] && ISSLASH(scratch[0]);
#ifdef WINDOWS
  if (!absolute && prefix_len >= 3 && scratch[1] == ':' && ISSLASH(scratch[2]))
    absolute = true;
#endif

  char* cursor = scratch + prefix_len;
  while (*cursor && ISSLASH(*cursor))
    ++cursor;

  size_t comp_cap = strlen(cursor) + 1;
  if (comp_cap == 0)
    comp_cap = 1;
  char** components = xcalloc(comp_cap, sizeof(char*));
  size_t comp_count = 0;

  while (*cursor) {
    while (ISSLASH(*cursor))
      ++cursor;
    if (!*cursor)
      break;

    char* start = cursor;
    while (*cursor && !ISSLASH(*cursor))
      ++cursor;
    if (*cursor)
      *cursor++ = '\0';

    if (segment_is_dot(start))
      continue;
    if (segment_is_dotdot(start)) {
      if (comp_count > 0 && !segment_is_dotdot(components[comp_count - 1])) {
        --comp_count;
        continue;
      }
      if (!absolute)
        components[comp_count++] = start;
      continue;
    }
    components[comp_count++] = start;
  }

  bool prefix_has_slash = prefix_len > 0 && ISSLASH(scratch[prefix_len - 1]);

  size_t alloc_len = strlen(path) + 2;
  char* result = xmalloc(alloc_len);
  char* out = result;

  if (prefix_len > 0) {
    memcpy(out, scratch, prefix_len);
    out += prefix_len;
  }

  if (absolute && !(out > result && ISSLASH(out[-1]))) {
    *out++ = '/';
    prefix_has_slash = true;
  }

  if (comp_count == 0) {
    if (!absolute && prefix_len == 0)
      *out++ = '.';
    *out = '\0';
    xfree(components);
    xfree(scratch);
    return result;
  }

  bool skip_first_sep = (prefix_len > 0 && !absolute && !prefix_has_slash);
  for (size_t i = 0; i < comp_count; ++i) {
    if (!(i == 0 && skip_first_sep)) {
      if (out != result && !ISSLASH(out[-1]))
        *out++ = '/';
    }
    size_t seg_len = strlen(components[i]);
    memcpy(out, components[i], seg_len);
    out += seg_len;
  }
  *out = '\0';

  xfree(components);
  xfree(scratch);
  return result;
}
