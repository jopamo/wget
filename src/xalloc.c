/* Replacement for gnulib xalloc helpers.
 * src/xalloc.c
 */

#include "wget.h"
#include "exits.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void ensure_allocation_possible(size_t count, size_t size, const char* context) {
  if (count && size > SIZE_MAX / count)
    xalloc_die(context, SIZE_MAX);
}

void xalloc_die(const char* context, size_t amount) {
  const char* what = context ? context : "xalloc";
  if (!exec_name)
    exec_name = "wget";
  logprintf(LOG_ALWAYS, _("%s: %s: Failed to allocate %zu bytes; memory exhausted.\n"), exec_name, what, amount);
  exit(WGET_EXIT_GENERIC_ERROR);
}

void* xmalloc(size_t n) {
  if (n == 0)
    n = 1;
  void* ptr = malloc(n);
  if (!ptr)
    xalloc_die("xmalloc", n);
  return ptr;
}

void* xcalloc(size_t count, size_t size) {
  ensure_allocation_possible(count, size, "xcalloc");
  if (count == 0 || size == 0)
    ++count;
  void* ptr = calloc(count, size);
  if (!ptr)
    xalloc_die("xcalloc", count * size);
  return ptr;
}

void* xrealloc(void* ptr, size_t n) {
  if (n == 0)
    n = 1;
  void* result = realloc(ptr, n);
  if (!result)
    xalloc_die("xrealloc", n);
  return result;
}

char* xstrdup(const char* s) {
  if (!s)
    s = "";
  size_t len = strlen(s) + 1;
  char* copy = xmalloc(len);
  memcpy(copy, s, len);
  return copy;
}

char* xstrndup(const char* s, size_t n) {
  if (!s)
    s = "";
  size_t len = strlen(s);
  if (len > n)
    len = n;
  char* copy = xmalloc(len + 1);
  memcpy(copy, s, len);
  copy[len] = '\0';
  return copy;
}

void* xmemdup(const void* src, size_t n) {
  void* copy = xmalloc(n ? n : 1);
  if (n)
    memcpy(copy, src, n);
  return copy;
}

char* xmemdup0(const void* src, size_t n) {
  char* copy = xmalloc(n + 1);
  if (n)
    memcpy(copy, src, n);
  copy[n] = '\0';
  return copy;
}
