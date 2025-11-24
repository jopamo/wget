/* Stubs required by http_response tests.
 * tests/http_response_stubs.c
 */

#include "config.h"

#include "wget.h"

#include <errno.h>
#include <string.h>

#include "retr.h"
#include "utils.h"

char* fd_read_hunk(int fd WGET_ATTR_UNUSED, hunk_terminator_t terminator WGET_ATTR_UNUSED, long initial WGET_ATTR_UNUSED, long limit WGET_ATTR_UNUSED) {
  errno = ENOSYS;
  return NULL;
}

char* strdupdelim(const char* beg, const char* end) {
  if (beg && beg <= end) {
    size_t len = end - beg;
    char* copy = xmalloc(len + 1);
    memcpy(copy, beg, len);
    copy[len] = '\0';
    return copy;
  }

  return xstrdup("");
}
