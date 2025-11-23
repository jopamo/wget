/* Safe stdio helpers replacing gnulib's close-stream wrappers.  */

#include "wget.h"
#include "safe_stdio.h"

#include <errno.h>
#include <string.h>

FILE* wget_safe_fopen(const char* path, const char* mode) {
  if (!path || !mode) {
    errno = EINVAL;
    return NULL;
  }
  return fopen(path, mode);
}

FILE* wget_safe_fdopen(int fd, const char* mode) {
  if (fd < 0 || !mode) {
    errno = EINVAL;
    return NULL;
  }
  return fdopen(fd, mode);
}

int wget_flush_stream(FILE* stream) {
  if (!stream)
    return 0;
  if (fflush(stream) == EOF) {
    if (errno == 0)
      errno = EIO;
    return -1;
  }
  if (ferror(stream)) {
    errno = EIO;
    return -1;
  }
  return 0;
}

int wget_close_stream(FILE* stream) {
  if (!stream)
    return 0;

  int saved_errno = 0;
  if (fflush(stream) == EOF)
    saved_errno = errno ? errno : EIO;
  else if (ferror(stream))
    saved_errno = EIO;

  if (fclose(stream) == EOF && saved_errno == 0)
    saved_errno = errno ? errno : EIO;

  if (saved_errno != 0) {
    errno = saved_errno;
    return -1;
  }
  return 0;
}

bool wget_fwrite_all(FILE* stream, const void* data, size_t len) {
  if (!stream || (!data && len != 0))
    return false;

  const unsigned char* bytes = data;
  size_t written = 0;

  while (written < len) {
    size_t chunk = fwrite(bytes + written, 1, len - written, stream);
    if (chunk == 0) {
      if (ferror(stream)) {
        errno = EIO;
        return false;
      }
      if (feof(stream))
        return false;
    }
    written += chunk;
  }
  return true;
}
