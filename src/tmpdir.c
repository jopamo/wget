/* Determine a temporary directory path for use with mkstemp-like helpers.
   Based on the gnulib tmpdir module.
   Copyright (C) 1999, 2001-2002, 2006, 2009-2025
   Free Software Foundation, Inc.

   This file is free software: you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   This file is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this file.  If not, see <https://www.gnu.org/licenses/>.  */

#include "config.h"

#include "tmpdir.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef P_tmpdir
#ifdef _P_tmpdir
#define P_tmpdir _P_tmpdir
#else
#define P_tmpdir "/tmp"
#endif
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define IS_DIR_SEPARATOR(C) ((C) == '/')

static bool direxists(const char* dir) {
  struct stat st;
  return dir && stat(dir, &st) == 0 && S_ISDIR(st.st_mode);
}

static const char* tmpdir_from_env(void) {
#if defined HAVE_SECURE_GETENV
  const char* dir = secure_getenv("TMPDIR");
#elif defined HAVE___SECURE_GETENV
  const char* dir = __secure_getenv("TMPDIR");
#else
  const char* dir = getenv("TMPDIR");
#endif
  if (dir && *dir)
    return dir;
  return NULL;
}

int path_search(char* tmpl, size_t tmpl_len, const char* dir, const char* pfx, bool try_tmpdir) {
  const char* chosen = dir;
  size_t plen;

  if (tmpl == NULL || tmpl_len == 0) {
    errno = EINVAL;
    return -1;
  }

  if (pfx == NULL || !pfx[0]) {
    pfx = "file";
    plen = 4;
  }
  else {
    plen = strlen(pfx);
    if (plen > 5)
      plen = 5;
  }

  if (try_tmpdir) {
    const char* env_dir = tmpdir_from_env();
    if (env_dir && direxists(env_dir))
      chosen = env_dir;
    else if (chosen && direxists(chosen))
      ; /* keep provided directory */
    else
      chosen = NULL;
  }

  if (chosen == NULL) {
    if (direxists(P_tmpdir))
      chosen = P_tmpdir;
    else if (strcmp(P_tmpdir, "/tmp") != 0 && direxists("/tmp"))
      chosen = "/tmp";
    else {
      errno = ENOENT;
      return -1;
    }
  }

  size_t dlen = strlen(chosen);
  bool add_slash = dlen != 0 && !IS_DIR_SEPARATOR(chosen[dlen - 1]);
  size_t needed = dlen + (add_slash ? 1 : 0) + plen + 6 + 1;
  if (tmpl_len < needed) {
    errno = EINVAL;
    return -1;
  }

  memcpy(tmpl, chosen, dlen);
  size_t offset = dlen;
  if (add_slash)
    tmpl[offset++] = '/';

  snprintf(tmpl + offset, tmpl_len - offset, "%.*sXXXXXX", (int)plen, pfx);
  return 0;
}
