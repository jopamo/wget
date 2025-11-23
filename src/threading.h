/* Simple cross-platform threading primitives used inside Wget.
   Copyright (C) 2024 Free Software Foundation, Inc.

   This file is part of GNU Wget.

   GNU Wget is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   GNU Wget is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with Wget.  If not, see <http://www.gnu.org/licenses/>.  */

#ifndef WGET_THREADING_H
#define WGET_THREADING_H

#include "wget.h"

#if defined HAVE_PTHREAD_H && HAVE_PTHREAD_H
#include <pthread.h>
#endif

typedef struct wget_mutex {
#if defined(WINDOWS)
  INIT_ONCE once;
  CRITICAL_SECTION cs;
  bool initialized;
#elif defined HAVE_PTHREAD_H && HAVE_PTHREAD_H
  pthread_mutex_t mutex;
  bool initialized;
#else
  int dummy;
#endif
} wget_mutex_t;

#if defined(WINDOWS)
#define WGET_MUTEX_INITIALIZER {INIT_ONCE_STATIC_INIT, {0}, false}
#elif defined HAVE_PTHREAD_H && HAVE_PTHREAD_H
#define WGET_MUTEX_INITIALIZER {{0}, false}
#else
#define WGET_MUTEX_INITIALIZER {0}
#endif

void wget_mutex_init(wget_mutex_t* mutex);
void wget_mutex_lock(wget_mutex_t* mutex);
void wget_mutex_unlock(wget_mutex_t* mutex);
void wget_mutex_destroy(wget_mutex_t* mutex);

#endif /* WGET_THREADING_H */
