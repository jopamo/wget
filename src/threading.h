/* Threading primitive declarations for GNU Wget
 * src/threading.h
 */

#ifndef WGET_THREADING_H
#define WGET_THREADING_H

#include "wget.h"

#include <pthread.h>
#include <stdbool.h>

typedef struct wget_mutex {
  pthread_mutex_t mutex;
  bool initialized;
} wget_mutex_t;

#define WGET_MUTEX_INITIALIZER {PTHREAD_MUTEX_INITIALIZER, false}

void wget_mutex_init(wget_mutex_t* mutex);
void wget_mutex_lock(wget_mutex_t* mutex);
void wget_mutex_unlock(wget_mutex_t* mutex);
void wget_mutex_destroy(wget_mutex_t* mutex);

#endif /* WGET_THREADING_H */
