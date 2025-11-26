/* Threading primitive implementation for GNU Wget
 * src/threading.c
 */

#include "threading.h"

#include <pthread.h>
#include <errno.h>
#include <stdlib.h>

static pthread_mutex_t pthread_init_lock = PTHREAD_MUTEX_INITIALIZER;

static void pthread_mutex_lazy_init(wget_mutex_t* mutex) {
  if (mutex->initialized)
    return;

  int err = pthread_mutex_lock(&pthread_init_lock);
  if (err)
    abort();

  if (!mutex->initialized) {
    pthread_mutexattr_t attr;

    err = pthread_mutexattr_init(&attr);
    if (err) {
      pthread_mutex_unlock(&pthread_init_lock);
      abort();
    }

    err = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    if (err) {
      pthread_mutexattr_destroy(&attr);
      pthread_mutex_unlock(&pthread_init_lock);
      abort();
    }

    err = pthread_mutex_init(&mutex->mutex, &attr);
    pthread_mutexattr_destroy(&attr);
    if (err) {
      pthread_mutex_unlock(&pthread_init_lock);
      abort();
    }

    mutex->initialized = true;
  }

  err = pthread_mutex_unlock(&pthread_init_lock);
  if (err)
    abort();
}

void wget_mutex_init(wget_mutex_t* mutex) {
  mutex->initialized = false;
}

void wget_mutex_lock(wget_mutex_t* mutex) {
  pthread_mutex_lazy_init(mutex);

  int err = pthread_mutex_lock(&mutex->mutex);
  if (err)
    abort();
}

void wget_mutex_unlock(wget_mutex_t* mutex) {
  if (!mutex->initialized)
    return;

  int err = pthread_mutex_unlock(&mutex->mutex);
  if (err)
    abort();
}

void wget_mutex_destroy(wget_mutex_t* mutex) {
  if (!mutex->initialized)
    return;

  int err = pthread_mutex_destroy(&mutex->mutex);
  if (err)
    abort();

  mutex->initialized = false;
}
