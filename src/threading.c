/* Threading primitive implementation for GNU Wget.
 * src/threading.c
 *
 * Copyright (C) 2024 Free Software Foundation, Inc.
 *
 * This file is part of GNU Wget.
 *
 * GNU Wget is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNU Wget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Wget.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "threading.h"
#include "evloop.h"
#include "utils.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#if defined HAVE_PTHREAD_H && HAVE_PTHREAD_H

static pthread_mutex_t pthread_init_lock = PTHREAD_MUTEX_INITIALIZER;

static void pthread_mutex_lazy_init(wget_mutex_t* mutex) {
  if (mutex->initialized)
    return;

  pthread_mutex_lock(&pthread_init_lock);
  if (!mutex->initialized) {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
#ifdef PTHREAD_MUTEX_RECURSIVE
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
#endif
    pthread_mutex_init(&mutex->mutex, &attr);
    pthread_mutexattr_destroy(&attr);
    mutex->initialized = true;
  }
  pthread_mutex_unlock(&pthread_init_lock);
}

void wget_mutex_init(wget_mutex_t* mutex) {
  mutex->initialized = false;
}

void wget_mutex_lock(wget_mutex_t* mutex) {
  pthread_mutex_lazy_init(mutex);
  pthread_mutex_lock(&mutex->mutex);
}

void wget_mutex_unlock(wget_mutex_t* mutex) {
  if (mutex->initialized)
    pthread_mutex_unlock(&mutex->mutex);
}

void wget_mutex_destroy(wget_mutex_t* mutex) {
  if (mutex->initialized) {
    pthread_mutex_destroy(&mutex->mutex);
    mutex->initialized = false;
  }
}

#else

void wget_mutex_init(wget_mutex_t* mutex WGET_ATTR_UNUSED) {}
void wget_mutex_lock(wget_mutex_t* mutex WGET_ATTR_UNUSED) {}
void wget_mutex_unlock(wget_mutex_t* mutex WGET_ATTR_UNUSED) {}
void wget_mutex_destroy(wget_mutex_t* mutex WGET_ATTR_UNUSED) {}

#endif

void wget_async_mailbox_init(wget_async_mailbox_t* mailbox) {
  if (!mailbox)
    return;
  atomic_store_explicit(&mailbox->head, (uintptr_t)NULL, memory_order_relaxed);
}

void wget_async_mailbox_push(wget_async_mailbox_t* mailbox, wget_async_task_t* task) {
  if (!mailbox || !task)
    return;

  uintptr_t head = atomic_load_explicit(&mailbox->head, memory_order_relaxed);
  do {
    task->next = (wget_async_task_t*)head;
  } while (!atomic_compare_exchange_weak_explicit(&mailbox->head, &head, (uintptr_t)task, memory_order_release, memory_order_relaxed));
}

wget_async_task_t* wget_async_mailbox_acquire_all(wget_async_mailbox_t* mailbox) {
  if (!mailbox)
    return NULL;
  uintptr_t head = atomic_exchange_explicit(&mailbox->head, (uintptr_t)NULL, memory_order_acquire);
  return (wget_async_task_t*)head;
}

wget_async_task_t* wget_async_mailbox_reverse(wget_async_task_t* head) {
  wget_async_task_t* prev = NULL;
  while (head) {
    wget_async_task_t* next = head->next;
    head->next = prev;
    prev = head;
    head = next;
  }
  return prev;
}

bool wget_async_mailbox_is_empty(const wget_async_mailbox_t* mailbox) {
  if (!mailbox)
    return true;
  return atomic_load_explicit(&mailbox->head, memory_order_acquire) == (uintptr_t)NULL;
}

#if defined HAVE_PTHREAD_H && HAVE_PTHREAD_H

typedef struct wget_worker_job {
  struct wget_worker_job* next;
  wget_worker_work_fn work;
  wget_worker_complete_fn complete;
  void* arg;
} wget_worker_job_t;

static struct {
  pthread_t* threads;
  size_t thread_count;
  wget_worker_job_t* head;
  wget_worker_job_t* tail;
  pthread_mutex_t lock;
  pthread_cond_t cond;
  bool running;
  bool initialized;
} worker_pool = {
    .threads = NULL,
    .thread_count = 0,
    .head = NULL,
    .tail = NULL,
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER,
    .running = false,
    .initialized = false,
};

static void wget_worker_job_complete_trampoline(void* arg) {
  wget_worker_job_t* job = (wget_worker_job_t*)arg;
  if (job->complete)
    job->complete(job->arg);
  xfree(job);
}

static void* wget_worker_thread_main(void* arg WGET_ATTR_UNUSED) {
  while (1) {
    wget_worker_job_t* job = NULL;
    pthread_mutex_lock(&worker_pool.lock);
    while (worker_pool.running && worker_pool.head == NULL)
      pthread_cond_wait(&worker_pool.cond, &worker_pool.lock);
    if (!worker_pool.running && worker_pool.head == NULL) {
      pthread_mutex_unlock(&worker_pool.lock);
      break;
    }
    job = worker_pool.head;
    worker_pool.head = job ? job->next : NULL;
    if (!worker_pool.head)
      worker_pool.tail = NULL;
    pthread_mutex_unlock(&worker_pool.lock);
    if (!job)
      continue;
    if (job->work)
      job->work(job->arg);
    if (job->complete) {
      if (!wget_ev_loop_post_async(wget_worker_job_complete_trampoline, job))
        wget_worker_job_complete_trampoline(job);
    }
    else
      xfree(job);
  }
  return NULL;
}

static unsigned int wget_worker_default_threads(unsigned int desired) {
  if (desired)
    return desired;
  long cpus = 1;
#ifdef _SC_NPROCESSORS_ONLN
  cpus = sysconf(_SC_NPROCESSORS_ONLN);
#endif
  if (cpus < 1)
    cpus = 1;
  if (cpus > 32)
    cpus = 32;
  return (unsigned int)cpus;
}

bool wget_worker_pool_init(unsigned int desired_workers) {
  if (worker_pool.initialized)
    return true;

  worker_pool.thread_count = wget_worker_default_threads(desired_workers);
  worker_pool.threads = xcalloc(worker_pool.thread_count, sizeof(*worker_pool.threads));
  worker_pool.running = true;

  for (size_t i = 0; i < worker_pool.thread_count; ++i) {
    if (pthread_create(&worker_pool.threads[i], NULL, wget_worker_thread_main, NULL) != 0) {
      worker_pool.thread_count = i;
      worker_pool.running = false;
      goto fail;
    }
  }

  worker_pool.initialized = true;
  return true;

fail:
  for (size_t i = 0; i < worker_pool.thread_count; ++i)
    pthread_join(worker_pool.threads[i], NULL);
  xfree(worker_pool.threads);
  worker_pool.threads = NULL;
  worker_pool.thread_count = 0;
  return false;
}

bool wget_worker_pool_available(void) {
  return worker_pool.initialized;
}

bool wget_worker_pool_submit(wget_worker_work_fn work, wget_worker_complete_fn complete, void* arg) {
  if (!worker_pool.initialized || !work)
    return false;

  wget_worker_job_t* job = xcalloc(1, sizeof(*job));
  job->work = work;
  job->complete = complete;
  job->arg = arg;

  pthread_mutex_lock(&worker_pool.lock);
  if (worker_pool.tail)
    worker_pool.tail->next = job;
  else
    worker_pool.head = job;
  worker_pool.tail = job;
  pthread_cond_signal(&worker_pool.cond);
  pthread_mutex_unlock(&worker_pool.lock);

  return true;
}

void wget_worker_pool_shutdown(void) {
  if (!worker_pool.initialized)
    return;

  pthread_mutex_lock(&worker_pool.lock);
  worker_pool.running = false;
  pthread_cond_broadcast(&worker_pool.cond);
  pthread_mutex_unlock(&worker_pool.lock);

  for (size_t i = 0; i < worker_pool.thread_count; ++i)
    pthread_join(worker_pool.threads[i], NULL);

  pthread_mutex_lock(&worker_pool.lock);
  while (worker_pool.head) {
    wget_worker_job_t* job = worker_pool.head;
    worker_pool.head = job->next;
    xfree(job);
  }
  worker_pool.tail = NULL;
  pthread_mutex_unlock(&worker_pool.lock);

  xfree(worker_pool.threads);
  worker_pool.threads = NULL;
  worker_pool.thread_count = 0;
  worker_pool.head = worker_pool.tail = NULL;
  worker_pool.initialized = false;
}

#else

bool wget_worker_pool_init(unsigned int desired_workers WGET_ATTR_UNUSED) {
  return false;
}

void wget_worker_pool_shutdown(void) {}

bool wget_worker_pool_submit(wget_worker_work_fn work WGET_ATTR_UNUSED, wget_worker_complete_fn complete WGET_ATTR_UNUSED, void* arg WGET_ATTR_UNUSED) {
  return false;
}

bool wget_worker_pool_available(void) {
  return false;
}

#endif
