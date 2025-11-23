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

#if defined(WINDOWS)

static BOOL CALLBACK mutex_init_once(PINIT_ONCE once WGET_ATTR_UNUSED, PVOID param, PVOID* ctx WGET_ATTR_UNUSED) {
  wget_mutex_t* mutex = (wget_mutex_t*)param;
  InitializeCriticalSection(&mutex->cs);
  mutex->initialized = true;
  return TRUE;
}

void wget_mutex_init(wget_mutex_t* mutex) {
  mutex->once = INIT_ONCE_STATIC_INIT;
  mutex->initialized = false;
}

void wget_mutex_lock(wget_mutex_t* mutex) {
  InitOnceExecuteOnce(&mutex->once, mutex_init_once, mutex, NULL);
  EnterCriticalSection(&mutex->cs);
}

void wget_mutex_unlock(wget_mutex_t* mutex) {
  if (mutex->initialized)
    LeaveCriticalSection(&mutex->cs);
}

void wget_mutex_destroy(wget_mutex_t* mutex) {
  if (mutex->initialized) {
    DeleteCriticalSection(&mutex->cs);
    mutex->initialized = false;
    mutex->once = INIT_ONCE_STATIC_INIT;
  }
}

#elif defined HAVE_PTHREAD_H && HAVE_PTHREAD_H

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
