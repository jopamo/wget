/* Tests for lock-free async postings into the event loop.
 * tests/evloop_async_test.c
 */

#include "config.h"

#include "evloop.h"
#include "threading.h"

#include <assert.h>
#include <stdatomic.h>

#if defined(HAVE_PTHREAD_H) && HAVE_PTHREAD_H
#include <pthread.h>
#else
#error "evloop_async_test requires pthread support"
#endif

#define MAIN_THREAD_POSTS 3
#define WORKER_THREAD_POSTS 5

struct async_state {
  atomic_int posted;
  atomic_int executed;
  wget_mutex_t lock;
  wget_cond_t cond;
};

static void async_cb(void* arg) {
  struct async_state* state = arg;
  atomic_fetch_add_explicit(&state->executed, 1, memory_order_relaxed);
  wget_mutex_lock(&state->lock);
  wget_cond_broadcast(&state->cond);
  wget_mutex_unlock(&state->lock);
}

static void* worker_thread(void* arg) {
  struct async_state* state = arg;
  for (int i = 0; i < WORKER_THREAD_POSTS; ++i) {
    if (!wget_ev_loop_post_async(async_cb, state))
      return (void*)1;
  }
  atomic_fetch_add_explicit(&state->posted, WORKER_THREAD_POSTS, memory_order_release);
  return NULL;
}

int main(void) {
  struct async_state state = {
    .posted = ATOMIC_VAR_INIT(0),
    .executed = ATOMIC_VAR_INIT(0),
    .lock = WGET_MUTEX_INITIALIZER,
    .cond = WGET_COND_INITIALIZER,
  };
  const int expected = MAIN_THREAD_POSTS + WORKER_THREAD_POSTS;

  wget_mutex_init(&state.lock);
  wget_cond_init(&state.cond);

  wget_ev_loop_get();
  for (int i = 0; i < MAIN_THREAD_POSTS; ++i) {
    if (!wget_ev_loop_post_async(async_cb, &state))
      return 1;
  }
  atomic_fetch_add_explicit(&state.posted, MAIN_THREAD_POSTS, memory_order_release);

  pthread_t thread;
  int err = pthread_create(&thread, NULL, worker_thread, &state);
  if (err != 0)
    return 1;

  wget_mutex_lock(&state.lock);
  while (atomic_load_explicit(&state.executed, memory_order_acquire) < expected)
    wget_cond_wait(&state.cond, &state.lock);
  wget_mutex_unlock(&state.lock);

  pthread_join(thread, NULL);
  wget_cond_destroy(&state.cond);
  wget_mutex_destroy(&state.lock);

  assert(atomic_load_explicit(&state.posted, memory_order_acquire) == expected);
  assert(atomic_load_explicit(&state.executed, memory_order_acquire) == expected);

  return 0;
}
