/* Tests for the pthread-backed worker pool dispatch path.
 * tests/worker_pool_test.c
 */

#include "config.h"

#include "threading.h"
#include "evloop.h"

#include <assert.h>
#include <stdatomic.h>

#if defined(HAVE_PTHREAD_H) && HAVE_PTHREAD_H
#include <pthread.h>
#else
#error "worker_pool_test requires pthread support"
#endif

#define JOB_COUNT 8

struct worker_state {
  atomic_int work_calls;
  atomic_int completion_calls;
  pthread_t main_thread;
  wget_mutex_t lock;
  wget_cond_t cond;
};

static void worker_job(void* arg) {
  struct worker_state* state = arg;
  atomic_fetch_add_explicit(&state->work_calls, 1, memory_order_relaxed);
}

static void worker_complete(void* arg) {
  struct worker_state* state = arg;
  atomic_fetch_add_explicit(&state->completion_calls, 1, memory_order_relaxed);
  wget_mutex_lock(&state->lock);
  wget_cond_broadcast(&state->cond);
  wget_mutex_unlock(&state->lock);
}

int main(void) {
  struct worker_state state = {
      .work_calls = ATOMIC_VAR_INIT(0),
      .completion_calls = ATOMIC_VAR_INIT(0),
      .main_thread = pthread_self(),
      .lock = WGET_MUTEX_INITIALIZER,
      .cond = WGET_COND_INITIALIZER,
  };

  wget_mutex_init(&state.lock);
  wget_cond_init(&state.cond);

  if (wget_worker_pool_available())
    return 1;
  if (!wget_worker_pool_init(0))
    return 1;
  if (!wget_worker_pool_available())
    return 1;

  wget_ev_loop_get();

  for (int i = 0; i < JOB_COUNT; ++i) {
    if (!wget_worker_pool_submit(worker_job, worker_complete, &state))
      return 1;
  }

  wget_mutex_lock(&state.lock);
  while (atomic_load_explicit(&state.completion_calls, memory_order_acquire) < JOB_COUNT)
    wget_cond_wait(&state.cond, &state.lock);
  wget_mutex_unlock(&state.lock);

  if (atomic_load_explicit(&state.work_calls, memory_order_acquire) != JOB_COUNT)
    return 1;
  if (atomic_load_explicit(&state.completion_calls, memory_order_acquire) != JOB_COUNT)
    return 1;

  wget_worker_pool_shutdown();
  if (wget_worker_pool_available())
    return 1;

  wget_cond_destroy(&state.cond);
  wget_mutex_destroy(&state.lock);
  return 0;
}
