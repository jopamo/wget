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
  atomic_int errors;
  pthread_t main_thread;
};

static void worker_job(void* arg) {
  struct worker_state* state = arg;
  atomic_fetch_add_explicit(&state->work_calls, 1, memory_order_relaxed);
}

static void worker_complete(void* arg) {
  struct worker_state* state = arg;
  /* Completion callbacks should always run inside the main loop thread. */
  if (!pthread_equal(pthread_self(), state->main_thread))
    atomic_fetch_add_explicit(&state->errors, 1, memory_order_relaxed);
  atomic_fetch_add_explicit(&state->completion_calls, 1, memory_order_relaxed);
}

int main(void) {
  struct worker_state state = {
      .work_calls = ATOMIC_VAR_INIT(0),
      .completion_calls = ATOMIC_VAR_INIT(0),
      .errors = ATOMIC_VAR_INIT(0),
      .main_thread = pthread_self(),
  };

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

  while (atomic_load_explicit(&state.completion_calls, memory_order_acquire) < JOB_COUNT)
    wget_ev_loop_run_once();

  if (atomic_load_explicit(&state.work_calls, memory_order_acquire) != JOB_COUNT)
    return 1;
  if (atomic_load_explicit(&state.completion_calls, memory_order_acquire) != JOB_COUNT)
    return 1;
  if (atomic_load_explicit(&state.errors, memory_order_acquire) != 0)
    return 1;

  wget_worker_pool_shutdown();
  if (wget_worker_pool_available())
    return 1;

  return 0;
}
