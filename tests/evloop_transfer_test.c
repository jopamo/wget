/* Tests for transfer-aware evloop helpers.
 * tests/evloop_transfer_test.c
 */

#include "evloop.h"
#include "threading.h"

#include <assert.h>
#include <ev.h>

static wget_mutex_t fired_lock = WGET_MUTEX_INITIALIZER;
static wget_cond_t fired_cond = WGET_COND_INITIALIZER;

static void unref_cb(EV_P_ ev_timer* w, int revents) {
  (void)revents;
  int* counter = w->data;
  wget_mutex_lock(&fired_lock);
  ++(*counter);
  wget_cond_broadcast(&fired_cond);
  wget_mutex_unlock(&fired_lock);
  wget_ev_loop_transfer_unref();
  ev_timer_stop(EV_A_ w);
}

int main(void) {
  struct ev_loop* loop = wget_ev_loop_get();
  ev_timer timers[2];
  int fired = 0;

  wget_mutex_init(&fired_lock);
  wget_cond_init(&fired_cond);

  for (int i = 0; i < 2; ++i) {
    ev_timer_init(&timers[i], unref_cb, 0.01 * (i + 1), 0.0);
    timers[i].data = &fired;
    wget_ev_loop_transfer_ref();
    ev_timer_start(loop, &timers[i]);
  }

  assert(wget_ev_loop_has_active_transfers());
  wget_mutex_lock(&fired_lock);
  while (fired < 2)
    wget_cond_wait(&fired_cond, &fired_lock);
  wget_mutex_unlock(&fired_lock);
  assert(!wget_ev_loop_has_active_transfers());
  assert(fired == 2);

  /* With no active transfers, run_transfers should return immediately. */
  double before = ev_now(loop);
  wget_ev_loop_run_transfers();
  double after = ev_now(loop);
  assert(after - before < 0.01);

  wget_cond_destroy(&fired_cond);
  wget_mutex_destroy(&fired_lock);

  return 0;
}
