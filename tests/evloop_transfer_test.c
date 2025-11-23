/* Tests for transfer-aware evloop helpers.
 * tests/evloop_transfer_test.c
 */

#include "evloop.h"

#include <assert.h>
#include <ev.h>

static void unref_cb(EV_P_ ev_timer* w, int revents) {
  (void)revents;
  int* counter = w->data;
  ++(*counter);
  wget_ev_loop_transfer_unref();
  ev_timer_stop(EV_A_ w);
}

int main(void) {
  struct ev_loop* loop = wget_ev_loop_get();
  ev_timer timers[2];
  int fired = 0;

  for (int i = 0; i < 2; ++i) {
    ev_timer_init(&timers[i], unref_cb, 0.01 * (i + 1), 0.0);
    timers[i].data = &fired;
    wget_ev_loop_transfer_ref();
    ev_timer_start(loop, &timers[i]);
  }

  assert(wget_ev_loop_has_active_transfers());
  wget_ev_loop_run_transfers();
  assert(!wget_ev_loop_has_active_transfers());
  assert(fired == 2);

  /* With no active transfers, run_transfers should return immediately. */
  double before = ev_now(loop);
  wget_ev_loop_run_transfers();
  double after = ev_now(loop);
  assert(after - before < 0.01);

  return 0;
}
