/* Helper glue translating sockets and timers into libev primitives
 * src/evhelpers.c
 */

#include "wget.h"

#include <errno.h>
#include <ev.h>
#include <stdbool.h>

#include "evhelpers.h"
#include "evloop.h"
#include "threading.h"
struct wget_ev_sleep_ctx {
  ev_timer timer;
#if WGET_EVLOOP_CONTINUOUS
  wget_mutex_t lock;
  wget_cond_t cond;
#endif
  bool done;
};

static void wget_ev_sleep_cb(EV_P_ ev_timer* w, int revents WGET_ATTR_UNUSED) {
  struct wget_ev_sleep_ctx* ctx = w->data;
  ev_timer_stop(EV_A_ w);
#if WGET_EVLOOP_CONTINUOUS
  wget_mutex_lock(&ctx->lock);
  ctx->done = true;
  wget_cond_broadcast(&ctx->cond);
  wget_mutex_unlock(&ctx->lock);
#else
  ctx->done = true;
#endif
}

void wget_ev_sleep(double seconds) {
  if (seconds <= 0)
    return;

#if WGET_EVLOOP_CONTINUOUS
  struct wget_ev_sleep_ctx ctx;
  xzero(ctx);
  wget_mutex_init(&ctx.lock);
  wget_cond_init(&ctx.cond);

  struct ev_loop* loop = wget_ev_loop_get();
  ev_timer_init(&ctx.timer, wget_ev_sleep_cb, seconds, 0);
  ctx.timer.data = &ctx;
  ev_timer_start(loop, &ctx.timer);

  wget_mutex_lock(&ctx.lock);
  while (!ctx.done)
    wget_cond_wait(&ctx.cond, &ctx.lock);
  wget_mutex_unlock(&ctx.lock);

  wget_cond_destroy(&ctx.cond);
  wget_mutex_destroy(&ctx.lock);
#else
  struct wget_ev_sleep_ctx ctx;
  xzero(ctx);
  ctx.done = false;

  struct ev_loop* loop = wget_ev_loop_get();
  ev_timer_init(&ctx.timer, wget_ev_sleep_cb, seconds, 0);
  ctx.timer.data = &ctx;
  ev_timer_start(loop, &ctx.timer);

  ev_run(loop, EVRUN_NOWAIT);
  while (!ctx.done) {
    ev_run(loop, EVRUN_ONCE);
    ev_run(loop, EVRUN_NOWAIT);
  }
#endif
}
