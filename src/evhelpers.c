/* Helper glue translating sockets and timers into libev primitives
 * src/evhelpers.c
 */

#include "wget.h"

#include <errno.h>
#include <ev.h>
#include <stdbool.h>

#include "connect.h"
#include "evhelpers.h"
#include "evloop.h"

struct fd_wait_ctx {
  ev_io io;
  ev_timer timer;
  int result;
  bool done;
  bool has_timer;
  bool timed_out;
};

static void fd_wait_io_cb(EV_P_ ev_io* w, int revents) {
  struct fd_wait_ctx* ctx = w->data;
  if (ctx->done)
    return;

  if (revents & EV_ERROR)
    ctx->result = -1;
  else
    ctx->result = 1;

  ctx->done = true;
  ev_io_stop(EV_A_ w);
  if (ctx->has_timer)
    ev_timer_stop(EV_A_ & ctx->timer);
}

static void fd_wait_timer_cb(EV_P_ ev_timer* w, int revents WGET_ATTR_UNUSED) {
  struct fd_wait_ctx* ctx = w->data;
  if (ctx->done)
    return;

  ctx->result = 0;
  ctx->timed_out = true;
  ctx->done = true;
  ev_timer_stop(EV_A_ w);
  ev_io_stop(EV_A_ & ctx->io);
}

/* LEGACY_BLOCKING: waits synchronously for readiness on a single fd. */
int wget_ev_io_wait(int fd, double maxtime, int wait_for) {
  if (fd < 0)
    return -1;

  int events = 0;
  if (wait_for & WAIT_FOR_READ)
    events |= EV_READ;
  if (wait_for & WAIT_FOR_WRITE)
    events |= EV_WRITE;
  if (!events) {
    errno = EINVAL;
    return -1;
  }

  struct fd_wait_ctx ctx;
  xzero(ctx);

  struct ev_loop* loop = wget_ev_loop_get();
  ev_io_init(&ctx.io, fd_wait_io_cb, fd, events);
  ctx.io.data = &ctx;
  ev_io_start(loop, &ctx.io);

  bool wait_forever = maxtime < 0;
  bool poll_only = maxtime == 0;

  if (!wait_forever && !poll_only) {
    ev_timer_init(&ctx.timer, fd_wait_timer_cb, maxtime, 0);
    ctx.timer.data = &ctx;
    ctx.has_timer = true;
    ev_timer_start(loop, &ctx.timer);
  }

  if (poll_only)
    ev_run(loop, EVRUN_NOWAIT);
  else {
    while (!ctx.done)
      ev_run(loop, EVRUN_ONCE);
  }

  if (!ctx.done)
    ctx.result = 0;

  ev_io_stop(loop, &ctx.io);
  if (ctx.has_timer)
    ev_timer_stop(loop, &ctx.timer);

  if (ctx.result == 0 && ctx.timed_out)
    errno = ETIMEDOUT;
  return ctx.result;
}

struct wget_ev_sleep_ctx {
  ev_timer timer;
  bool done;
};

static void wget_ev_sleep_cb(EV_P_ ev_timer* w, int revents WGET_ATTR_UNUSED) {
  struct wget_ev_sleep_ctx* ctx = w->data;
  ctx->done = true;
  ev_timer_stop(EV_A_ w);
}

/* LEGACY_BLOCKING: busy-loops the main event loop until the timer fires. */
void wget_ev_sleep(double seconds) {
  if (seconds <= 0)
    return;

  struct wget_ev_sleep_ctx ctx;
  xzero(ctx);
  ctx.done = false;

  struct ev_loop* loop = wget_ev_loop_get();
  ev_timer_init(&ctx.timer, wget_ev_sleep_cb, seconds, 0);
  ctx.timer.data = &ctx;
  ev_timer_start(loop, &ctx.timer);

  while (!ctx.done)
    ev_run(loop, EVRUN_ONCE);
}
