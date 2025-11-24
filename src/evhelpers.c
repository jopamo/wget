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
#include "threading.h"

#if WGET_EVLOOP_CONTINUOUS
#include <poll.h>
#endif

struct fd_wait_ctx {
  ev_io io;
  ev_timer timer;
  int result;
  bool done;
  bool has_timer;
  bool timed_out;
#if WGET_EVLOOP_CONTINUOUS
  wget_mutex_t lock;
  wget_cond_t cond;
#endif
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
#if WGET_EVLOOP_CONTINUOUS
  wget_mutex_lock(&ctx->lock);
  wget_cond_broadcast(&ctx->cond);
  wget_mutex_unlock(&ctx->lock);
#endif
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
#if WGET_EVLOOP_CONTINUOUS
  wget_mutex_lock(&ctx->lock);
  wget_cond_broadcast(&ctx->cond);
  wget_mutex_unlock(&ctx->lock);
#endif
}

#if WGET_EVLOOP_CONTINUOUS

/* Wait for readiness via the continuous event loop by blocking on a condition variable. */
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

  bool wait_forever = maxtime < 0;
  bool poll_only = maxtime == 0;

  if (poll_only) {
    struct pollfd pfd = {
        .fd = fd,
        .events = 0,
    };
    if (events & EV_READ)
      pfd.events |= POLLIN;
    if (events & EV_WRITE)
      pfd.events |= POLLOUT;
    int rc = poll(&pfd, 1, 0);
    if (rc > 0)
      return 1;
    if (rc == 0)
      return 0;
    return -1;
  }

  struct fd_wait_ctx ctx;
  xzero(ctx);
  wget_mutex_init(&ctx.lock);
  wget_cond_init(&ctx.cond);

  struct ev_loop* loop = wget_ev_loop_get();
  ev_io_init(&ctx.io, fd_wait_io_cb, fd, events);
  ctx.io.data = &ctx;
  ev_io_start(loop, &ctx.io);

  if (!wait_forever) {
    ev_timer_init(&ctx.timer, fd_wait_timer_cb, maxtime, 0);
    ctx.timer.data = &ctx;
    ctx.has_timer = true;
    ev_timer_start(loop, &ctx.timer);
  }

  wget_mutex_lock(&ctx.lock);
  if (!ctx.done) {
    if (!wait_forever) {
      if (!wget_cond_timedwait(&ctx.cond, &ctx.lock, maxtime)) {
        ctx.result = 0;
        ctx.timed_out = true;
        ctx.done = true;
      }
    }
    else {
      while (!ctx.done)
        wget_cond_wait(&ctx.cond, &ctx.lock);
    }
  }
  wget_mutex_unlock(&ctx.lock);

  ev_io_stop(loop, &ctx.io);
  if (ctx.has_timer)
    ev_timer_stop(loop, &ctx.timer);

  wget_cond_destroy(&ctx.cond);
  wget_mutex_destroy(&ctx.lock);

  if (ctx.result == 0 && ctx.timed_out)
    errno = ETIMEDOUT;
  return ctx.result;
}

#else

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
#endif

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
  ctx->done = true;
  ev_timer_stop(EV_A_ w);
#if WGET_EVLOOP_CONTINUOUS
  wget_mutex_lock(&ctx->lock);
  wget_cond_broadcast(&ctx->cond);
  wget_mutex_unlock(&ctx->lock);
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

  while (!ctx.done)
    ev_run(loop, EVRUN_ONCE);
#endif
}
