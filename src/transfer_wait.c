/* Scheduler-aware helpers for waiting on FD readiness.
 * src/transfer_wait.c
 */

#include "wget.h"

#include "transfer_wait.h"

#include "connect.h"
#include "evloop.h"
#include "threading.h"
#include "utils.h"
#include "xalloc.h"

#include <errno.h>
#include <ev.h>
#include <stdbool.h>

#if WGET_EVLOOP_CONTINUOUS
#include <poll.h>
#endif

struct transfer_io_waiter {
  transfer_ctx_t* ctx;
  struct ev_loop* loop;
  transfer_io_wait_cb cb;
  void* user_data;
  ev_io io;
  ev_timer timer;
  bool timer_active;
  bool io_active;
  bool completed;
};

static int wait_flags_to_ev(int wait_for) {
  int events = 0;
  if (wait_for & WAIT_FOR_READ)
    events |= EV_READ;
  if (wait_for & WAIT_FOR_WRITE)
    events |= EV_WRITE;
  return events;
}

#if WGET_EVLOOP_CONTINUOUS
static short wait_flags_to_poll(int wait_for) {
  short events = 0;
  if (wait_for & WAIT_FOR_READ)
    events |= POLLIN;
  if (wait_for & WAIT_FOR_WRITE)
    events |= POLLOUT;
  return events;
}
#endif

static struct ev_loop* transfer_wait_loop(transfer_ctx_t* ctx) {
  if (ctx)
    return transfer_context_loop(ctx);
  return wget_ev_loop_get();
}

static void transfer_io_waiter_destroy(struct transfer_io_waiter* waiter) {
  if (!waiter)
    return;
  if (waiter->io_active) {
    ev_io_stop(waiter->loop, &waiter->io);
    waiter->io_active = false;
  }
  if (waiter->timer_active) {
    ev_timer_stop(waiter->loop, &waiter->timer);
    waiter->timer_active = false;
  }
  xfree(waiter);
}

static void transfer_io_wait_complete(struct transfer_io_waiter* waiter, int status, int err_no) {
  if (!waiter || waiter->completed)
    return;
  waiter->completed = true;
  if (waiter->io_active) {
    ev_io_stop(waiter->loop, &waiter->io);
    waiter->io_active = false;
  }
  if (waiter->timer_active) {
    ev_timer_stop(waiter->loop, &waiter->timer);
    waiter->timer_active = false;
  }
  if (waiter->cb)
    waiter->cb(waiter->ctx, waiter->user_data, status, err_no);
  xfree(waiter);
}

static void transfer_io_wait_io_cb(EV_P_ ev_io* w, int revents) {
  struct transfer_io_waiter* waiter = w->data;
  int err_no = 0;
  int status = 1;
  if (revents & EV_ERROR) {
    status = -1;
    err_no = EIO;
  }
  transfer_io_wait_complete(waiter, status, err_no);
}

static void transfer_io_wait_timer_cb(EV_P_ ev_timer* w, int revents WGET_ATTR_UNUSED) {
  struct transfer_io_waiter* waiter = w->data;
  transfer_io_wait_complete(waiter, 0, ETIMEDOUT);
}

transfer_io_waiter_t* transfer_io_wait_schedule(transfer_ctx_t* ctx,
                                                int fd,
                                                int wait_for,
                                                double maxtime,
                                                transfer_io_wait_cb cb,
                                                void* user_data) {
  if (fd < 0) {
    errno = EBADF;
    return NULL;
  }

  int events = wait_flags_to_ev(wait_for);
  if (!events) {
    errno = EINVAL;
    return NULL;
  }

  struct transfer_io_waiter* waiter = xcalloc(1, sizeof(*waiter));
  waiter->ctx = ctx;
  waiter->loop = transfer_wait_loop(ctx);
  waiter->cb = cb;
  waiter->user_data = user_data;

  ev_io_init(&waiter->io, transfer_io_wait_io_cb, fd, events);
  waiter->io.data = waiter;
  ev_io_start(waiter->loop, &waiter->io);
  waiter->io_active = true;

  if (maxtime > 0) {
    ev_timer_init(&waiter->timer, transfer_io_wait_timer_cb, maxtime, 0);
    waiter->timer.data = waiter;
    ev_timer_start(waiter->loop, &waiter->timer);
    waiter->timer_active = true;
  }

  wget_ev_loop_wakeup();

  return waiter;
}

void transfer_io_wait_cancel(transfer_io_waiter_t* waiter) {
  if (!waiter)
    return;
  if (waiter->completed) {
    xfree(waiter);
    return;
  }
  waiter->completed = true;
  transfer_io_waiter_destroy(waiter);
}

#if WGET_EVLOOP_CONTINUOUS
static int transfer_io_wait_poll(int fd, int wait_for) {
  short events = wait_flags_to_poll(wait_for);
  if (!events) {
    errno = EINVAL;
    return -1;
  }

  struct pollfd pfd = {
      .fd = fd,
      .events = events,
      .revents = 0,
  };
  int rc = poll(&pfd, 1, 0);
  if (rc > 0)
    return 1;
  if (rc == 0) {
    errno = ETIMEDOUT;
    return 0;
  }
  return -1;
}
#endif

struct transfer_wait_sync_bridge {
  int status;
  int err;
#if WGET_EVLOOP_CONTINUOUS
  wget_mutex_t lock;
  wget_cond_t cond;
#endif
  bool done;
};

static void transfer_io_wait_sync_cb(transfer_ctx_t* ctx WGET_ATTR_UNUSED, void* user_data, int status, int err) {
  struct transfer_wait_sync_bridge* bridge = user_data;
#if WGET_EVLOOP_CONTINUOUS
  wget_mutex_lock(&bridge->lock);
  bridge->status = status;
  bridge->err = err;
  bridge->done = true;
  wget_cond_broadcast(&bridge->cond);
  wget_mutex_unlock(&bridge->lock);
#else
  bridge->status = status;
  bridge->err = err;
  bridge->done = true;
#endif
}

int transfer_io_wait_blocking(int fd, double maxtime, int wait_for) {
  int events = wait_flags_to_ev(wait_for);
  if (fd < 0) {
    errno = EBADF;
    return -1;
  }
  if (!events) {
    errno = EINVAL;
    return -1;
  }

#if WGET_EVLOOP_CONTINUOUS
  if (maxtime == 0)
    return transfer_io_wait_poll(fd, wait_for);
#endif

  struct transfer_wait_sync_bridge bridge;
  xzero(bridge);
#if WGET_EVLOOP_CONTINUOUS
  wget_mutex_init(&bridge.lock);
  wget_cond_init(&bridge.cond);
#endif

  transfer_io_waiter_t* waiter =
      transfer_io_wait_schedule(NULL, fd, wait_for, maxtime, transfer_io_wait_sync_cb, &bridge);
  if (!waiter) {
#if WGET_EVLOOP_CONTINUOUS
    wget_cond_destroy(&bridge.cond);
    wget_mutex_destroy(&bridge.lock);
#endif
    return -1;
  }

#if WGET_EVLOOP_CONTINUOUS
  wget_mutex_lock(&bridge.lock);
  while (!bridge.done)
    wget_cond_wait(&bridge.cond, &bridge.lock);
  wget_mutex_unlock(&bridge.lock);
  wget_cond_destroy(&bridge.cond);
  wget_mutex_destroy(&bridge.lock);
#else
  struct ev_loop* loop = wget_ev_loop_get();
  bool non_blocking_poll = maxtime <= 0;
  if (non_blocking_poll) {
    ev_run(loop, EVRUN_NOWAIT);
    if (!bridge.done) {
      transfer_io_wait_cancel(waiter);
      waiter = NULL;
      bridge.status = 0;
      bridge.err = ETIMEDOUT;
      bridge.done = true;
    }
  }
  else {
    while (!bridge.done)
      ev_run(loop, EVRUN_ONCE);
  }
#endif

  if (bridge.status == 0 && bridge.err == ETIMEDOUT)
    errno = ETIMEDOUT;
  else if (bridge.status < 0 && bridge.err)
    errno = bridge.err;
  return bridge.status;
}
