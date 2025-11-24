/* Scheduler skeleton for coordinating concurrent transfers.
 * src/scheduler.c
 */

#include "scheduler.h"

#include "wget.h"

#include <string.h>

#include "evloop.h"
#include "transfer.h"
#include "utils.h"
#include "xalloc.h"
#include "ev.h"

struct scheduler_transfer {
  struct scheduler_transfer* next;
  transfer_ctx_t* ctx;
  unsigned int flags;
  transfer_cb_t done_cb;
  void* user_arg;
  bool queued;
};

struct scheduler_host_limit_entry {
  struct scheduler_host_limit_entry* next;
  char* host;
  scheduler_host_limits_t limits;
};

struct scheduler_timer {
  struct scheduler_timer* next;
  ev_timer timer;
  scheduler_timer_cb_t callback;
  void* user_arg;
  bool active;
};

struct scheduler {
  struct ev_loop* loop;
  size_t max_concurrent;
  size_t active;
  size_t queued;
  struct scheduler_transfer* queue_head;
  struct scheduler_transfer* queue_tail;
  struct scheduler_timer* timers;
  bool shutting_down;
  scheduler_params_t params;
  bool have_params;
  struct scheduler_host_limit_entry* host_limits;
};

typedef struct scheduler_completion {
  scheduler_t* sched;
  struct scheduler_transfer* transfer;
  int status;
} scheduler_completion_t;

static void scheduler_async_complete(void* arg);
static void scheduler_dispatch_completion(scheduler_t* sched, struct scheduler_transfer* transfer, int status);
static void scheduler_complete_now(scheduler_t* sched, struct scheduler_transfer* transfer, int status);
static void scheduler_try_start(scheduler_t* sched);
static void scheduler_start_transfer(scheduler_t* sched WGET_ATTR_UNUSED, struct scheduler_transfer* transfer);
static void scheduler_queue_push(scheduler_t* sched, struct scheduler_transfer* transfer, bool high_priority);
static void scheduler_queue_remove(scheduler_t* sched, struct scheduler_transfer* transfer, struct scheduler_transfer* prev);
static void scheduler_cancel_queued(scheduler_t* sched, struct scheduler_transfer* transfer, int status);
static struct scheduler_host_limit_entry* scheduler_find_host_entry(scheduler_t* sched, const char* host, bool create);
static void scheduler_clear_host_limits(struct scheduler* sched);

scheduler_t* scheduler_create(struct ev_loop* loop, size_t max_concurrent_transfers) {
  scheduler_t* sched;

  if (max_concurrent_transfers == 0)
    return NULL;

  sched = xcalloc(1, sizeof(*sched));
  sched->loop = loop ? loop : wget_ev_loop_get();
  sched->max_concurrent = max_concurrent_transfers;
  return sched;
}

int scheduler_destroy(scheduler_t* sched, bool wait_for_completion WGET_ATTR_UNUSED) {
  if (!sched)
    return SCHED_ERR_INVALID;

  sched->shutting_down = true;

  while (sched->queue_head) {
    struct scheduler_transfer* transfer = sched->queue_head;
    scheduler_queue_remove(sched, transfer, NULL);
    scheduler_cancel_queued(sched, transfer, SCHED_ERR_SHUTDOWN);
  }

  /* Clean up any active timers */
  while (sched->timers) {
    struct scheduler_timer* timer = sched->timers;
    sched->timers = timer->next;
    ev_timer_stop(sched->loop, &timer->timer);
    xfree(timer);
  }

  scheduler_clear_host_limits(sched);
  xfree(sched);
  return SCHED_OK;
}

int scheduler_enqueue(scheduler_t* sched, transfer_ctx_t* ctx, unsigned int flags, transfer_cb_t done_cb, void* user_arg) {
  struct scheduler_transfer* transfer;
  bool high_priority;

  if (!sched || !ctx)
    return SCHED_ERR_INVALID;
  if (sched->shutting_down)
    return SCHED_ERR_SHUTDOWN;
  if (sched->have_params && sched->params.max_queue_depth > 0 && sched->queued >= sched->params.max_queue_depth)
    return SCHED_ERR_RESOURCE;

  transfer = xcalloc(1, sizeof(*transfer));
  transfer->ctx = ctx;
  transfer->flags = flags;
  transfer->done_cb = done_cb;
  transfer->user_arg = user_arg;
  transfer->queued = true;

  ctx->scheduler = sched;
  ctx->scheduler_internal = transfer;
  ctx->user_priority = (flags & SCHED_FLAG_HIGH_PRIORITY) ? 1 : 0;
  transfer_context_set_state(ctx, TRANSFER_STATE_IDLE);

  high_priority = (flags & SCHED_FLAG_HIGH_PRIORITY) != 0;
  scheduler_queue_push(sched, transfer, high_priority);
  ++sched->queued;

  scheduler_try_start(sched);
  return SCHED_OK;
}

int scheduler_cancel(scheduler_t* sched, transfer_ctx_t* ctx) {
  struct scheduler_transfer* prev = NULL;
  struct scheduler_transfer* current;

  if (!sched || !ctx)
    return SCHED_ERR_INVALID;
  if (ctx->scheduler != sched)
    return SCHED_ERR_INVALID;

  current = sched->queue_head;
  while (current) {
    if (current->ctx == ctx) {
      scheduler_queue_remove(sched, current, prev);
      scheduler_cancel_queued(sched, current, SCHED_ERR_CANCELLED);
      return SCHED_OK;
    }
    prev = current;
    current = current->next;
  }

  return SCHED_ERR_INVALID;
}

int scheduler_status(scheduler_t* sched, transfer_ctx_t* ctx, int* out_status) {
  if (!sched || !ctx || !out_status)
    return SCHED_ERR_INVALID;
  if (ctx->scheduler != sched)
    return SCHED_ERR_INVALID;

  if (ctx->scheduler_internal)
    *out_status = TRANSFER_STATE_IDLE;
  else
    *out_status = transfer_context_state(ctx);
  return SCHED_OK;
}

int scheduler_set_host_limits(scheduler_t* sched, const char* host, const scheduler_host_limits_t* limits) {
  struct scheduler_host_limit_entry* entry;

  if (!sched || !host || !limits)
    return SCHED_ERR_INVALID;
  entry = scheduler_find_host_entry(sched, host, true);
  if (!entry)
    return SCHED_ERR_RESOURCE;
  entry->limits = *limits;
  return SCHED_OK;
}

int scheduler_set_global_params(scheduler_t* sched, const scheduler_params_t* params) {
  if (!sched || !params)
    return SCHED_ERR_INVALID;
  sched->params = *params;
  sched->have_params = true;
  return SCHED_OK;
}

static void scheduler_try_start(scheduler_t* sched) {
  while (sched->active < sched->max_concurrent && sched->queue_head) {
    struct scheduler_transfer* transfer = sched->queue_head;
    scheduler_queue_remove(sched, transfer, NULL);
    --sched->queued;
    ++sched->active;
    transfer->queued = false;
    transfer_context_set_state(transfer->ctx, TRANSFER_STATE_CONNECTING);
    scheduler_start_transfer(sched, transfer);
  }
}

static void scheduler_start_transfer(scheduler_t* sched WGET_ATTR_UNUSED, struct scheduler_transfer* transfer) {
  transfer_context_set_state(transfer->ctx, TRANSFER_STATE_FAILED);
  scheduler_dispatch_completion(sched, transfer, SCHED_ERR_NOT_SUPPORTED);
}

static void scheduler_async_complete(void* arg) {
  scheduler_completion_t* completion = arg;
  if (!completion)
    return;
  scheduler_complete_now(completion->sched, completion->transfer, completion->status);
  xfree(completion);
}

static void scheduler_dispatch_completion(scheduler_t* sched, struct scheduler_transfer* transfer, int status) {
  scheduler_completion_t* completion;

  completion = xmalloc(sizeof(*completion));
  completion->sched = sched;
  completion->transfer = transfer;
  completion->status = status;

  if (!wget_ev_loop_post_async(scheduler_async_complete, completion)) {
    /* Fallback to synchronous completion if async posting fails. */
    scheduler_async_complete(completion);
  }
}

static void scheduler_complete_now(scheduler_t* sched, struct scheduler_transfer* transfer, int status) {
  transfer_ctx_t* ctx;

  if (!sched || !transfer)
    return;

  ctx = transfer->ctx;
  if (sched->active > 0)
    --sched->active;
  ctx->scheduler_internal = NULL;
  ctx->scheduler = NULL;
  if (status == SCHED_OK)
    transfer_context_set_state(ctx, TRANSFER_STATE_COMPLETED);
  else
    transfer_context_set_state(ctx, TRANSFER_STATE_FAILED);

  if (transfer->done_cb)
    transfer->done_cb(ctx, transfer->user_arg, status);

  xfree(transfer);
  scheduler_try_start(sched);
}

static void scheduler_queue_push(scheduler_t* sched, struct scheduler_transfer* transfer, bool high_priority) {
  if (!sched || !transfer)
    return;
  transfer->next = NULL;
  if (!sched->queue_head) {
    sched->queue_head = sched->queue_tail = transfer;
    return;
  }
  if (high_priority) {
    transfer->next = sched->queue_head;
    sched->queue_head = transfer;
    return;
  }
  sched->queue_tail->next = transfer;
  sched->queue_tail = transfer;
}

static void scheduler_queue_remove(scheduler_t* sched, struct scheduler_transfer* transfer, struct scheduler_transfer* prev) {
  if (!sched || !transfer)
    return;

  if (prev)
    prev->next = transfer->next;
  else
    sched->queue_head = transfer->next;

  if (sched->queue_tail == transfer)
    sched->queue_tail = prev;
  transfer->next = NULL;
}

static void scheduler_cancel_queued(scheduler_t* sched, struct scheduler_transfer* transfer, int status) {
  if (!sched || !transfer)
    return;
  if (sched->queued > 0)
    --sched->queued;

  transfer->queued = false;
  transfer->ctx->scheduler_internal = NULL;
  transfer->ctx->scheduler = NULL;
  transfer_context_set_state(transfer->ctx, TRANSFER_STATE_FAILED);

  if (transfer->done_cb)
    transfer->done_cb(transfer->ctx, transfer->user_arg, status);

  xfree(transfer);
}

static struct scheduler_host_limit_entry* scheduler_find_host_entry(scheduler_t* sched, const char* host, bool create) {
  struct scheduler_host_limit_entry* entry = sched->host_limits;

  while (entry) {
    if (strcmp(entry->host, host) == 0)
      return entry;
    entry = entry->next;
  }

  if (!create)
    return NULL;

  entry = xcalloc(1, sizeof(*entry));
  entry->host = xstrdup(host);
  entry->next = sched->host_limits;
  sched->host_limits = entry;
  return entry;
}

static void scheduler_clear_host_limits(struct scheduler* sched) {
  struct scheduler_host_limit_entry* entry = sched->host_limits;

  while (entry) {
    struct scheduler_host_limit_entry* next = entry->next;
    xfree(entry->host);
    xfree(entry);
    entry = next;
  }
  sched->host_limits = NULL;
}

/* Timer callback function */
static void scheduler_timer_cb(EV_P_ ev_timer* w, int revents WGET_ATTR_UNUSED) {
  struct scheduler_timer* timer = w->data;

  if (timer->active && timer->callback) {
    timer->active = false;
    timer->callback(timer->user_arg);
  }
}

/* Timer management functions */
static void scheduler_timer_remove(scheduler_t* sched, struct scheduler_timer* timer) {
  struct scheduler_timer** prev = &sched->timers;
  struct scheduler_timer* current = sched->timers;

  while (current) {
    if (current == timer) {
      *prev = current->next;
      ev_timer_stop(sched->loop, &timer->timer);
      xfree(timer);
      return;
    }
    prev = &current->next;
    current = current->next;
  }
}

int scheduler_delay(scheduler_t* sched, double seconds, scheduler_timer_cb_t callback, void* user_arg) {
  struct scheduler_timer* timer;

  if (!sched || seconds <= 0 || !callback)
    return SCHED_ERR_INVALID;
  if (sched->shutting_down)
    return SCHED_ERR_SHUTDOWN;

  timer = xcalloc(1, sizeof(*timer));
  timer->callback = callback;
  timer->user_arg = user_arg;
  timer->active = true;

  ev_timer_init(&timer->timer, scheduler_timer_cb, seconds, 0);
  timer->timer.data = timer;
  ev_timer_start(sched->loop, &timer->timer);

  timer->next = sched->timers;
  sched->timers = timer;

  return SCHED_OK;
}

int scheduler_cancel_delay(scheduler_t* sched, void* user_arg) {
  struct scheduler_timer* timer = sched->timers;

  if (!sched || !user_arg)
    return SCHED_ERR_INVALID;

  while (timer) {
    if (timer->user_arg == user_arg && timer->active) {
      scheduler_timer_remove(sched, timer);
      return SCHED_OK;
    }
    timer = timer->next;
  }

  return SCHED_ERR_INVALID;
}
