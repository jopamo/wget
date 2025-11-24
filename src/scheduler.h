/* Scheduler skeleton for coordinating concurrent transfers.
 * src/scheduler.h
 */

#ifndef WGET_SCHEDULER_H
#define WGET_SCHEDULER_H

#include <stdbool.h>
#include <stddef.h>

struct ev_loop;
struct scheduler;
struct transfer_context;

typedef struct scheduler scheduler_t;
typedef struct transfer_context transfer_ctx_t;

typedef void (*transfer_cb_t)(transfer_ctx_t* ctx, void* user_arg, int status);

enum {
  SCHED_OK = 0,
  SCHED_ERR_RESOURCE = -1,
  SCHED_ERR_INVALID = -2,
  SCHED_ERR_CANCELLED = -3,
  SCHED_ERR_SHUTDOWN = -4,
  SCHED_ERR_NOT_SUPPORTED = -5
};

enum {
  SCHED_FLAG_NONE = 0,
  SCHED_FLAG_HIGH_PRIORITY = 1 << 0,
  SCHED_FLAG_HOST_LIMIT = 1 << 1
};

typedef struct scheduler_params {
  size_t max_queue_depth;
  bool fair_share_enabled;
} scheduler_params_t;

typedef struct scheduler_host_limits {
  size_t max_concurrent;
  size_t max_idle_sessions;
} scheduler_host_limits_t;

scheduler_t* scheduler_create(struct ev_loop* loop, size_t max_concurrent_transfers);
int scheduler_destroy(scheduler_t* sched, bool wait_for_completion);

int scheduler_enqueue(scheduler_t* sched,
                      transfer_ctx_t* ctx,
                      unsigned int flags,
                      transfer_cb_t done_cb,
                      void* user_arg);
int scheduler_cancel(scheduler_t* sched, transfer_ctx_t* ctx);
int scheduler_status(scheduler_t* sched, transfer_ctx_t* ctx, int* out_status);

int scheduler_set_host_limits(scheduler_t* sched, const char* host, const scheduler_host_limits_t* limits);
int scheduler_set_global_params(scheduler_t* sched, const scheduler_params_t* params);

#endif /* WGET_SCHEDULER_H */
