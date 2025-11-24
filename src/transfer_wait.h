/* Scheduler-aware helpers for waiting on FD readiness.
 * src/transfer_wait.h
 */

#ifndef WGET_TRANSFER_WAIT_H
#define WGET_TRANSFER_WAIT_H

#include "transfer.h"

typedef struct transfer_io_waiter transfer_io_waiter_t;

typedef void (*transfer_io_wait_cb)(transfer_ctx_t* ctx, void* user_data, int status, int error_no);

transfer_io_waiter_t* transfer_io_wait_schedule(transfer_ctx_t* ctx, int fd, int wait_for, double maxtime, transfer_io_wait_cb cb, void* user_data);
void transfer_io_wait_cancel(transfer_io_waiter_t* waiter);
int transfer_io_wait_blocking(int fd, double maxtime, int wait_for);

#endif /* WGET_TRANSFER_WAIT_H */
