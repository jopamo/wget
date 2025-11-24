# Legacy blocking helpers

The refactor roadmap in `checklist.md` requires us to retire the synchronous helpers that stall the libev loop while a single transfer progresses. This document tracks each blocking helper, why it is problematic, and exactly where it is consumed today so future patches can eliminate or replace them.

## `wget_ev_io_wait` — `src/evhelpers.c:52`

*Purpose*: Runs the global libev loop until a single fd reports readiness, effectively serialising I/O.

*Call sites*:

- `src/connect.c:285` — `connect_with_timeout` blocks while waiting for connect().
- `src/connect.c:701` — `select_fd` wrapper.
- `src/connect.c:706` — `select_fd_nb` on Windows.
- `src/connect.c:723` — `test_socket_open` polls for readability.

## `wget_ev_sleep` — `src/evhelpers.c:114`

*Purpose*: Spins the central loop until a timer fires, preventing other transfers from progressing.

*Call sites*:

- `src/retr.c:1739-1755` — `sleep_between_retrievals` gates retries and `--wait`.

## `fd_read_body` — `src/retr.c:981`

*Purpose*: Starts the asynchronous body reader and then blocks on `wget_ev_loop_run_transfers()` until the download finishes.

*Call sites*:

- `src/http.c:1549-1564` — HTTP response body download.
- `src/ftp.c:1392-1446` — FTP data socket download.

## `wget_ev_loop_run_transfers` — `src/evloop.c:115`

*Purpose*: Drives the libev loop until all transfers finish, preventing concurrency.

*Call sites*:

- `src/retr.c:1003` — used by `fd_read_body`.
- (Tests: `tests/evloop_transfer_test.c:31,37`.)

---

## Replacement design sketch

To remove the four blocking helpers we need coordinated replacements that keep libev running continuously, allow multiple transfers to progress concurrently, and provide async completion notifications back to higher layers. The table below outlines the desired behavior.

| Legacy helper | Replacement concept | Notes |
| --- | --- | --- |
| `wget_ev_io_wait` | Non-blocking **IO waiter API** returning a token/handle that callers can poll/cancel via the central scheduler. Instead of spinning `ev_run`, components register interest (fd, events, timeout) and get a callback when ready. | Likely a thin wrapper over `ev_io` + optional `ev_timer` stored inside the transfer context. Needs cancellation and integration with connection logic in `src/connect.c`. |
| `wget_ev_sleep` | Scheduler-aware **delay task** that arms an `ev_timer` and invokes a continuation when it fires. Sleep consumers (retry logic) should pass a callback/lambda, not block the thread. | Recursion/wait logic must be restructured to queue the next action via the scheduler rather than pausing the whole process. |
| `fd_read_body` | Fully asynchronous **body transfer state machine** that streams data through registered watchers, reports progress/events via callbacks/promises, and lets callers continue immediately after enqueueing. | Essentially move the guts of `fd_read_body` into the transfer scheduler so HTTP/FTP call sites only register interest and resume when completion callback fires. |
| `wget_ev_loop_run_transfers` | Global **loop pump** that stays running (or at least iterative) at `main()` scope while the scheduler owns active transfers. Higher layers await completion via futures/callbacks rather than blocking on this helper. | Means `main()` (and recursion) must drive the event loop proactively instead of calling “run until done”. |

### Behavioral requirements

1. **Non-blocking connect/read/write**  
   - `connect_with_timeout` currently calls `wget_ev_io_wait`. Rework so it registers an `ev_io` watcher for `EV_WRITE` (connect readiness) plus a timer. When either fires, the scheduler resumes the operation.  
   - Provide an API such as `transfer_scheduler_wait_io(ctx, fd, events, timeout, completion_cb)`.

2. **Timer/delay semantics**  
   - Replace `wget_ev_sleep` with `transfer_scheduler_delay(ctx, seconds, cb)` so retry logic enqueues a timer and returns. Scheduler fires the callback and resumes the state machine.  
   - For global sleeps (e.g., between recursion steps), use a scheduler owned by recursion rather than the network loop so multiple outstanding waits can coexist.

3. **Body streaming**  
   - The existing `retr_async_ctx` almost implements what we need; instead of bridging back via `fd_read_body`, expose it directly:  
     ```c
     void transfer_body_start(struct transfer_context* ctx,
                              transfer_body_callbacks* cbs);
     ```  
   - Callers enqueue the body state machine and receive completion via `cbs->on_finished`. No synchronous wait remains.

4. **Loop ownership**  
   - Introduce `transfer_scheduler_run()` that is driven from `main()` and never blocks per transfer.  
   - Provide `transfer_scheduler_poll()` for components like recursion to advance the loop incrementally when scheduling additional work.

### Migration plan (high-level)

1. **Introduce scheduler skeleton** in `src/transfer.c` with APIs for:
   - Enqueueing transfers (`transfer_scheduler_submit`).
   - Registering IO/timeouts (`transfer_scheduler_wait_io`, `transfer_scheduler_delay`).
   - Pumping completions (`transfer_scheduler_run`, `transfer_scheduler_drain`).

2. **Refactor `retr_async_ctx`** into a reusable transfer primitive invoked directly by HTTP/FTP instead of via `fd_read_body`.

3. **Update connection helpers** (`connect_with_timeout`, `test_socket_open`, etc.) to use the new waiter API rather than `wget_ev_io_wait`.

4. **Rework retry/sleep logic** to use scheduler timers instead of `wget_ev_sleep`.

5. **Delete legacy helpers** once all call sites migrate; keep tests updated to exercise the new scheduler.

## Current progress

* `src/scheduler.c` / `src/scheduler.h` now provide the scheduler skeleton. The API exposes enqueue/cancel/status hooks, host-limit configuration, and ties directly into `struct transfer_context`. Transfers still short-circuit with `SCHED_ERR_NOT_SUPPORTED`, but this scaffolding lets future patches start routing HTTP/FTP state machines through the scheduler so we can finally drop `fd_read_body` and `wget_ev_loop_run_transfers`.
