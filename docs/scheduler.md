# Download Scheduler (`scheduler`)

**Status Note**: This component is **IMPLEMENTED AND OPERATIONAL**. The scheduler manages concurrent downloads with global and per-host limits, retry logic, and job completion tracking.

**Goal:** Coordinate multiple `http_transaction` tasks, enforce global and per-host concurrency limits, handle retries, and decide which URL to fetch next. The scheduler is the high-level controller for downloads.

## Core Responsibilities

* Maintain a **pending job queue** of URLs/requests.
* Track **active transactions** and **per-host active counts**.
* Enforce:

  * Global max concurrent downloads.
  * Per-host max connections.
* Start transactions when slots are available.
* Handle completion/failure and retries.

## Data Structures

```c
struct download_job {
  char *url;
  char *output_path;
  int retries_remaining;
  // more metadata...
};

struct scheduler {
  struct ev_loop *loop;

  struct job_queue *pending_jobs;    // FIFO

  struct transaction_list *active;   // active http_transaction*
  struct host_map *per_host_active;  // host -> count

  int max_global;
  int max_per_host;

  int num_succeeded;
  int num_failed;

  // maybe WARC writer handle, etc.
};
```

## Adding Jobs

```c
void scheduler_add_job(struct scheduler *s, struct download_job *job);
```

* Append job to `pending_jobs`.
* Attempt to start jobs immediately if slots are free.

## Starting Transactions

When scheduler wants to start a job:

1. Inspect next job in `pending_jobs`:

   * Extract host/scheme/port from its URL.
2. Check:

   * `active_count < max_global`.
   * `per_host_active[host] < max_per_host`.
3. If under limits:

   * Dequeue job.
   * Build `http_request`.
   * Create `http_transaction` with that request and output sink.
   * Call `pconn_acquire` to get a `net_conn`.
   * Add transaction to `active`.
   * Increment `per_host_active[host]`.

If limits are exceeded, keep job queued.

## Handling Completion/Failure

`http_transaction` calls into scheduler on finish:

```c
void scheduler_notify_done(struct scheduler *s, struct http_transaction *txn,
                           bool success);
```

* Remove `txn` from `active`.
* Decrement `per_host_active` for its host.
* Increment `num_succeeded` or `num_failed`.
* If `success == false` and `retries_remaining > 0`:

  * Decrement retries.
  * Optionally use a timer to re-enqueue after some backoff.
* Else, mark permanently failed.
* Free transaction.
* Try to start more jobs from `pending_jobs` (new slots freed).

## Retry Logic

* For transient errors (timeouts, connection failures) you can retry up to N times.
* Use exponential backoff via `evloop_timer`:

  * On failure, schedule a timer.
  * Timer callback re-adds job to `pending_jobs` and triggers rescheduling.

## Completion of All Work

Scheduler knows all work is done when:

* `pending_jobs` is empty.
* `active` is empty.
* No retry timers are pending.

At that point, scheduler:

* Calls `evloop_break(loop)` to exit the event loop.
* Main then proceeds to cleanup and exit.

## Graceful Shutdown

On user interrupt (e.g., `SIGINT`):

* Scheduler may implement:

  ```c
  void scheduler_cancel_all(struct scheduler *s);
  ```

* This:

  * Cancels pending jobs.
  * Aborts active transactions (closing connections).

* Then call `evloop_break(loop)` to exit.