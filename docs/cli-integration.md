# Top-Level Workflow and CLI Integration (`retr`)

**Status Note**: This describes the **planned async workflow**. The current CLI uses synchronous execution in `main.c` and `retr.c`.

**Goal:** Provide CLI interface and orchestrate initialization, scheduling, event loop, and teardown.

## Program Start Steps

### 1. Parse Command-Line Arguments

* Collect:

  * List of URLs.
  * Output options (`-O`, output directory).
  * Concurrency options (e.g. `-n N`).
  * Timeouts, user-agent, WARC options, etc.

### 2. Initialize System Components

* **Event loop**: `struct ev_loop *loop = evloop_get_default();`

* **DNS resolver**: `dns_init(loop)` or lazy init via `dns_resolve_async`.

* **TLS/SSL**:

  * Initialize OpenSSL.
  * Create a global `SSL_CTX` for client.

* **Connection pool**: initialize `pconn` maps and limits.

* **Scheduler**:

  * Create, set `max_global`, `max_per_host`, assign `loop`.

* **Output/WARC/logging**:

  * Set up output directory.
  * Open WARC file (if any).
  * Set verbosity.

* **Signal handlers**:

  * Use libev `ev_signal` watchers for `SIGINT` / `SIGTERM`.
  * On signal, call `scheduler_cancel_all()` and `evloop_break(loop)`.

### 3. Enqueue Initial Downloads

For each URL:

* Create `download_job` with URL, output path, retries.
* Call `scheduler_add_job(sched, job)`.

### 4. Run Event Loop

* Call `evloop_run(loop)`.
* While running:

  * Scheduler starts transactions as slots open.
  * Event loop delivers DNS/connect/I/O/timer events.
  * `net_conn`, `http_transaction`, and scheduler callbacks progress the work.

### 5. Exit Condition

* Once scheduler has no pending jobs, no active transactions, and no pending retries, it calls `evloop_break(loop)`.
* `evloop_run()` returns control to `main`.

### 6. Cleanup and Exit

* Print summary: successes, failures.
* Close WARC file and any remaining open output files.
* Call `pconn_shutdown_all()`.
* Destroy DNS channel (`ares_destroy`).
* Free scheduler, transactions, jobs list if any remain.
* Free SSL context (`SSL_CTX_free`).
* Return exit code (0 if all succeeded, non-zero if some failed).

## Optional Blocking API

To provide a legacy `retrieve_url()`:

* Implement:

  ```c
  int retrieve_url(const char *url, const char *output_path);
  ```

* Internally:

  * Initialize loop/scheduler.
  * Create a single job.
  * Run event loop to completion.
  * Cleanup.
  * Return success/fail code.

This wraps the async core in a blocking wrapper that behaves like classic Wget but uses the new architecture.