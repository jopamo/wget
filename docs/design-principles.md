# Design Principles and Best Practices

These principles guide the **IMPLEMENTED** async architecture and ensure robust, fully asynchronous operation:

## No Blocking Calls

* No `getaddrinfo()` → use c-ares.
* No blocking `connect()` → always non-blocking.
* No blocking `read()`/`write()` → non-blocking only and handle `EAGAIN`.
* No `sleep()` for timeouts → always timers.

## Callbacks + Immediate Returns

* Initiate network operations (DNS, connect, read, write), then return immediately.
* Completion or progress is signaled via callbacks invoked by the event loop.

## Timer-based Timeouts

* Use libev timers for:

  * DNS timeouts.
  * Connect timeouts.
  * Header wait timeouts.
  * Inactivity / total request timeouts.

## Incremental Parsing

* HTTP headers and chunked encoding must be parsed incrementally:

  * Accumulate data until you see `\r\n` or `\r\n\r\n`.
  * Allow split boundaries (e.g., chunk size line split across two reads).
* Parsers must be able to resume when more data arrives.

## Bounded Work per Event

* In each callback:

  * Process a limited amount of data.
  * Avoid spinning if a lot of data is ready; process a chunk, then return.
* Prevent a single socket or transaction from starving others.

## Single-threaded Core

* All libev operations in a single thread.
* If background threads are later added, they must communicate via `ev_async`.

## Clear Object Lifecycles

* Each `http_transaction`, `net_conn`, `download_job` has obvious creation and destruction points.
* Use single teardown paths where possible (e.g., `http_transaction_fail()`).

## No Unowned Watchers

* Before freeing any object with active watchers, stop its watchers.
* Timers for a transaction must be stopped when the transaction finishes.

## Proper libev Usage

* Stick to the default loop (for simplicity).
* Do not mix multiple loops unless there is a strong reason.

## Error Propagation

* If a lower layer sees an error, propagate it upward:

  * DNS → connection → transaction → scheduler.
* Avoid silent failures; always notify scheduler for retry/fail decisions.

## Unit Testing of Components

* Test:

  * DNS resolver (`dns_resolve_async`).
  * `net_conn` on real or mock servers.
  * HTTP parser with canned responses.
* Use small test harnesses that run an event loop and verify behavior.

## Extensibility

* Module boundaries:

  * `evloop` hides libev,
  * `dns_cares` hides c-ares,
  * `net_conn` hides socket/TLS,
  * `http_transaction` hides HTTP parsing.
* This allows swapping components (e.g., different event loop) without redesigning everything.

## Resource Limits

* Be aware of `ulimit -n` and FD limits for many connections.
* Adjust limits or document requirements.

## Memory Management

* Do not buffer entire large downloads in memory; always stream to disk/WARC.
* Keep header buffers bounded (e.g., reject headers over some max size).

## Security

* For TLS, verify certificates (unless explicitly disabled via options).
* Avoid unsafe buffer handling in parsers.
* Carefully validate HTTP chunk sizes and header lengths.

Following these principles yields an efficient, scalable, and maintainable downloader. The event loop and state machines orchestrate all network activity so the program never blocks on a single operation when other work can progress.