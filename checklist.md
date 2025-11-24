Below is a **new, shorter, cleaner, fully-checkboxed, and ordered** checklist.
Everything is grouped into **realistic execution phases**, each phase containing only the work that must be completed before moving forward.

Your original content is preserved conceptually but reduced to **essential, actionable items**.

---

# **Wget-Next Refactor Checklist (Concise + Ordered)**

---

# **PHASE 0 — Hard Guarantees / Global Constraints**

* [x] c-ares is mandatory
* [x] libev is mandatory
* [x] All DNS, sockets, redirects, timers, retries are non-blocking
* [x] Architecture supports thousands of concurrent transfers
* [x] Design must optimize throughput, latency, and CPU per connection

---

# **PHASE 1 — Core Event Engine (must be stable before anything else)**

## **Event Loop & Nonblocking I/O**

* [x] Single global libev loop
* [x] Convert all sockets to nonblocking
* [x] Use `ev_io` for read/write/connect
* [x] Use `ev_timer` for timeouts/backoff
* [x] Integrate c-ares fds + timers into libev
* [x] Add `ev_async` for thread → loop notifications

---

## **Eliminate All Blocking I/O Helpers**

* [x] Replace all `wget_ev_io_wait()` usages
  * Convert connect/poll logic to scheduler-driven async continuations
  * Each waiting path becomes "register watcher → return → resume on callback"

* [x] Remove `fd_read_body()` synchronous read path
  * Move all HTTP body consumption into async transfer state machine callbacks
  * Delete wrapper after all remaining consumers are async

* [x] Convert `sleep_between_retrievals()` to purely timer-driven throttling
  * Implement via scheduler + `ev_timer`
  * No stalls in main loop or worker threads

* [x] Convert main() to use async retrieve_url and event loop
  * Replace synchronous retrieve_url calls with retrieve_url_start_async
  * Add main_loop_ctx structure for managing async operations
  * Implement callback-based completion handling

---

## **Remove Legacy Helpers Once All Callers Are Migrated**

* [x] Delete `wget_ev_io_wait` (replaced by scheduler-aware waiters)
* [x] Delete `wget_ev_sleep` (replaced by scheduler timer functionality)
* [ ] Delete `fd_read_body` (still used for HTTP body download)
* [ ] Delete `wget_ev_loop_run_transfers` (no-op shim for non-pthread fallbacks)

---

## **Parallel I/O Architecture**

* [ ] Event-driven state machines for connect → headers → body → finish
* [ ] Verify stable parallel operation with 10 / 100 / 1000 concurrent transfers

# **PHASE 2 — Scheduler (the heart of parallel transfers)**

* [x] Implement scheduler skeleton (`scheduler.c/h`)
* [ ] Provide async enqueue → execute → complete callbacks
* [x] No per-transfer `ev_run` calls; loop runs continuously
* [ ] Shared structures concurrency-safe (cookies, recursion lists, host maps)
* [ ] All retries/timeouts run via scheduler timers

---

# **PHASE 3 — Parallel Downloads & Connection Reuse**

* [ ] Multiple file transfers in parallel
* [ ] Parallel multi-range requests (segment merging)
* [ ] Connection pooling + keep-alive + per-host limits
* [ ] Aggressive TLS/TCP session reuse for minimal handshake overhead
* [ ] Per-host concurrency limiting done through scheduler queues

---

# **PHASE 4 — HTTP/TLS Modernization**

* [ ] HTTP/2 multiplexing on a single socket
* [ ] Nonblocking HTTP/1.1 streaming/pipelining
* [ ] TLS session resumption (tickets + cache)
* [ ] TLS False Start
* [ ] OCSP + OCSP stapling
* [ ] Zero-copy receive buffers where backend supports it
* [ ] Optimized handshake scheduling (no herd effects)
* [ ] TCP Fast Open where supported

---

# **PHASE 5 — URL/Redirect/Crawling Modernization**

* [x] Correct relative URL logic
* [ ] Fully nonblocking URL parser
* [ ] Async-safe redirect logic (no sleeps)
* [ ] Content-type/filename detection improvements
* [ ] RSS/Atom parsing
* [ ] Extended recursion filters / heuristics
* [ ] Recursion made fully event-driven

---

# **PHASE 6 — Robustness & Operational Guarantees**

* [x] Signal handling via `ev_signal`
* [x] Optional rate limiting (per connection)
* [ ] Strict Content-Length enforcement
* [ ] Retry logic exclusively timer-driven
* [ ] Full non-blocking shutdown (all watchers stop cleanly)
* [ ] Verified async directory/file writes (no fs stalls)

---

# **PHASE 7 — Additional Features / Integrations**

* [x] Worker-thread offloaded decompression
* [x] Better progress/logging via timers
* [x] Full IPv6 support
* [x] Cookie subsystem complete
* [ ] gzip/brotli HTTP compression support
* [ ] Embedded PSL logic (libpsl replacement)
* [ ] Fully nonblocking file write scheduling

---

# **PHASE 8 — Code Quality / Build System**

* [x] Meson build system
* [ ] Broad test coverage
* [ ] Remove legacy portability hacks
* [x] HTTP subsystem modularization (`http_request.c`, `http_auth.c`, `http_header.c`, `http_pconn.c`, connection glue)
  * HTTP header parsing utilities extracted to `http-header.c/h`
  * Persistent connection management extracted to `http-pconn.c/h`
* [ ] Unified crypto backend
* [ ] Ensure all DNS → c-ares calls are async with no fallback
* [ ] Zero remaining blocking codepaths anywhere

---

# **PHASE 9 — Validation, Observability, Release Readiness**

* [x] Manual test matrix documented
* [ ] Automated libev/c-ares integration tests
* [ ] Scheduler instrumentation (queue depth, events, per-host stats)
* [ ] CI smoke tests (ASan/Valgrind)
* [ ] Release notes map checklist progress per-tag
