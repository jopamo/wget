### **HARD REQUIREMENTS**

* c-ares is mandatory
* libev is mandatory
* absolutely **no blocking paths** anywhere (DNS, sockets, timers, redirect logic, etc.)
* architecture must support **thousands of concurrent connections efficiently**
* design choices must explicitly favor **maximum throughput + minimum latency + minimum CPU per connection**

---

## **1. Core event-driven I/O & parallelism infrastructure**

* [x] Single, central **libev event loop** for all network I/O
* [x] Connection state machines implemented as pure libev watchers – update `src/retr.c`, `src/transfer.c`, `src/evloop.c`
* [x] Fully nonblocking sockets with `ev_io` for read/write readiness (connect/read/write paths now route through libev helpers)
* [x] Multi-threaded dispatch only for CPU-heavy tasks (hashing, decompression, HTML parsing) – update `src/threading.c`, `src/transfer.c`, `src/html-parse.c`
* [x] Zero-blocking cross-thread notifications using `ev_async` – update `src/evloop.c`, `src/threading.c`
* [x] Internal DNS caching layer (c-ares)
* [x] Fully asynchronous DNS resolution (c-ares required)
* [x] Integrate c-ares with libev using c-ares fds → `ev_io` watchers and c-ares timeouts → `ev_timer`
* [x] Optional TCP_NODELAY and optimized buffer sizes per connection
* [x] Lock-free I/O path where possible (minimize mutex usage) – update `src/threading.c`, `src/evloop.c`
* [ ] Parallel downloading of multiple files – update `src/recur.c`, `src/transfer.c`, `src/main.c`
* [ ] Parallel range-requests for single-file acceleration – update `src/http.c`, `src/retr.c`
* [ ] Connection pooling with persistent keep-alive and per-host limits – update `src/http.c`, `src/host.c`, `src/transfer.c`
* [ ] Enforce aggressive reuse of TCP/TLS sessions to minimize handshake overhead – update `src/http.c`, `src/openssl.c`, `src/host.c`

### Parallel transfer refactor roadmap

To flip the remaining `[ ]` entries in this section we now require the staged refactor below. Each phase builds on the prior one; treat the individual items as hard requirements, not “nice to have”.

1. **Prepare foundational architecture**
   - Audit every blocking helper (`wget_ev_io_wait`, `fd_read_body`, `wget_ev_loop_run_transfers`, etc.), mark them legacy, and catalog all call sites.
   - Rework `src/evloop.c` so the main libev loop runs continuously; remove per-transfer blocking `ev_run` calls.
   - Introduce a scheduler in `src/transfer.c` that owns a pool of `transfer_context`s, accepts enqueue requests, and reports completion asynchronously. (In progress: new `src/scheduler.c` + `src/scheduler.h` expose enqueue/cancel/status APIs that bind transfer contexts to the central loop; remaining HTTP wiring still pending.)
   - Convert connect → header → body → finish flows into libev-driven state machines for each protocol.
   - Demonstrate N concurrent transfers (10/100/1000) without blocking the loop.

2. **Make shared data structures concurrency-safe**
   - Audit mutation of `dl_url_file_map`, recursion queues, cookie/HSTS stores, progress/logging buffers, etc.
   - Either move state into per-transfer contexts or add the necessary locking/lock-free containers.
   - Update recursive crawling to schedule work via events rather than blocking loops.

3. **Enable new behavior via the scheduler**
   - Parallelize downloading of distinct files from `src/main.c`/`src/recur.c`.
   - Implement multi-range transfers for single-file acceleration with result merging.
   - Add connection pooling, keep-alive/per-host limits, and aggressive TCP/TLS reuse.

4. **Robustness, protocol, and polish**
   - Enforce strict Content-Length verification plus timer-driven retry logic.
   - Provide graceful, non-blocking shutdown of all watchers and worker threads.
   - Add gzip/brotli streaming (worker-thread offload) and continue layering HTTP/2, zero-copy, TLS False Start, etc.

5. **Cleanup, testing, transition**
   - Grow automated coverage (concurrency/unit/fuzz) and keep gnulib-free, modern Meson wiring.
   - Purge remaining blocking patterns, finish crypto/code cleanups, and ensure every subsystem matches the event-driven model.

### Legacy blocking helper retirement tracker

See `docs/blocking-helpers.md` for the design notes and outstanding call sites. These entries stay `[ ]` until the helper disappears entirely.

* [ ] Remove `wget_ev_io_wait` by moving `connect_with_timeout`, `select_fd`, and `test_socket_open` over to scheduler-aware `ev_io` + timer registrations (touch `src/connect.c`, `src/evloop.c`).
* [ ] Replace `wget_ev_sleep` with scheduler timers so retry/backoff logic (`sleep_between_retrievals` in `src/retr.c`) never spins the global loop.
* [ ] Delete `fd_read_body` once HTTP body streaming uses the asynchronous transfer callbacks directly (updates to `src/http.c`, `src/retr.c`, `src/http_body.c`).
* [ ] Retire `wget_ev_loop_run_transfers` after the scheduler owns the global loop pumping and all callers use completion callbacks/futures (touch `src/evloop.c`, `src/main.c`, tests).

---

## **2. HTTP/TLS & performance protocol layer**

* [ ] HTTP/2 support using a single socket → multiplexed streams – update `src/http.c`, `src/openssl.c`, `src/evloop.c`
* [ ] HTTP/1.1 pipelining/streaming tuned for non-blocking engines – update `src/http.c`, `src/transfer.c`
* [ ] TLS session resumption (tickets + session cache) – update `src/openssl.c`, `src/http.c`
* [ ] TLS False Start support – update `src/openssl.c`
* [ ] OCSP and OCSP-stapling validation – update `src/openssl.c`, `src/http.c`
* [ ] Zero-copy receive buffers when supported by TLS backend – update `src/openssl.c`, `src/transfer.c`
* [ ] Optimized handshake scheduling to avoid thundering herd – update `src/host.c`, `src/http.c`, `src/evloop.c`
* [ ] TCP Fast Open support where kernel allows – update `src/socket_opts.c`, `src/http.c`

---

## **3. URL / Redirect / Crawling infrastructure**

* [x] Correct relative URL resolution
* [ ] Fully RFC-correct nonblocking URL parser – update `src/url.c`, `src/iri.c`
* [ ] Hardened redirect logic with async safety checks – update `src/http.c`, `src/url.c`, `src/retr.c`
* [ ] Improved filename/content-type detection – update `src/http.c`, `src/retr.c`, `src/utils.c`
* [ ] Rewrite redirect logic so all retries and hops run under libev timers with no sleeps – update `src/retr.c`, `src/evloop.c`
* [ ] Parsing and traversal of RSS and Atom feeds – update `src/recur.c`, `src/html-parse.c`
* [ ] Extended recursion filters and smarter crawl heuristics – update `src/recur.c`, `src/spider.c`
* [ ] Ensure recursion is fully asynchronous (no blocking parsing or sleeps) – update `src/recur.c`, `src/evloop.c`

---

## **4. Robustness / operational guarantees**

* [x] Improved signal handling through `ev_signal`
* [x] Per-connection rate-limiting (optional) implemented via timers/throttling watchers
* [ ] Strict and consistent Content-Length enforcement – update `src/http.c`, `src/retr.c`
* [ ] Retry and reconnection logic implemented via libev timers (never blocking) – update `src/retr.c`, `src/evloop.c`, `src/transfer.c`
* [ ] Graceful shutdown orchestrated through non-blocking teardown of all watchers – update `src/evloop.c`, `src/main.c`
* [ ] Per-host concurrency limiting enforced via non-blocking queue + watchers – update `src/host.c`, `src/transfer.c`

---

## **5. Additional features / polish**

* [x] Decompression offloaded to worker threads – update `src/threading.c`, `src/transfer.c`
* [x] Enhanced progress reporting and logging using libev timers
* [x] Full IPv6 support with fallback logic
* [x] Automatic decompression of compressed bodies
* [x] Full cookie management with a dedicated cookie subsystem
* [ ] HTTP compression support (gzip / brotli) – brotli/deflate branches need coding
* [ ] Full PSL (Public Suffix List) support through custom embedded libpsl – update `src/cookies.c`, `src/utils.c`, `src/init.c`
* [ ] Non-blocking file I/O scheduling (write chunks batched and dispatched without stalls) – update `src/transfer.c`, `src/evloop.c`, `src/threading.c`

---

## **6. Code quality / cleanup / transition (No gnulib + Meson build)**

* [x] Modern build system (Meson)
* [x] Targeted unit tests for TCP tuning options (TCP_NODELAY + buffer sizing)
* [ ] Broad unit-test coverage and fuzz testing – update `tests/`, `src/meson.build`
* [ ] Minimized legacy code and compatibility hacks – update `src/utils.c`, `src/sysdep.h`
* [ ] Clean modular architecture oriented around event loop-driven state machines – update `src/evloop.c`, `src/transfer.c`, `src/http.c`
* [ ] HTTP subsystem modularization roadmap
  - [x] Extracted request construction helpers into `src/http_request.c` and authentication helpers into `src/http_auth.c`
  - [ ] Move response parsing + http_stat bookkeeping into a dedicated module (new `src/http_response.c` handles header parsing; wire remaining http_stat plumbing)
  - [ ] Lift retry/state-machine glue and persistent-connection helpers out of `src/http.c` so orchestration becomes the thin layer
* [ ] Thread-safe, lock-minimized design around libev + worker pool – update `src/threading.c`, `src/evloop.c`
* [ ] Confirm crypto codepaths (MD5/SHA variants) use a unified crypto backend – update `src/hash.c`, `src/openssl.c`
* [ ] Replace all legacy blocking patterns (`sleep`, blocking DNS, blocking poll, blocking writes) with libev timers or non-blocking calls – update `src/retr.c`, `src/threading.c`, `src/evhelpers.c`
* [ ] Ensure all DNS code paths are 100% async under c-ares with no fallbacks – update `src/host.c`, `src/res.c`, `src/evloop.c`
* [ ] Verify that no file operations stall the event loop (I/O batching, worker delegation) – update `src/transfer.c`, `src/threading.c`, `src/evloop.c`

---

## **7. Validation, observability, and release readiness**

* [ ] Document a repeatable manual test matrix (libev/c-ares builds, HTTPS targets, recursion) and capture commands/logs in `docs/testing.md` or a new `docs/test-matrix.md`.
* [ ] Add libev/c-ares integration tests that assert watchers fire as expected (extend `tests/evloop_transfer_test.c` or add new suites under `tests/`).
* [ ] Instrument the scheduler with debug logging / stats hooks so we can prove per-host limits, queue depth, and throughput against the “thousands of concurrent transfers” goal (`src/scheduler.c`, `src/log.c`).
* [ ] Automate ASan/Valgrind smoke runs in CI scripts or Meson targets to catch regressions before release (`meson.build`, `tests/` helpers).
* [ ] Track completion of checklist items inside release notes so each tag documents which boxes from sections 1–6 were validated (update `docs/release-notes.md` or add a new summary file).
