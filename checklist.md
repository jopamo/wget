**HARD REQUIREMENTS**

* c-ares is mandatory
* libev is mandatory
* absolutely **no blocking paths** anywhere (DNS, sockets, timers, redirect logic, etc.)
* architecture must support **thousands of concurrent connections efficiently**
* design choices must explicitly favor **maximum throughput + minimum latency + minimum CPU per connection**

---

NOTE: WHEN WORKING THROUGH CHECKLIST, MARK OFF COMPLETED ITEMS, ADD MISSING ITEMS WHEN APPLICABLE AND COMMIT CHANGES.

# **Wget Feature Requirements Checklist (Optimized for Massive Parallelism)**

## **Performance / Parallelism**

* [x] Single, central **libev event loop** for all network I/O
* [ ] Connection state machines implemented as pure libev watchers
* [ ] Fully nonblocking sockets with `ev_io` for read/write readiness
* [ ] Multi-threaded dispatch **only for CPU-heavy tasks** (hashing, decompression, HTML parsing)
* [ ] Parallel downloading of multiple files
* [ ] Parallel range-requests for single-file acceleration
* [ ] Connection pooling with persistent keep-alive and per-host limits
* [ ] Zero-blocking cross-thread notifications using `ev_async`
* [x] Internal DNS caching layer (c-ares)
* [x] Fully asynchronous DNS resolution (c-ares required)
* [x] Integrate c-ares with libev using c-ares fds → `ev_io` watchers and c-ares timeouts → `ev_timer`
* [ ] Enforce aggressive reuse of TCP/TLS sessions to minimize handshake overhead
* [ ] Optional TCP_NODELAY and optimized buffer sizes per connection
* [ ] Lock-free I/O path where possible (minimize mutex usage)

**Next steps**
- Port socket connect/read/write paths onto libev watchers (connect.c/retr.c) so transfers share the central loop.
- Add per-host pools / keep-alive reuse policies running under libev timers to prep for large-connection workloads.
- Layer in `ev_async` cross-thread notifications + worker hand-off for CPU-heavy helpers (decompression, parsing).

---

## **Modern HTTP/TLS Capabilities**

*(Assumes OpenSSL, BoringSSL, or WolfSSL — NOT GnuTLS/Nettle)*

* [ ] HTTP/2 support using a single socket → multiplexed streams
* [ ] HTTP/1.1 pipelining/streaming tuned for nonblocking engines
* [ ] TLS session resumption (tickets + session cache)
* [ ] TLS False Start support
* [ ] OCSP and OCSP-stapling validation
* [ ] Zero-copy receive buffers when supported by TLS backend
* [ ] Optimized handshake scheduling to avoid thundering herd
* [ ] TCP Fast Open support where kernel allows

---

## **URL & Redirect Handling**

* [ ] Fully RFC-correct nonblocking URL parser
* [x] Correct relative URL resolution
* [ ] Hardened redirect logic with async safety checks
* [ ] Improved filename/content-type detection
* [ ] Rewrite redirect logic so all retries and hops run under libev timers with no sleeps

---

## **Crawling / Mirroring Features**

* [x] Link extraction from HTML and XHTML
* [x] Link extraction from CSS files
* [ ] Parsing and traversal of RSS and Atom feeds
* [ ] Parsing of XML Sitemap files
* [ ] Metalink multi-source engine driven by libev state machines
* [ ] Extended recursion filters and smarter crawl heuristics
* [ ] Ensure recursion is also fully asynchronous (no blocking parsing or sleeps)

---

## **Robustness / Safety Guarantees**

* [ ] Strict and consistent Content-Length enforcement
* [ ] Retry and reconnection logic implemented via libev timers (never blocking)
* [ ] Built-in checksum verification framework
* [ ] Improved signal handling through `ev_signal`
* [ ] Graceful shutdown orchestrated through nonblocking teardown of all watchers
* [ ] Per-connection rate limiting (optional) implemented via timers/throttling watchers
* [ ] Per-host concurrency limiting enforced via nonblocking queue + watchers

---

## **Additional Functionality**

* [ ] HTTP compression support (gzip / brotli)
* [ ] Decompression offloaded to worker threads
* [ ] Enhanced progress reporting and logging using libev timers
* [x] Full IPv6 support with fallback logic
* [x] Automatic decompression of compressed bodies
* [x] Full cookie management with a dedicated cookie subsystem
* [ ] Full PSL (Public Suffix List) support through your custom embedded libpsl replacement
* [ ] Nonblocking file I/O scheduling (write chunks batched and dispatched without stalls)

---

## **Code Quality / Portability**

* [x] Modern build system (Meson)
* [ ] Broad unit-test coverage and fuzz testing
* [ ] Minimized legacy code and compatibility hacks
* [ ] Clean modular architecture oriented around event loop–driven state machines
* [ ] Thread-safe, lock-minimized design around libev + worker pool

---

## **Transition / Cleanup Tasks for a Pure Meson + No-Gnulib Build**

All items updated to reflect **NO gnulib whatsoever** **and** the hard requirements of c-ares + libev:

* [x] Provide replacements for all gnulib helpers previously used:

  * [x] xalloc wrappers
  * [x] base32/base64
  * [x] tmpdir discovery
  * [x] quote/quotearg
  * [x] safe-stdio wrappers
  * [x] path canonicalization helpers

* [x] Remove all `_GL_*` macro usage or replace with strict internal equivalents

* [x] Ensure Meson feature options (Metalink, cookies, PSL, proxies, IDN2, compression) map 1:1 to internal config headers

* [x] Fully eliminate any autoconf leftovers tied to gnulib behavior

* [ ] Confirm crypto codepaths (Metalink hashes, MD5/SHA variants) use your unified crypto backend or are removed

* [ ] Replace all legacy blocking patterns (`sleep`, blocking DNS, blocking `poll`, blocking writes) with libev timers or nonblocking calls

* [ ] Ensure all DNS code paths are 100% async under c-ares with no fallbacks

* [ ] Verify that no file operations stall the event loop (I/O batching, worker delegation)
