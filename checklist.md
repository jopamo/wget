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
* [x] Connection state machines implemented as pure libev watchers — update `src/retr.c`, `src/transfer.c`, `src/evloop.c`
* [x] Fully nonblocking sockets with `ev_io` for read/write readiness (connect/read/write paths now route through libev helpers)
* [x] Multi-threaded dispatch **only for CPU-heavy tasks** (hashing, decompression, HTML parsing) — update `src/threading.c`, `src/transfer.c`, `src/html-parse.c`
* [ ] Parallel downloading of multiple files — update `src/recur.c`, `src/transfer.c`, `src/main.c`
* [ ] Parallel range-requests for single-file acceleration — update `src/http.c`, `src/retr.c`
* [ ] Connection pooling with persistent keep-alive and per-host limits — update `src/http.c`, `src/host.c`, `src/transfer.c`
* [x] Zero-blocking cross-thread notifications using `ev_async` — update `src/evloop.c`, `src/threading.c`
* [x] Internal DNS caching layer (c-ares)
* [x] Fully asynchronous DNS resolution (c-ares required)
* [x] Integrate c-ares with libev using c-ares fds → `ev_io` watchers and c-ares timeouts → `ev_timer`
* [ ] Enforce aggressive reuse of TCP/TLS sessions to minimize handshake overhead — update `src/http.c`, `src/openssl.c`, `src/host.c`
* [x] Optional TCP_NODELAY and optimized buffer sizes per connection
* [x] Lock-free I/O path where possible (minimize mutex usage) — update `src/threading.c`, `src/evloop.c`

**Next steps**
- Promote per-transfer state machines to persistent libev watchers (connect/retr now use central loop helpers per operation; follow-up is to remove remaining synchronous glue).
- Add per-host pools / keep-alive reuse policies running under libev timers to prep for large-connection workloads.
- Expand the worker pool coverage beyond decompression/HTML parsing to hashing, checksum verification, and other CPU helpers while keeping libev watchers fed.

---

## **Modern HTTP/TLS Capabilities**

*(Assumes OpenSSL, BoringSSL, or WolfSSL — NOT GnuTLS/Nettle)*

* [ ] HTTP/2 support using a single socket → multiplexed streams — update `src/http.c`, `src/openssl.c`, `src/evloop.c`
* [ ] HTTP/1.1 pipelining/streaming tuned for nonblocking engines — update `src/http.c`, `src/transfer.c`
* [ ] TLS session resumption (tickets + session cache) — update `src/openssl.c`, `src/http.c`
* [ ] TLS False Start support — update `src/openssl.c`
* [ ] OCSP and OCSP-stapling validation — update `src/openssl.c`, `src/http.c`
* [ ] Zero-copy receive buffers when supported by TLS backend — update `src/openssl.c`, `src/transfer.c`
* [ ] Optimized handshake scheduling to avoid thundering herd — update `src/host.c`, `src/http.c`, `src/evloop.c`
* [ ] TCP Fast Open support where kernel allows — update `src/socket_opts.c`, `src/http.c`

---

## **URL & Redirect Handling**

* [ ] Fully RFC-correct nonblocking URL parser — update `src/url.c`, `src/iri.c`
* [x] Correct relative URL resolution
* [ ] Hardened redirect logic with async safety checks — update `src/http.c`, `src/url.c`, `src/retr.c`
* [ ] Improved filename/content-type detection — update `src/http.c`, `src/retr.c`, `src/utils.c`
* [ ] Rewrite redirect logic so all retries and hops run under libev timers with no sleeps — update `src/retr.c`, `src/evloop.c`

---

## **Crawling / Mirroring Features**

* [x] Link extraction from HTML and XHTML
* [x] Link extraction from CSS files
* [ ] Parsing and traversal of RSS and Atom feeds — update `src/recur.c`, `src/html-parse.c`
* [ ] Parsing of XML Sitemap files — update `src/recur.c`, `src/html-parse.c`
* [ ] Metalink multi-source engine driven by libev state machines — update `src/metalink.c`, `src/transfer.c`, `src/evloop.c`
* [ ] Extended recursion filters and smarter crawl heuristics — update `src/recur.c`, `src/spider.c`
* [ ] Ensure recursion is also fully asynchronous (no blocking parsing or sleeps) — update `src/recur.c`, `src/evloop.c`

---

## **Robustness / Safety Guarantees**

* [ ] Strict and consistent Content-Length enforcement — update `src/http.c`, `src/retr.c`
* [ ] Retry and reconnection logic implemented via libev timers (never blocking) — update `src/retr.c`, `src/evloop.c`, `src/transfer.c`
* [ ] Built-in checksum verification framework — update `src/transfer.c`, `src/hash.c`, `src/metalink.c`
* [x] Improved signal handling through `ev_signal`
* [ ] Graceful shutdown orchestrated through nonblocking teardown of all watchers — update `src/evloop.c`, `src/main.c`
* [ ] Per-connection rate limiting (optional) implemented via timers/throttling watchers — update `src/transfer.c`, `src/evloop.c`
* [ ] Per-host concurrency limiting enforced via nonblocking queue + watchers — update `src/host.c`, `src/transfer.c`

---

## **Additional Functionality**

* [ ] HTTP compression support (gzip / brotli) — update `src/http.c`, `src/transfer.c`, `src/utils.c`
* [x] Decompression offloaded to worker threads — update `src/threading.c`, `src/transfer.c`
* [ ] Enhanced progress reporting and logging using libev timers — update `src/progress.c`, `src/log.c`, `src/evloop.c`
* [x] Full IPv6 support with fallback logic
* [x] Automatic decompression of compressed bodies
* [x] Full cookie management with a dedicated cookie subsystem
* [ ] Full PSL (Public Suffix List) support through your custom embedded libpsl replacement — update `src/cookies.c`, `src/utils.c`, `src/init.c`
* [ ] Nonblocking file I/O scheduling (write chunks batched and dispatched without stalls) — update `src/transfer.c`, `src/evloop.c`, `src/threading.c`

---

## **Code Quality / Portability**

* [x] Modern build system (Meson)
* [x] Targeted unit tests for TCP tuning options (tcp_nodelay + buffer sizing)
* [ ] Broad unit-test coverage and fuzz testing — update `tests/`, `src/meson.build`
* [ ] Minimized legacy code and compatibility hacks — update `src/utils.c`, `src/mswindows.c`, `src/sysdep.h`
* [ ] Clean modular architecture oriented around event loop–driven state machines — update `src/evloop.c`, `src/transfer.c`, `src/http.c`
* [ ] Thread-safe, lock-minimized design around libev + worker pool — update `src/threading.c`, `src/evloop.c`

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

* [ ] Confirm crypto codepaths (Metalink hashes, MD5/SHA variants) use your unified crypto backend or are removed — update `src/metalink.c`, `src/hash.c`, `src/openssl.c`

* [ ] Replace all legacy blocking patterns (`sleep`, blocking DNS, blocking `poll`, blocking writes) with libev timers or nonblocking calls (connect/read/write waits + rate limiting now share libev via `evhelpers`) — update `src/retr.c`, `src/threading.c`, `src/evhelpers.c`

* [ ] Ensure all DNS code paths are 100% async under c-ares with no fallbacks — update `src/host.c`, `src/res.c`, `src/evloop.c`

* [ ] Verify that no file operations stall the event loop (I/O batching, worker delegation) — update `src/transfer.c`, `src/threading.c`, `src/evloop.c`
