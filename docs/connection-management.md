# Connection/Session Management (`net_conn`)

**Status Note**: This component is **planned but not yet implemented**. The current codebase uses synchronous connection logic in `connect.c`.

**Goal:** Encapsulate a single network connection (TCP socket, optionally with TLS) in a non-blocking, event-driven object. This module handles hostname resolution, non-blocking connect, TLS handshake, and provides simple read/write methods. It exposes a callback when the connection is ready or if an error occurs, and allows registering for read/write notifications once connected.

## Connection States

```c
enum conn_state {
  CONN_INIT,
  CONN_RESOLVING,
  CONN_CONNECTING,
  CONN_TLS_HANDSHAKE,
  CONN_READY,
  CONN_CLOSED,
  CONN_ERROR
};
```

* `CONN_INIT`: Initial state.
* `CONN_RESOLVING`: DNS resolution in progress.
* `CONN_CONNECTING`: Non-blocking `connect()` initiated.
* `CONN_TLS_HANDSHAKE`: TLS handshake in progress.
* `CONN_READY`: Connected (and TLS-negotiated if applicable).
* `CONN_CLOSED`: Closed gracefully.
* `CONN_ERROR`: Failed.

## Connection Structure

```c
typedef void (*conn_event_cb)(struct net_conn *c, void *arg);

struct net_conn {
  enum conn_state state;

  char *host;
  char *port;
  bool use_tls;

  int fd;
  SSL *ssl;             // optional, if TLS

  struct evloop_io *io_watcher;
  struct evloop_timer *connect_timer;

  conn_event_cb on_ready;
  conn_event_cb on_error;
  void *cb_arg;

  conn_event_cb readable_cb;
  conn_event_cb writable_cb;
  void *rw_arg;

  // additional fields...
};
```

## Creating a Connection

```c
struct net_conn *conn_new(struct ev_loop *loop,
                          const char *host, const char *port,
                          bool use_tls,
                          conn_event_cb on_ready,
                          conn_event_cb on_error,
                          void *arg);
```

* Store host/port, `use_tls`, callbacks, `arg`.
* If host is IP literal, skip DNS and go directly to `CONN_CONNECTING`.
* Otherwise:

  * Set `state = CONN_RESOLVING`.
  * Call `dns_resolve_async(loop, host, port, ...)`.
  * On DNS success, create a non-blocking socket and initiate `connect()`.
  * On DNS failure, set `CONN_ERROR`, call `on_error`.

For non-blocking `connect()`:

* Create socket with `SOCK_NONBLOCK`.
* Call `connect()`; if `EINPROGRESS`, set `CONN_CONNECTING`.
* Register `io_watcher` for `EV_READ | EV_WRITE` with callback `conn_io_cb`.
* Start a `connect_timer` (e.g., 10s). On timeout, abort and call `on_error`.

## `conn_io_cb` Logic

In `conn_io_cb(int fd, int revents, void *arg)`:

* If `state == CONN_CONNECTING`:

  * Use `getsockopt(fd, SOL_SOCKET, SO_ERROR, &err)` to check connection result.
  * If `err == 0`:

    * If `use_tls`, go to `CONN_TLS_HANDSHAKE`.
    * Else, go to `CONN_READY` and call `on_ready`.
  * Else:

    * Set `CONN_ERROR`, stop watcher/timer, close socket, call `on_error`.

* If `state == CONN_TLS_HANDSHAKE`:

  * Call `SSL_do_handshake(ssl)`.
  * If result `1`, handshake complete → `CONN_READY`, cancel timer, call `on_ready`.
  * If `SSL_ERROR_WANT_READ` or `SSL_ERROR_WANT_WRITE`, keep watcher active and wait for next event.
  * On fatal error, close SSL+fd, `CONN_ERROR`, call `on_error`.

* If `state == CONN_READY`:

  * Dispatch events:

    * If `revents & EV_READ` and `readable_cb`, call `readable_cb(c, rw_arg)`.
    * If `revents & EV_WRITE` and `writable_cb`, call `writable_cb(c, rw_arg)`.

## Read/Write APIs

```c
ssize_t conn_try_read(struct net_conn *c, void *buf, size_t len);
ssize_t conn_try_write(struct net_conn *c, const void *buf, size_t len);
```

* If TLS: use `SSL_read` / `SSL_write`, translating `SSL_ERROR_WANT_*` to `-1` with `errno = EAGAIN` or similar.
* If plain: use `read()` / `write()` on non-blocking fd.
* Return:

  * `>0` bytes processed.
  * `0` on EOF (read).
  * `-1` on error or `EAGAIN` (caller checks `errno` and/or SSL error).

## Event Notification Registration

```c
void conn_set_readable_callback(struct net_conn *c, conn_event_cb cb, void *arg);
void conn_set_writable_callback(struct net_conn *c, conn_event_cb cb, void *arg);
```

* Store callbacks and `rw_arg`.
* Update watcher events via `evloop_io_update` to turn on/off `EV_READ` / `EV_WRITE` depending on which callbacks are set.

## Closing the Connection

```c
void conn_close(struct net_conn *c);
```

* Stop `io_watcher` and timers.
* If TLS: `SSL_shutdown` and `SSL_free`.
* Close `fd`.
* Free `net_conn` (or mark for pool).

Errors at any stage (DNS, connect, handshake, I/O) propagate via `on_error`. Reuse is handled by pooling at a higher level.