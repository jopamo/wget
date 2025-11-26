# Asynchronous DNS Resolution (`dns_cares`)

**Status Note**: This component is **planned but not yet implemented**. The current codebase uses synchronous `getaddrinfo()`.

**Goal:** Perform all hostname resolutions asynchronously using c-ares, integrated with our libev event loop. The rest of the program will call a simple function to resolve hostnames, and this DNS module will invoke a callback with the results once the DNS query completes (or fails), without blocking the main thread.

## Design and Steps

### Initialize c-ares Channel

Create an `ares_channel` with `ares_init_options`. We want c-ares to use our custom event base. We can use `ARES_OPT_SOCK_STATE_CB` in `ares_init_options` to set up c-ares to notify us of socket state changes, or use `ares_getsock()` polling.

Store the `ares_channel` in a context structure:

```c
struct dns_ev_ctx {
  struct ev_loop *loop;
  ares_channel channel;
  // mapping sockfd -> struct evloop_io*
  // struct evloop_timer *timeout_timer;
};
```

### Watching DNS Sockets

After any DNS query is started (or whenever c-ares indicates a socket state change), determine which sockets c-ares is using:

* Use `ares_getsock(channel, sockets, num)` to retrieve up to `ARES_GETSOCK_MAXNUM` (e.g. 16) sockets.
* For each socket:

  * If not already being watched, create a new evloop I/O watcher via

    ```c
    evloop_io_start(loop, sock, events, dns_sock_cb, ctx);
    ```

  * If already watched, update its events via `evloop_io_update`.

  * If a socket is no longer needed, stop and free its watcher via `evloop_io_stop`.

The callback:

```c
static void dns_sock_cb(int fd, int revents, void *arg) {
  struct dns_ev_ctx *ctx = arg;
  ares_process_fd(ctx->channel,
                  (revents & EV_READ)  ? fd : ARES_SOCKET_BAD,
                  (revents & EV_WRITE) ? fd : ARES_SOCKET_BAD);
  // then rescan with ares_getsock and update watchers
}
```

### DNS Query Timeouts

Use an `evloop_timer` to handle DNS timeouts:

* After each `ares_process_fd` or when a query is initiated, call:

  ```c
  struct timeval tv = ares_timeout(channel, NULL, NULL);
  ```

* If `tv` is non-zero, start or reschedule a timer to fire after `tv`. If `tv` is zero, you may call:

  ```c
  ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
  ```

* The timer's callback should call `ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD)` then recompute the next timeout.

### Public API

Provide a friendly function to start a DNS resolution:

```c
typedef void (*dns_result_cb)(int status, const struct addrinfo *ai, void *arg);

void dns_resolve_async(struct ev_loop *loop,
                       const char *hostname, const char *service,
                       int family, int socktype, int protocol,
                       dns_result_cb cb, void *arg);
```

* Use `ares_getaddrinfo` (if available) or `ares_query` for A/AAAA.
* Allocate a small context storing `cb`, `arg`, etc.
* In the c-ares completion callback, translate result to `struct addrinfo` (or equivalent), call `dns_result_cb`, and free resources.

### Error Handling

If resolution fails, call `cb` with error status and `NULL` result. The higher layer (e.g. connection module) will handle it.

### Integration with Event Loop

All c-ares sockets are integrated via `evloop` wrappers. Multiple DNS queries can be in-flight concurrently while the event loop also manages other network I/O.

By encapsulating DNS in `dns_cares`, other components simply request a resolution and continue; the result is delivered asynchronously via callback.