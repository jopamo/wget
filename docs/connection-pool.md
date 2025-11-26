# Persistent Connection Pool (`pconn`)

**Status Note**: This component is **partially implemented** as `http-pconn.c` but uses synchronous patterns. The planned async version would integrate with the new architecture.

**Goal:** Improve efficiency by reusing TCP connections for multiple HTTP requests to the same server (persistent/keep-alive connections).

## Pool Key and Structures

* Key on `(scheme, host, port)`:

  ```c
  struct pconn_key {
    char *scheme;
    char *host;
    char *port;
  };
  ```

* Value: list of idle `net_conn *` connections for that key.

* Track per-host limits (idle and/or total connections).

## `pconn_acquire`

```c
struct net_conn *pconn_acquire(struct ev_loop *loop,
                               const char *scheme,
                               const char *host,
                               const char *port,
                               bool use_tls,
                               conn_event_cb on_ready,
                               conn_event_cb on_error,
                               void *arg);
```

* Look up idle list for `(scheme, host, port)`:

  * If idle connection exists:

    * Pop it from list.
    * Optionally verify it's still alive (will be detected on first use if server closed it).
    * Re-attach `on_ready` / `on_error` and user `arg` as needed.
    * Return it.
  * If none:

    * Create new `net_conn` with `conn_new(...)`.
    * `net_conn` will call callbacks on completion/error.

## `pconn_release`

```c
void pconn_release(struct net_conn *c, bool keep_alive_ok);
```

* If `keep_alive_ok == false`:

  * Call `conn_close(c)`, do not pool.
* If `keep_alive_ok == true`:

  * Determine pool key from `c` (stored host/port/scheme).
  * If idle list size for this key is below max idle:

    * Clear `readable/writable` callbacks (disable watchers or reduce events).
    * Add `c` to idle list.
  * Else:

    * Close connection instead of pooling.

## Flush/Shutdown

* `pconn_flush_for_host(host)`:

  * Close all idle connections for a given host.
* `pconn_shutdown_all()`:

  * On program exit, close all idle connections in pool.

All operations are performed in the event loop thread, avoiding locking. If server has closed an idle connection, this will be detected on reuse and a new connection will be opened.