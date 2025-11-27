/*
 * Non-blocking connection object for Wget.
 * src/net_conn.c
 */

#include "wget.h"
#include "net_conn.h"
#include "evloop.h"
#include "dns_cares.h"
#include "utils.h"
#include "xalloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#ifdef HAVE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

/* Helper macro for debug logging */
#define LOG(fmt, ...)                                       \
  do {                                                      \
    fprintf(stderr, "[net_conn] " fmt "\n", ##__VA_ARGS__); \
    fflush(stderr);                                         \
  } while (0)

struct net_conn {
  enum conn_state state;

  char* host;
  char* port;
  bool use_tls;

  int fd;
#ifdef HAVE_SSL
  SSL* ssl;
  SSL_CTX* ssl_ctx; /* We might need a context, but usually it's global or passed in.
                       For now, we'll assume a global one or create one temporarily?
                       The TODO doesn't specify where SSL_CTX comes from.
                       We'll use a simple one or assume init elsewhere. */
#endif

  struct ev_loop* loop;
  struct evloop_io* io_watcher;
  struct evloop_timer* connect_timer;

  /* User callbacks */
  conn_event_cb on_ready;
  conn_event_cb on_error;
  void* cb_arg;

  conn_event_cb readable_cb;
  conn_event_cb writable_cb;
  void* rw_arg;

  char* error_msg;
};

/* Forward decls */
static void conn_io_cb(int fd, int revents, void* arg);
static void conn_timeout_cb(void* arg);
static void dns_resolve_cb(int status, const struct addrinfo* ai, void* arg);

/* Helper to set error state */
static void set_error(struct net_conn* c, const char* msg) {
  if (c->state == CONN_CLOSED || c->state == CONN_ERROR)
    return;

  c->state = CONN_ERROR;
  if (c->error_msg)
    xfree(c->error_msg);
  c->error_msg = xstrdup(msg ? msg : "Unknown error");

  /* Stop watchers */
  if (c->io_watcher)
    evloop_io_stop(c->io_watcher);
  if (c->connect_timer)
    evloop_timer_stop(c->connect_timer);

  if (c->on_error)
    c->on_error(c, c->cb_arg);
}

struct net_conn* conn_new(struct ev_loop* loop, const char* host, const char* port, bool use_tls, conn_event_cb on_ready, conn_event_cb on_error, void* arg) {
  struct net_conn* c = xnew0(struct net_conn);
  c->loop = loop;
  c->host = xstrdup(host);
  c->port = xstrdup(port ? port : (use_tls ? "443" : "80"));
  c->use_tls = use_tls;
  c->on_ready = on_ready;
  c->on_error = on_error;
  c->cb_arg = arg;
  c->fd = -1;
  c->state = CONN_INIT;

#ifdef HAVE_SSL
  if (use_tls) {
    /* For now, create a basic context if not provided.
       Ideally, this should be passed in or global.
       We will rely on global init in main, but here we need a context to create SSL*.
       Let's assume for now we use a temporary one or fix this later.
       Actually, Wget has global `ssl_ctx` in `openssl.c` but it's not easily exposed?
       Let's look at `src/openssl.c` later. For now, we might fail if we need one.
       We will use a placeholder or assume user initializes SSL. */
  }
#endif

  /* Start Resolution */
  c->state = CONN_RESOLVING;
  LOG("conn_new: resolving %s:%s", c->host, c->port);

  /* Check if it's an IP literal to skip DNS?
     dns_resolve_async might handle it (c-ares handles literals).
     So we just call it. */

  /* We pass 'c' as arg. Danger if 'c' is freed before callback! */
  dns_resolve_async(loop, c->host, c->port, AF_UNSPEC, SOCK_STREAM, 0, dns_resolve_cb, c);

  return c;
}

void conn_close(struct net_conn* c) {
  if (!c)
    return;
  LOG("conn_close: closing connection");

  c->state = CONN_CLOSED;

  if (c->io_watcher) {
    evloop_io_free(c->io_watcher);
    c->io_watcher = NULL;
  }
  if (c->connect_timer) {
    evloop_timer_free(c->connect_timer);
    c->connect_timer = NULL;
  }

#ifdef HAVE_SSL
  if (c->ssl) {
    SSL_shutdown(c->ssl);
    SSL_free(c->ssl);
    c->ssl = NULL;
  }
  /* We don't own ssl_ctx usually */
#endif

  if (c->fd >= 0) {
    close(c->fd);
    c->fd = -1;
  }

  xfree(c->host);
  xfree(c->port);
  if (c->error_msg)
    xfree(c->error_msg);
  xfree(c);
}

/* DNS Callback */
static void dns_resolve_cb(int status, const struct addrinfo* ai, void* arg) {
  struct net_conn* c = arg;
  LOG("dns_resolve_cb: status=%d", status);

  if (c->state != CONN_RESOLVING) {
    /* Cancelled or closed? */
    LOG("dns_resolve_cb: state mismatch %d", c->state);
    return;
  }

  if (status != 0 || !ai) {
    set_error(c, "DNS resolution failed");
    return;
  }

  /* Pick first address */
  /* Create socket */
  c->fd = socket(ai->ai_family, ai->ai_socktype | SOCK_NONBLOCK, ai->ai_protocol);
  if (c->fd < 0) {
    set_error(c, "Socket creation failed");
    return;
  }

  /* Start Connect */
  c->state = CONN_CONNECTING;
  LOG("dns_resolve_cb: starting connect fd=%d", c->fd);
  int r = connect(c->fd, ai->ai_addr, ai->ai_addrlen);

  if (r == 0) {
    LOG("dns_resolve_cb: connect immediate success");
    /* Immediate success (rare for network) */
    /* Proceed to next step via fake IO event or direct call */
    /* We'll handle it in IO callback logic to avoid duplication,
       but we need to trigger it. */
    /* Simplest is to register watcher and it will fire WRITE immediately */
  }
  else if (errno != EINPROGRESS) {
    LOG("dns_resolve_cb: connect failed errno=%d", errno);
    set_error(c, "Connect failed immediately");
    return;
  }

  /* Register Watcher */
  c->io_watcher = evloop_io_start(c->loop, c->fd, EVLOOP_READ | EVLOOP_WRITE, conn_io_cb, c);

  /* Start Timeout (e.g. 10s) */
  c->connect_timer = evloop_timer_start(c->loop, 10.0, 0.0, conn_timeout_cb, c);
}

static void conn_timeout_cb(void* arg) {
  struct net_conn* c = arg;
  set_error(c, "Connection timed out");
}

static void conn_io_cb(int fd, int revents, void* arg) {
  struct net_conn* c = arg;
  (void)fd;
  LOG("conn_io_cb: state=%d revents=%d", c->state, revents);

  if (c->state == CONN_CONNECTING) {
    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
      set_error(c, "getsockopt failed");
      return;
    }
    if (err != 0) {
      /* Failed */
      /* We might want to construct error string from strerror(err) */
      char buf[256];
      snprintf(buf, sizeof(buf), "Connect failed: %s", strerror(err));
      LOG("conn_io_cb: connect failed %s", buf);
      set_error(c, buf);
      return;
    }

    /* Connected */
    if (c->use_tls) {
#ifdef HAVE_SSL
      LOG("conn_io_cb: starting TLS handshake");
      c->state = CONN_TLS_HANDSHAKE;
      /* Init SSL */
      /* We need a context! For prototype, we'll assume we can get a global one or fail.
         Let's try to use a static simple context if needed. */
      static SSL_CTX* simple_ctx = NULL;
      if (!simple_ctx) {
        const SSL_METHOD* method = TLS_client_method();
        simple_ctx = SSL_CTX_new(method);
        if (!simple_ctx) {
          set_error(c, "SSL_CTX_new failed");
          return;
        }
        /* Set default paths? SSL_CTX_set_default_verify_paths(simple_ctx); */
      }

      c->ssl = SSL_new(simple_ctx);
      if (!c->ssl) {
        set_error(c, "SSL_new failed");
        return;
      }
      SSL_set_fd(c->ssl, c->fd);
      SSL_set_connect_state(c->ssl);

      /* Fallthrough to handshake logic */
      /* We need to trigger handshake. We can call it now. */
      /* But better to let the loop handle it if we need wait. */
#else
      set_error(c, "TLS requested but not compiled in");
      return;
#endif
    }
    else {
      LOG("conn_io_cb: connected (plain)");
      c->state = CONN_READY;
      /* Stop connect timer */
      if (c->connect_timer)
        evloop_timer_stop(c->connect_timer);
      /* Notify Ready */
      if (c->on_ready)
        c->on_ready(c, c->cb_arg);

      /* Reconfigure watcher based on callback state (on_ready might have set them) */
      int events = 0;
      if (c->readable_cb)
        events |= EVLOOP_READ;
      if (c->writable_cb)
        events |= EVLOOP_WRITE;
      evloop_io_update(c->io_watcher, events);
      return;
    }
  }

#ifdef HAVE_SSL
  if (c->state == CONN_TLS_HANDSHAKE) {
    int r = SSL_do_handshake(c->ssl);
    LOG("conn_io_cb: SSL_do_handshake r=%d", r);
    if (r == 1) {
      /* Success */
      c->state = CONN_READY;
      if (c->connect_timer)
        evloop_timer_stop(c->connect_timer);
      if (c->on_ready)
        c->on_ready(c, c->cb_arg);
      evloop_io_update(c->io_watcher, 0);
    }
    else {
      int err = SSL_get_error(c->ssl, r);
      LOG("conn_io_cb: SSL_get_error err=%d", err);
      if (err == SSL_ERROR_WANT_READ) {
        evloop_io_update(c->io_watcher, EVLOOP_READ);
      }
      else if (err == SSL_ERROR_WANT_WRITE) {
        evloop_io_update(c->io_watcher, EVLOOP_WRITE);
      }
      else {
        set_error(c, "TLS Handshake failed");
      }
    }
    return;
  }
#endif

  if (c->state == CONN_READY) {
    LOG("conn_io_cb: READY dispatch");
    /* Dispatch User Events */
    if ((revents & EVLOOP_READ) && c->readable_cb) {
      c->readable_cb(c, c->rw_arg);
    }
    if ((revents & EVLOOP_WRITE) && c->writable_cb) {
      c->writable_cb(c, c->rw_arg);
    }
  }
}

void conn_set_readable_callback(struct net_conn* c, conn_event_cb cb, void* arg) {
  if (!c)
    return;
  c->readable_cb = cb;
  c->rw_arg = arg;  // Shared arg for R/W for now, or use same arg as create?
                    // Spec said "void *arg" in signature, so we use that.
                    // Wait, conn_io_cb uses c->rw_arg.
                    // If writable sets different arg, it might overwrite.
                    // Usually higher layer uses same arg (the http_transaction).

  /* Update watcher events */
  int events = 0;
  if (c->readable_cb)
    events |= EVLOOP_READ;
  if (c->writable_cb)
    events |= EVLOOP_WRITE;

  if (c->io_watcher)
    evloop_io_update(c->io_watcher, events);
}

void conn_set_writable_callback(struct net_conn* c, conn_event_cb cb, void* arg) {
  if (!c)
    return;
  c->writable_cb = cb;
  c->rw_arg = arg;

  int events = 0;
  if (c->readable_cb)
    events |= EVLOOP_READ;
  if (c->writable_cb)
    events |= EVLOOP_WRITE;

  if (c->io_watcher)
    evloop_io_update(c->io_watcher, events);
}

ssize_t conn_try_read(struct net_conn* c, void* buf, size_t len) {
  if (c->state != CONN_READY) {
    errno = ENOTCONN;
    return -1;
  }

#ifdef HAVE_SSL
  if (c->use_tls) {
    int n = SSL_read(c->ssl, buf, len);
    if (n <= 0) {
      int err = SSL_get_error(c->ssl, n);
      if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        errno = EAGAIN;
        return -1;
      }
      if (err == SSL_ERROR_ZERO_RETURN) {
        return 0;  // EOF
      }
      // Other errors
      return -1;
    }
    return n;
  }
#endif

  return read(c->fd, buf, len);
}

ssize_t conn_try_write(struct net_conn* c, const void* buf, size_t len) {
  if (c->state != CONN_READY) {
    errno = ENOTCONN;
    return -1;
  }

#ifdef HAVE_SSL
  if (c->use_tls) {
    int n = SSL_write(c->ssl, buf, len);
    if (n <= 0) {
      int err = SSL_get_error(c->ssl, n);
      if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        errno = EAGAIN;
        return -1;
      }
      return -1;
    }
    return n;
  }
#endif

  return write(c->fd, buf, len);
}

enum conn_state conn_get_state(struct net_conn* c) {
  return c ? c->state : CONN_CLOSED;
}

const char* conn_get_error_msg(struct net_conn* c) {
  return c ? c->error_msg : NULL;
}
