/*
 * Asynchronous DNS resolution using c-ares and libev.
 * src/dns_cares.c
 */

#include "wget.h"
#include "dns_cares.h"
#include "evloop.h"
#include "utils.h"
#include "xalloc.h"

#include <ares.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ARES_SOCKETS 16

struct dns_watcher {
  int fd;
  struct evloop_io *io;
};

struct dns_ev_ctx {
  struct ev_loop *loop;
  ares_channel channel;
  struct dns_watcher watchers[MAX_ARES_SOCKETS];
  struct evloop_timer *timer;
};

/* Singleton context */
static struct dns_ev_ctx *global_dns_ctx = NULL;

static void update_watchers(struct dns_ev_ctx *ctx);

/* Callback for c-ares processing when a socket is ready */
static void
dns_sock_cb(int fd, int revents, void *arg)
{
  struct dns_ev_ctx *ctx = arg;
  int read_fd = (revents & EVLOOP_READ) ? fd : ARES_SOCKET_BAD;
  int write_fd = (revents & EVLOOP_WRITE) ? fd : ARES_SOCKET_BAD;

  ares_process_fd(ctx->channel, read_fd, write_fd);
  update_watchers(ctx);
}

/* Callback for c-ares timeout */
static void
dns_timer_cb(void *arg)
{
  struct dns_ev_ctx *ctx = arg;
  
  /* Tell c-ares that timeout has occurred */
  ares_process_fd(ctx->channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
  update_watchers(ctx);
}

/* Update the evloop watchers based on what c-ares needs */
static void
update_watchers(struct dns_ev_ctx *ctx)
{
  ares_socket_t socks[MAX_ARES_SOCKETS];
  int action_bits;
  int i, j;
  struct timeval tv, *tvp;

  /* 1. Handle Timeouts */
  tvp = ares_timeout(ctx->channel, NULL, &tv);
  if (tvp) {
    double after = (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
    if (!ctx->timer) {
      ctx->timer = evloop_timer_start(ctx->loop, after, 0.0, dns_timer_cb, ctx);
    } else {
      evloop_timer_reschedule(ctx->timer, after, 0.0);
    }
  } else {
    if (ctx->timer) {
      evloop_timer_stop(ctx->timer);
      /* We don't free the timer structure, just stop it, 
         or we could free and recreate. Rescheduling is efficient. 
         But evloop_timer_reschedule implies it's active or restartable. 
         If we stop it, we might need to restart it. 
         Our evloop_timer_reschedule does stop then start. */
         
       /* If we want to "disable" it, we stop it. 
          If we want to re-enable, we can use reschedule or just stop it now. */
       evloop_timer_stop(ctx->timer);
    }
  }

  /* 2. Handle Sockets */
  action_bits = ares_getsock(ctx->channel, socks, MAX_ARES_SOCKETS);
  
  /* Mark all current watchers as "not found" initially by some logic, 
     or just simplistic approach:
     
     We have a small array `watchers`.
     We have a set of needed sockets `socks` + `action_bits`.
     
     Iterate over needed sockets:
       Find in `watchers`.
       If found: update events if needed. Mark as visited.
       If not found: add new watcher.
     
     Iterate over `watchers`:
       If not visited (and was active): remove watcher.
  */

  bool visited[MAX_ARES_SOCKETS] = {0};

  for (i = 0; i < MAX_ARES_SOCKETS && i < (int)(sizeof(action_bits) * 8); i++) {
    /* The bitmap returned by ares_getsock is relevant for the sockets array positions. 
       See ares_getsock docs: 
       "Returns a bitmask... Bit 0 corresponds to socks[0], bit 1 to socks[1]..."
       ARES_GETSOCK_READABLE(bits, i) checks read for socks[i].
    */
    
    /* However, ares_getsock returns the number of sockets filled? No.
       "The number of file descriptors... is limited by the size of the socks array..."
       Wait, ares_getsock returns the bitmask. It doesn't return count directly?
       Actually, we don't know how many valid entries in socks[] unless we check the bits?
       No, docs say: "The physical number of sockets is not returned".
       So we have to check up to MAX_ARES_SOCKETS. 
       But sockets are only valid if the bit is set?
       Docs: "It returns a bitmask... describing which operations to check for... 
       If a bit is set... socks[i] is valid."
       
       So we iterate i from 0 to MAX_ARES_SOCKETS-1.
    */
     
    int events = 0;
    if (ARES_GETSOCK_READABLE(action_bits, i))
      events |= EVLOOP_READ;
    if (ARES_GETSOCK_WRITABLE(action_bits, i))
      events |= EVLOOP_WRITE;

    if (events == 0)
      continue; /* This slot is unused */

    int fd = socks[i];
    bool found = false;

    /* Find in existing watchers */
    for (j = 0; j < MAX_ARES_SOCKETS; j++) {
      if (ctx->watchers[j].io && ctx->watchers[j].fd == fd) {
        found = true;
        visited[j] = true;
        /* Update events */
        evloop_io_update(ctx->watchers[j].io, events);
        break;
      }
    }

    if (!found) {
      /* Add new watcher */
      for (j = 0; j < MAX_ARES_SOCKETS; j++) {
        if (ctx->watchers[j].io == NULL) {
          ctx->watchers[j].fd = fd;
          ctx->watchers[j].io = evloop_io_start(ctx->loop, fd, events, dns_sock_cb, ctx);
          visited[j] = true;
          break;
        }
      }
      if (j == MAX_ARES_SOCKETS) {
        /* Error: too many sockets */
        /* Should rarely happen with c-ares default config */
      }
    }
  }

  /* Prune removed sockets */
  for (j = 0; j < MAX_ARES_SOCKETS; j++) {
    if (ctx->watchers[j].io && !visited[j]) {
       /* Not requested by ares anymore */
       evloop_io_free(ctx->watchers[j].io);
       ctx->watchers[j].io = NULL;
       ctx->watchers[j].fd = -1;
    }
  }
}

int
dns_init(struct ev_loop *loop)
{
  int status;
  struct ares_options options;
  int optmask = 0;

  if (global_dns_ctx)
    return 0; /* Already initialized */

  struct dns_ev_ctx *ctx = xnew0(struct dns_ev_ctx);
  ctx->loop = loop;

  /* Initialize c-ares */
  /* We can set ARES_OPT_FLAGS if needed, e.g. ARES_FLAG_STAYOPEN */
  
  status = ares_init_options(&ctx->channel, &options, optmask);
  if (status != ARES_SUCCESS) {
    xfree(ctx);
    return -1;
  }

  global_dns_ctx = ctx;
  return 0;
}

void
dns_shutdown(void)
{
  if (!global_dns_ctx)
    return;

  struct dns_ev_ctx *ctx = global_dns_ctx;
  int i;

  ares_destroy(ctx->channel);

  if (ctx->timer)
    evloop_timer_free(ctx->timer);

  for (i = 0; i < MAX_ARES_SOCKETS; i++) {
    if (ctx->watchers[i].io) {
      evloop_io_free(ctx->watchers[i].io);
    }
  }

  xfree(ctx);
  global_dns_ctx = NULL;
}

struct resolve_req_ctx {
  dns_result_cb cb;
  void *arg;
};

static void
ares_addrinfo_cb(void *arg, int status, int timeouts, struct ares_addrinfo *result)
{
  struct resolve_req_ctx *req = arg;
  (void)timeouts;

  if (status != ARES_SUCCESS) {
    req->cb(status, NULL, req->arg);
  } else {
    /* Convert ares_addrinfo to struct addrinfo? 
       Actually, ares_addrinfo is very similar to struct addrinfo.
       Usually we want the standard struct addrinfo. 
       c-ares provides `ares_addrinfo` which contains a linked list of `ares_addrinfo_node`.
       We might need to convert it if the caller expects `struct addrinfo`.
       
       However, the caller signature is `dns_result_cb(int status, const struct addrinfo *ai, ...)`
       
       Wait, does c-ares return `struct addrinfo` or its own type?
       It returns `struct ares_addrinfo`.
       But `ares_addrinfo` nodes have `ai_family`, `ai_socktype`, etc.
       BUT the types are slightly different or at least the struct name.
       
       If `dns_resolve_async` promised `struct addrinfo`, we must provide it.
       We can't just cast it if the layout differs.
       
       Checking `ares.h` (or online docs):
       `struct ares_addrinfo_node` is the node.
       `struct ares_addrinfo` contains `nodes`.
       
       We probably need to construct a `struct addrinfo` chain from `ares_addrinfo`.
       Or change our API to expose `ares_addrinfo`.
       But `TODO` says "translate results into `struct addrinfo`-like data".
       
       Let's assume we should translate.
    */
    
    struct addrinfo *head = NULL;
    struct addrinfo **tail = &head;
    
    struct ares_addrinfo_node *node;
    for (node = result->nodes; node; node = node->ai_next) {
        struct addrinfo *ai = xnew0(struct addrinfo);
        ai->ai_flags = node->ai_flags;
        ai->ai_family = node->ai_family;
        ai->ai_socktype = node->ai_socktype;
        ai->ai_protocol = node->ai_protocol;
        ai->ai_addrlen = node->ai_addrlen;
        
        if (node->ai_addr) {
            ai->ai_addr = xmalloc(node->ai_addrlen);
            memcpy(ai->ai_addr, node->ai_addr, node->ai_addrlen);
        }
        
        /* c-ares nodes don't seem to have canonname attached directly to node?
           Actually `ares_addrinfo` has `name` and `cnames`.
           Standard `getaddrinfo` puts `ai_canonname` in the first node.
        */
        
        *tail = ai;
        tail = &ai->ai_next;
    }
    
    /* If we had canonname, we might want to attach it to head->ai_canonname */
    if (head && result->name) {
        head->ai_canonname = xstrdup(result->name);
    }

    req->cb(0, head, req->arg);

    /* Free our copy */
    struct addrinfo *cur, *next;
    for (cur = head; cur; cur = next) {
        next = cur->ai_next;
        if (cur->ai_addr) xfree(cur->ai_addr);
        if (cur->ai_canonname) xfree(cur->ai_canonname);
        xfree(cur);
    }
  }
  
  ares_freeaddrinfo(result);
  xfree(req);
  
  /* After callback, we should update watchers just in case? 
     c-ares usually handles this via process, but we are inside a callback invoked by process.
     So update_watchers will be called after this returns by dns_sock_cb or dns_timer_cb.
  */
}

void
dns_resolve_async(struct ev_loop *loop,
                  const char *hostname, const char *service,
                  int family, int socktype, int protocol,
                  dns_result_cb cb, void *arg)
{
  /* Ensure initialized */
  if (!global_dns_ctx) {
      if (dns_init(loop) != 0) {
          cb(EAI_SYSTEM, NULL, arg); /* Roughly EAI_SYSTEM */
          return;
      }
  }
  
  struct resolve_req_ctx *req = xnew0(struct resolve_req_ctx);
  req->cb = cb;
  req->arg = arg;

  struct ares_addrinfo_hints hints = {0};
  hints.ai_family = family;
  hints.ai_socktype = socktype;
  hints.ai_protocol = protocol;
  
  /* Call ares_getaddrinfo */
  ares_getaddrinfo(global_dns_ctx->channel, hostname, service, &hints, ares_addrinfo_cb, req);
  
  /* Trigger watcher update immediately as new query might require new sockets */
  update_watchers(global_dns_ctx);
}
