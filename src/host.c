/* Host name resolution and matching.
 * src/host.c
 */

#include "wget.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifndef __BEOS__
#include <arpa/inet.h>
#endif
#include <netdb.h>
#define SET_H_ERRNO(err) ((void)(h_errno = (err)))

#include <errno.h>

#include "utils.h"
#include "host.h"
#include "url.h"
#include "hash.h"
#include "ptimer.h"
#include "threading.h"
#include "evloop.h"

#ifndef NO_ADDRESS
#define NO_ADDRESS NO_DATA
#endif

#if !HAVE_DECL_H_ERRNO
extern int h_errno;
#endif

/* Lists of IP addresses that result from running DNS queries.  See
   lookup_host for details.  */

struct address_list {
  int count;             /* number of addresses */
  ip_address* addresses; /* pointer to the string of addresses */

  int faulty;     /* number of addresses known not to work. */
  bool connected; /* whether we were able to connect to
                     one of the addresses in the list,
                     at least once. */

  int refcount; /* reference count; when it drops to
                   0, the entry is freed. */
};

/* Get the bounds of the address list.  */

void address_list_get_bounds(const struct address_list* al, int* start, int* end) {
  *start = al->faulty;
  *end = al->count;
}

/* Return a pointer to the address at position POS.  */

const ip_address* address_list_address_at(const struct address_list* al, int pos) {
  assert(pos >= al->faulty && pos < al->count);
  return al->addresses + pos;
}

/* Return true if AL contains IP, false otherwise.  */

bool address_list_contains(const struct address_list* al, const ip_address* ip) {
  int i;
  switch (ip->family) {
    case AF_INET:
      for (i = 0; i < al->count; i++) {
        ip_address* cur = al->addresses + i;
        if (cur->family == AF_INET && (cur->data.d4.s_addr == ip->data.d4.s_addr))
          return true;
      }
      return false;
#ifdef ENABLE_IPV6
    case AF_INET6:
      for (i = 0; i < al->count; i++) {
        ip_address* cur = al->addresses + i;
        if (cur->family == AF_INET6
#ifdef HAVE_SOCKADDR_IN6_SCOPE_ID
            && cur->ipv6_scope == ip->ipv6_scope
#endif
            && IN6_ARE_ADDR_EQUAL(&cur->data.d6, &ip->data.d6))
          return true;
      }
      return false;
#endif /* ENABLE_IPV6 */
    default:
      abort();
  }
}

/* Mark the INDEXth element of AL as faulty, so that the next time
   this address list is used, the faulty element will be skipped.  */

void address_list_set_faulty(struct address_list* al, int index) {
  /* We assume that the address list is traversed in order, so that a
     "faulty" attempt is always preceded with all-faulty addresses,
     and this is how Wget uses it.  */
  assert(index == al->faulty);
  if (index != al->faulty) {
    logprintf(LOG_ALWAYS, "index: %d\nal->faulty: %d\n", index, al->faulty);
    logprintf(LOG_ALWAYS, _("Error in handling the address list.\n"));
    logprintf(LOG_ALWAYS, _("Please report this issue to bug-wget@gnu.org\n"));
    abort();
  }

  ++al->faulty;
  if (al->faulty >= al->count)
    /* All addresses have been proven faulty.  Since there's not much
       sense in returning the user an empty address list the next
       time, we'll rather make them all clean, so that they can be
       retried anew.  */
    al->faulty = 0;
}

/* Set the "connected" flag to true.  This flag used by connect.c to
   see if the host perhaps needs to be resolved again.  */

void address_list_set_connected(struct address_list* al) {
  al->connected = true;
}

/* Return the value of the "connected" flag. */

bool address_list_connected_p(const struct address_list* al) {
  return al->connected;
}

#ifdef ENABLE_IPV6

/* Create an address_list from the addresses in the given struct
   addrinfo.  */

static struct address_list* address_list_from_addrinfo(const struct addrinfo* ai) {
  struct address_list* al;
  const struct addrinfo* ptr;
  int cnt;
  ip_address* ip;

  cnt = 0;
  for (ptr = ai; ptr != NULL; ptr = ptr->ai_next)
    if (ptr->ai_family == AF_INET || ptr->ai_family == AF_INET6)
      ++cnt;
  if (cnt == 0)
    return NULL;

  al = xnew0(struct address_list);
  al->addresses = xnew_array(ip_address, cnt);
  al->count = cnt;
  al->refcount = 1;

  ip = al->addresses;
  for (ptr = ai; ptr != NULL; ptr = ptr->ai_next)
    if (ptr->ai_family == AF_INET6) {
      const struct sockaddr_in6* sin6 = (const struct sockaddr_in6*)ptr->ai_addr;
      ip->family = AF_INET6;
      ip->data.d6 = sin6->sin6_addr;
#ifdef HAVE_SOCKADDR_IN6_SCOPE_ID
      ip->ipv6_scope = sin6->sin6_scope_id;
#endif
      ++ip;
    }
    else if (ptr->ai_family == AF_INET) {
      const struct sockaddr_in* sin = (const struct sockaddr_in*)ptr->ai_addr;
      ip->family = AF_INET;
      ip->data.d4 = sin->sin_addr;
      ++ip;
    }
  assert(ip - al->addresses == cnt);
  return al;
}

#define IS_IPV4(addr) (((const ip_address*)addr)->family == AF_INET)

/* Compare two IP addresses by family, giving preference to the IPv4
   address (sorting it first).  In other words, return -1 if ADDR1 is
   IPv4 and ADDR2 is IPv6, +1 if ADDR1 is IPv6 and ADDR2 is IPv4, and
   0 otherwise.

   This is intended to be used as the comparator arg to a qsort-like
   sorting function, which is why it accepts generic pointers.  */

static int cmp_prefer_ipv4(const void* addr1, const void* addr2) {
  return !IS_IPV4(addr1) - !IS_IPV4(addr2);
}

#define IS_IPV6(addr) (((const ip_address*)addr)->family == AF_INET6)

/* Like the above, but give preference to the IPv6 address.  */

static int cmp_prefer_ipv6(const void* addr1, const void* addr2) {
  return !IS_IPV6(addr1) - !IS_IPV6(addr2);
}

#else /* not ENABLE_IPV6 */

/* Create an address_list from a NULL-terminated vector of IPv4
   addresses.  This kind of vector is returned by gethostbyname.  */

static struct address_list* address_list_from_ipv4_addresses(char** vec) {
  int count, i;
  struct address_list* al = xnew0(struct address_list);

  count = 0;
  while (vec[count])
    ++count;
  assert(count > 0);

  al->addresses = xnew_array(ip_address, count);
  al->count = count;
  al->refcount = 1;

  for (i = 0; i < count; i++) {
    ip_address* ip = &al->addresses[i];
    ip->family = AF_INET;
    memcpy(IP_INADDR_DATA(ip), vec[i], 4);
  }

  return al;
}

#endif /* not ENABLE_IPV6 */

static void address_list_delete(struct address_list* al) {
  xfree(al->addresses);
  xfree(al);
}

/* Mark the address list as being no longer in use.  This will reduce
   its reference count which will cause the list to be freed when the
   count reaches 0.  */

void address_list_release(struct address_list* al) {
  --al->refcount;
  DEBUGP(("Releasing 0x%0*lx (new refcount %d).\n", PTR_FORMAT(al), al->refcount));
  if (al->refcount <= 0) {
    DEBUGP(("Deleting unused 0x%0*lx.\n", PTR_FORMAT(al)));
    address_list_delete(al);
  }
}

/* Versions of gethostbyname and getaddrinfo that support timeout. */

#ifndef ENABLE_IPV6

struct ghbnwt_context {
  const char* host_name;
  struct hostent* hptr;
};

static void gethostbyname_with_timeout_callback(void* arg) {
  struct ghbnwt_context* ctx = (struct ghbnwt_context*)arg;
  ctx->hptr = gethostbyname(ctx->host_name);
}

/* Just like gethostbyname, except it times out after TIMEOUT seconds.
   In case of timeout, NULL is returned and errno is set to ETIMEDOUT.
   The function makes sure that when NULL is returned for reasons
   other than timeout, errno is reset.  */

static struct hostent* gethostbyname_with_timeout(const char* host_name, double timeout) {
  struct ghbnwt_context ctx;
  ctx.host_name = host_name;
  if (run_with_timeout(timeout, gethostbyname_with_timeout_callback, &ctx)) {
    SET_H_ERRNO(HOST_NOT_FOUND);
    errno = ETIMEDOUT;
    return NULL;
  }
  if (!ctx.hptr)
    errno = 0;
  return ctx.hptr;
}

/* Print error messages for host errors.  */
static const char* host_errstr(int error) {
  /* Can't use switch since some of these constants can be equal,
     which makes the compiler complain about duplicate case
     values.  */
  if (error == HOST_NOT_FOUND || error == NO_RECOVERY || error == NO_DATA || error == NO_ADDRESS)
    return _("Unknown host");
  else if (error == TRY_AGAIN)
    /* Message modeled after what gai_strerror returns in similar
       circumstances.  */
    return _("Temporary failure in name resolution");
  else
    return _("Unknown error");
}

#else /* ENABLE_IPV6 */

struct gaiwt_context {
  const char* node;
  const char* service;
  const struct addrinfo* hints;
  struct addrinfo** res;
  int exit_code;
};

static void getaddrinfo_with_timeout_callback(void* arg) {
  struct gaiwt_context* ctx = (struct gaiwt_context*)arg;
  ctx->exit_code = getaddrinfo(ctx->node, ctx->service, ctx->hints, ctx->res);
}

/* Just like getaddrinfo, except it times out after TIMEOUT seconds.
   In case of timeout, the EAI_SYSTEM error code is returned and errno
   is set to ETIMEDOUT.  */

static int getaddrinfo_with_timeout(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res, double timeout) {
  struct gaiwt_context ctx;
  ctx.node = node;
  ctx.service = service;
  ctx.hints = hints;
  ctx.res = res;

  if (run_with_timeout(timeout, getaddrinfo_with_timeout_callback, &ctx)) {
    errno = ETIMEDOUT;
    return EAI_SYSTEM;
  }
  return ctx.exit_code;
}

#endif /* ENABLE_IPV6 */

/* Return a textual representation of ADDR, i.e. the dotted quad for
   IPv4 addresses, and the colon-separated list of hex words (with all
   zeros omitted, etc.) for IPv6 addresses.  */

const char* print_address(const ip_address* addr) {
  static char buf[64];

  if (!inet_ntop(addr->family, IP_INADDR_DATA(addr), buf, sizeof buf))
    snprintf(buf, sizeof buf, "<error: %s>", strerror(errno));

  return buf;
}

/* The following two functions were adapted from glibc's
   implementation of inet_pton, written by Paul Vixie. */

static bool is_valid_ipv4_address(const char* str, const char* end) {
  bool saw_digit = false;
  int octets = 0;
  int val = 0;

  while (str < end) {
    int ch = *str++;

    if (ch >= '0' && ch <= '9') {
      val = val * 10 + (ch - '0');

      if (val > 255)
        return false;
      if (!saw_digit) {
        if (++octets > 4)
          return false;
        saw_digit = true;
      }
    }
    else if (ch == '.' && saw_digit) {
      if (octets == 4)
        return false;
      val = 0;
      saw_digit = false;
    }
    else
      return false;
  }
  if (octets < 4)
    return false;

  return true;
}

bool is_valid_ipv6_address(const char* str, const char* end) {
  /* Use lower-case for these to avoid clash with system headers.  */
  enum { ns_inaddrsz = 4, ns_in6addrsz = 16, ns_int16sz = 2 };

  const char* curtok;
  int tp;
  const char* colonp;
  bool saw_xdigit;
  unsigned int val;

  tp = 0;
  colonp = NULL;

  if (str == end)
    return false;

  /* Leading :: requires some special handling. */
  if (*str == ':') {
    ++str;
    if (str == end || *str != ':')
      return false;
  }

  curtok = str;
  saw_xdigit = false;
  val = 0;

  while (str < end) {
    int ch = *str++;

    /* if ch is a number, add it to val. */
    if (c_isxdigit(ch)) {
      val <<= 4;
      val |= _unhex(ch);
      if (val > 0xffff)
        return false;
      saw_xdigit = true;
      continue;
    }

    /* if ch is a colon ... */
    if (ch == ':') {
      curtok = str;
      if (!saw_xdigit) {
        if (colonp != NULL)
          return false;
        colonp = str + tp;
        continue;
      }
      else if (str == end)
        return false;
      if (tp > ns_in6addrsz - ns_int16sz)
        return false;
      tp += ns_int16sz;
      saw_xdigit = false;
      val = 0;
      continue;
    }

    /* if ch is a dot ... */
    if (ch == '.' && (tp <= ns_in6addrsz - ns_inaddrsz) && is_valid_ipv4_address(curtok, end) == 1) {
      tp += ns_inaddrsz;
      saw_xdigit = false;
      break;
    }

    return false;
  }

  if (saw_xdigit) {
    if (tp > ns_in6addrsz - ns_int16sz)
      return false;
    tp += ns_int16sz;
  }

  if (colonp != NULL) {
    if (tp == ns_in6addrsz)
      return false;
    tp = ns_in6addrsz;
  }

  if (tp != ns_in6addrsz)
    return false;

  return true;
}

/* Simple host cache, used by lookup_host to speed up resolving.  The
   cache doesn't handle TTL because Wget is a fairly short-lived
   application.  Refreshing is attempted when connect fails, though --
   see connect_to_host.  */

/* Mapping between known hosts and to lists of their addresses. */
static struct hash_table* host_name_addresses_map;
static wget_mutex_t dns_cache_lock = WGET_MUTEX_INITIALIZER;

/* Return the host's resolved addresses from the cache, if
   available.  */

static struct address_list* cache_query(const char* host) {
  struct address_list* al = NULL;

  wget_mutex_lock(&dns_cache_lock);
  if (host_name_addresses_map) {
    al = hash_table_get(host_name_addresses_map, host);
    if (al)
      ++al->refcount;
  }
  wget_mutex_unlock(&dns_cache_lock);

  if (al)
    DEBUGP(("Found %s in host_name_addresses_map (%p)\n", host, (void*)al));

  return al;
}

/* Cache the DNS lookup of HOST.  Subsequent invocations of
   lookup_host will return the cached value.  */

static void cache_store(const char* host, struct address_list* al) {
  wget_mutex_lock(&dns_cache_lock);
  if (!host_name_addresses_map)
    host_name_addresses_map = make_nocase_string_hash_table(0);

  ++al->refcount;
  hash_table_put(host_name_addresses_map, xstrdup_lower(host), al);
  wget_mutex_unlock(&dns_cache_lock);

  IF_DEBUG {
    int i;
    debug_logprintf("Caching %s =>", host);
    for (i = 0; i < al->count; i++)
      debug_logprintf(" %s", print_address(al->addresses + i));
    debug_logprintf("\n");
  }
}

/* Remove HOST from the DNS cache.  Does nothing is HOST is not in
   the cache.  */

static void cache_remove(const char* host) {
  struct address_list* al;
  wget_mutex_lock(&dns_cache_lock);
  if (!host_name_addresses_map) {
    wget_mutex_unlock(&dns_cache_lock);
    return;
  }
  al = hash_table_get(host_name_addresses_map, host);
  if (al) {
    address_list_release(al);
    hash_table_remove(host_name_addresses_map, host);
  }
  wget_mutex_unlock(&dns_cache_lock);
}

#ifdef HAVE_LIBCARES
#include <ares.h>
#include <ev.h>
extern ares_channel ares;

struct ares_options;

struct ares_socket_watch {
  ares_socket_t fd;
  ev_io io;
  int events;
};

struct dns_query_ctx {
  struct address_list* result;
  int status;
  bool complete;
};

static struct ares_socket_watch** ares_watches;
static size_t ares_watch_count;
static ev_timer ares_timer;
static bool ares_timer_active;
static void ares_clear_socket_state(void) WGET_ATTR_UNUSED;
static void ares_timeout_cb(EV_P_ ev_timer* w, int revents);
static void ares_update_timer(void);
static bool dns_wait_for_completion(struct dns_query_ctx* ctx);

static struct ares_socket_watch* ares_watch_by_fd(ares_socket_t fd, size_t* index_out) {
  size_t i;

  for (i = 0; i < ares_watch_count; ++i) {
    if (ares_watches[i]->fd == fd) {
      if (index_out)
        *index_out = i;
      return ares_watches[i];
    }
  }

  if (index_out)
    *index_out = SIZE_MAX;
  return NULL;
}

static void ares_remove_watch_index(struct ev_loop* loop, size_t index) {
  struct ares_socket_watch* watch = ares_watches[index];

  ev_io_stop(loop, &watch->io);
  xfree(watch);

  if (index + 1 < ares_watch_count)
    memmove(&ares_watches[index], &ares_watches[index + 1], (ares_watch_count - index - 1) * sizeof(*ares_watches));

  --ares_watch_count;
  if (ares_watch_count == 0) {
    xfree(ares_watches);
    ares_watches = NULL;
  }
}

static void ares_clear_socket_state(void) {
  if (!wget_ev_loop_is_initialized())
    return;

  struct ev_loop* loop = wget_ev_loop_get();

  while (ares_watch_count > 0)
    ares_remove_watch_index(loop, ares_watch_count - 1);

  if (ares_timer_active) {
    ev_timer_stop(loop, &ares_timer);
    ares_timer_active = false;
  }
}

static void ares_update_timer(void) {
  struct ev_loop* loop = wget_ev_loop_get();
  struct timeval tv;
  struct timeval* tvp = ares_timeout(ares, NULL, &tv);

  if (!tvp) {
    if (ares_timer_active) {
      ev_timer_stop(loop, &ares_timer);
      ares_timer_active = false;
    }
    return;
  }

  double after = tvp->tv_sec + (double)tvp->tv_usec / 1000000.0;
  if (after < 0)
    after = 0;

  if (ares_timer_active)
    ev_timer_stop(loop, &ares_timer);

  ev_timer_init(&ares_timer, ares_timeout_cb, after, 0.);
  ev_timer_start(loop, &ares_timer);
  ares_timer_active = true;
}

static void ares_timeout_cb(EV_P_ ev_timer* w WGET_ATTR_UNUSED, int revents WGET_ATTR_UNUSED) {
  ares_timer_active = false;
  ares_process_fd(ares, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
  ares_update_timer();
}

static void ares_io_cb(EV_P_ ev_io* w, int revents) {
  struct ares_socket_watch* watch = (struct ares_socket_watch*)w->data;
  ares_socket_t read_fd = (revents & EV_READ) ? watch->fd : ARES_SOCKET_BAD;
  ares_socket_t write_fd = (revents & EV_WRITE) ? watch->fd : ARES_SOCKET_BAD;

  ares_process_fd(ares, read_fd, write_fd);
  ares_update_timer();
}

static bool dns_wait_for_completion(struct dns_query_ctx* ctx) {
  struct ptimer* timer = NULL;
  bool timed_out = false;

  if (opt.dns_timeout > 0)
    timer = ptimer_new();

  while (!ctx->complete) {
    if (timer && ptimer_measure(timer) >= opt.dns_timeout) {
      timed_out = true;
      ares_cancel(ares);
      ares_update_timer();
      break;
    }

    wget_ev_loop_run_once();
  }

  if (timer)
    ptimer_destroy(timer);

  return !timed_out && ctx->complete;
}

static struct address_list* address_list_from_ares_nodes(const struct ares_addrinfo_node* nodes) {
  struct address_list* al;
  const struct ares_addrinfo_node* ptr;
  ip_address* ip;
  int count = 0;

  for (ptr = nodes; ptr != NULL; ptr = ptr->ai_next)
    if (ptr->ai_family == AF_INET
#ifdef ENABLE_IPV6
        || ptr->ai_family == AF_INET6
#endif
    )
      ++count;

  if (count == 0)
    return NULL;

  al = xnew0(struct address_list);
  al->addresses = xnew_array(ip_address, count);
  al->count = count;
  al->refcount = 1;

  ip = al->addresses;
  for (ptr = nodes; ptr != NULL; ptr = ptr->ai_next) {
    if (ptr->ai_family == AF_INET) {
      const struct sockaddr_in* sin = (const struct sockaddr_in*)ptr->ai_addr;
      ip->family = AF_INET;
      ip->data.d4 = sin->sin_addr;
      ++ip;
    }
#ifdef ENABLE_IPV6
    else if (ptr->ai_family == AF_INET6) {
      const struct sockaddr_in6* sin6 = (const struct sockaddr_in6*)ptr->ai_addr;
      ip->family = AF_INET6;
      ip->data.d6 = sin6->sin6_addr;
#ifdef HAVE_SOCKADDR_IN6_SCOPE_ID
      ip->ipv6_scope = sin6->sin6_scope_id;
#endif
      ++ip;
    }
#endif
  }

  return al;
}

static void wget_ares_addrinfo_callback(void* arg, int status, int timeouts WGET_ATTR_UNUSED, struct ares_addrinfo* info) {
  struct dns_query_ctx* ctx = (struct dns_query_ctx*)arg;

  ctx->status = status;
  ctx->result = NULL;

  if (info && status == ARES_SUCCESS)
    ctx->result = address_list_from_ares_nodes(info->nodes);

  if (info)
    ares_freeaddrinfo(info);

  ctx->complete = true;
}

static void host_ares_socket_state_cb(void* data WGET_ATTR_UNUSED, ares_socket_t socket_fd, int readable, int writable) {
  struct ev_loop* loop = wget_ev_loop_get();
  int events = (readable ? EV_READ : 0) | (writable ? EV_WRITE : 0);
  size_t index = SIZE_MAX;
  struct ares_socket_watch* watch = ares_watch_by_fd(socket_fd, &index);

  if (events == 0) {
    if (watch && index != SIZE_MAX)
      ares_remove_watch_index(loop, index);
  }
  else if (!watch) {
    watch = xnew0(struct ares_socket_watch);
    watch->fd = socket_fd;
    watch->events = events;
    ev_io_init(&watch->io, ares_io_cb, socket_fd, events);
    watch->io.data = watch;
    ev_io_start(loop, &watch->io);

    ares_watches = xrealloc(ares_watches, (ares_watch_count + 1) * sizeof(*ares_watches));
    ares_watches[ares_watch_count++] = watch;
  }
  else if (watch->events != events) {
    ev_io_stop(loop, &watch->io);
    ev_io_set(&watch->io, socket_fd, events);
    watch->events = events;
    ev_io_start(loop, &watch->io);
  }

  ares_update_timer();
}

void host_prepare_ares_options(struct ares_options* options, int* optmask) {
  if (!options || !optmask)
    return;

  options->sock_state_cb = host_ares_socket_state_cb;
  options->sock_state_cb_data = NULL;
  *optmask |= ARES_OPT_SOCK_STATE_CB;
}
#endif

/* Look up HOST in DNS and return a list of IP addresses.

   This function caches its result so that, if the same host is passed
   the second time, the addresses are returned without DNS lookup.
   (Use LH_REFRESH to force lookup, or set opt.dns_cache to 0 to
   globally disable caching.)

   The order of the returned addresses is affected by the setting of
   opt.prefer_family: if it is set to prefer_ipv4, IPv4 addresses are
   placed at the beginning; if it is prefer_ipv6, IPv6 ones are placed
   at the beginning; otherwise, the order is left intact.  The
   relative order of addresses with the same family is left
   undisturbed in either case.

   FLAGS can be a combination of:
     LH_SILENT  - don't print the "resolving ... done" messages.
     LH_BIND    - resolve addresses for use with bind, which under
                  IPv6 means to use AI_PASSIVE flag to getaddrinfo.
                  Passive lookups are not cached under IPv6.
     LH_REFRESH - if HOST is cached, remove the entry from the cache
                  and resolve it anew.  */

struct address_list* lookup_host(const char* host, int flags) {
  struct address_list* al;
  bool silent = !!(flags & LH_SILENT);
  bool use_cache;
  bool numeric_address = false;
  double timeout = opt.dns_timeout;

#ifndef ENABLE_IPV6
  /* If we're not using getaddrinfo, first check if HOST specifies a
     numeric IPv4 address.  Some implementations of gethostbyname
     (e.g. the Ultrix one and possibly Winsock) don't accept
     dotted-decimal IPv4 addresses.  */
  {
    uint32_t addr_ipv4 = (uint32_t)inet_addr(host);
    if (addr_ipv4 != (uint32_t)-1) {
      /* No need to cache host->addr relation, just return the
         address.  */
      char* vec[2];
      vec[0] = (char*)&addr_ipv4;
      vec[1] = NULL;
      return address_list_from_ipv4_addresses(vec);
    }
  }
#else /* ENABLE_IPV6 */
  /* If we're using getaddrinfo, at least check whether the address is
     already numeric, in which case there is no need to print the
     "Resolving..." output.  (This comes at no additional cost since
     the is_valid_ipv*_address are already required for
     url_parse.)  */
  {
    const char* end = host + strlen(host);
    if (is_valid_ipv4_address(host, end) || is_valid_ipv6_address(host, end))
      numeric_address = true;
  }
#endif

  /* Cache is normally on, but can be turned off with --no-dns-cache.
     Don't cache passive lookups under IPv6.  */
  use_cache = opt.dns_cache;
#ifdef ENABLE_IPV6
  if ((flags & LH_BIND) || numeric_address)
    use_cache = false;
#endif

  /* Try to find the host in the cache so we don't need to talk to the
     resolver.  If LH_REFRESH is requested, remove HOST from the cache
     instead.  */
  if (use_cache) {
    if (!(flags & LH_REFRESH)) {
      al = cache_query(host);
      if (al)
        return al;
    }
    else
      cache_remove(host);
  }

  /* No luck with the cache; resolve HOST. */

  if (!silent && !numeric_address) {
    char *str = NULL, *name;

    if (opt.enable_iri && (name = idn_decode((char*)host)) != NULL) {
      str = aprintf("%s (%s)", name, host);
      xfree(name);
    }

    logprintf(LOG_VERBOSE, _("Resolving %s... "), quotearg_style(escape_quoting_style, str ? str : host));

    xfree(str);
  }

#ifdef ENABLE_IPV6
#ifdef HAVE_LIBCARES
  if (ares) {
    struct ares_addrinfo_hints hints;
    struct dns_query_ctx async_ctx;
    bool completed;

    xzero(hints);
    hints.ai_socktype = SOCK_STREAM;
    if (opt.ipv4_only)
      hints.ai_family = AF_INET;
    else if (opt.ipv6_only)
      hints.ai_family = AF_INET6;
    else
      hints.ai_family = AF_UNSPEC;
    if (flags & LH_BIND)
      hints.ai_flags |= AI_PASSIVE;

    xzero(async_ctx);
    ares_getaddrinfo(ares, host, NULL, &hints, wget_ares_addrinfo_callback, &async_ctx);
    ares_update_timer();
    completed = dns_wait_for_completion(&async_ctx);
    if (!completed) {
      if (!silent)
        logputs(LOG_VERBOSE, _("failed: timed out.\n"));
      return NULL;
    }

    if (async_ctx.status != ARES_SUCCESS) {
      if (!silent)
        logprintf(LOG_VERBOSE, _("failed: %s.\n"), ares_strerror(async_ctx.status));
      return NULL;
    }

    al = async_ctx.result;
  }
  else
#endif
  {
    int err;
    struct addrinfo hints, *res;

    xzero(hints);
    hints.ai_socktype = SOCK_STREAM;
    if (opt.ipv4_only)
      hints.ai_family = AF_INET;
    else if (opt.ipv6_only)
      hints.ai_family = AF_INET6;
    else
      /* We tried using AI_ADDRCONFIG, but removed it because: it
         misinterprets IPv6 loopbacks, it is broken on AIX 5.1, and
         it's unneeded since we sort the addresses anyway.  */
      hints.ai_family = AF_UNSPEC;

    if (flags & LH_BIND)
      hints.ai_flags |= AI_PASSIVE;

#ifdef AI_NUMERICHOST
    if (numeric_address) {
      /* Where available, the AI_NUMERICHOST hint can prevent costly
         access to DNS servers.  */
      hints.ai_flags |= AI_NUMERICHOST;
      timeout = 0; /* no timeout needed when "resolving"
                               numeric hosts -- avoid setting up
                               signal handlers and such. */
    }
#endif

    err = getaddrinfo_with_timeout(host, NULL, &hints, &res, timeout);

    if (err != 0 || res == NULL) {
      if (!silent)
        logprintf(LOG_VERBOSE, _("failed: %s.\n"), err != EAI_SYSTEM ? gai_strerror(err) : strerror(errno));
      return NULL;
    }
    al = address_list_from_addrinfo(res);
    freeaddrinfo(res);
  }

  if (!al) {
    logprintf(LOG_VERBOSE, _("failed: No IPv4/IPv6 addresses for host.\n"));
    return NULL;
  }

  /* Reorder addresses so that IPv4 ones (or IPv6 ones, as per
     --prefer-family) come first.  Sorting is stable so the order of
     the addresses with the same family is undisturbed.  */
  if (al->count > 1 && opt.prefer_family != prefer_none)
    stable_sort(al->addresses, al->count, sizeof(ip_address), opt.prefer_family == prefer_ipv4 ? cmp_prefer_ipv4 : cmp_prefer_ipv6);
#else /* not ENABLE_IPV6 */
#ifdef HAVE_LIBCARES
  if (ares) {
    struct ares_addrinfo_hints hints;
    struct dns_query_ctx async_ctx;
    bool completed;

    xzero(hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (flags & LH_BIND)
      hints.ai_flags |= AI_PASSIVE;

    xzero(async_ctx);
    ares_getaddrinfo(ares, host, NULL, &hints, wget_ares_addrinfo_callback, &async_ctx);
    ares_update_timer();
    completed = dns_wait_for_completion(&async_ctx);
    if (!completed) {
      if (!silent)
        logputs(LOG_VERBOSE, _("failed: timed out.\n"));
      return NULL;
    }

    if (async_ctx.status != ARES_SUCCESS) {
      if (!silent)
        logprintf(LOG_VERBOSE, _("failed: %s.\n"), ares_strerror(async_ctx.status));
      return NULL;
    }

    al = async_ctx.result;
  }
  else
#endif
  {
    struct hostent* hptr = gethostbyname_with_timeout(host, timeout);
    if (!hptr) {
      if (!silent) {
        if (errno != ETIMEDOUT)
          logprintf(LOG_VERBOSE, _("failed: %s.\n"), host_errstr(h_errno));
        else
          logputs(LOG_VERBOSE, _("failed: timed out.\n"));
      }
      return NULL;
    }
    /* Do older systems have h_addr_list?  */
    al = address_list_from_ipv4_addresses(hptr->h_addr_list);
  }
#endif /* not ENABLE_IPV6 */

  /* Print the addresses determined by DNS lookup, but no more than
     three if show_all_dns_entries is not specified.  */
  if (!silent && !numeric_address) {
    int i;
    int printmax = al->count;

    if (!opt.show_all_dns_entries && printmax > 3)
      printmax = 3;

    for (i = 0; i < printmax; i++) {
      logputs(LOG_VERBOSE, print_address(al->addresses + i));
      if (i < printmax - 1)
        logputs(LOG_VERBOSE, ", ");
    }
    if (printmax != al->count)
      logputs(LOG_VERBOSE, ", ...");
    logputs(LOG_VERBOSE, "\n");
  }

  /* Cache the lookup information. */
  if (use_cache)
    cache_store(host, al);

  return al;
}

/* Determine whether a URL is acceptable to be followed, according to
   a list of domains to accept.  */
bool accept_domain(struct url* u) {
  assert(u->host != NULL);
  if (opt.domains) {
    if (!sufmatch((const char**)opt.domains, u->host))
      return false;
  }
  if (opt.exclude_domains) {
    if (sufmatch((const char**)opt.exclude_domains, u->host))
      return false;
  }
  return true;
}

/* Check whether WHAT is matched in LIST, each element of LIST being a
   pattern to match WHAT against, using backward matching (see
   match_backwards() in utils.c).

   If an element of LIST matched, 1 is returned, 0 otherwise.  */
bool sufmatch(const char** list, const char* what) {
  int i, j, k, lw;

  lw = strlen(what);

  for (i = 0; list[i]; i++) {
    j = strlen(list[i]);
    if (lw < j)
      continue; /* what is no (sub)domain of list[i] */

    for (k = lw; j >= 0 && k >= 0; j--, k--)
      if (c_tolower(list[i][j]) != c_tolower(what[k]))
        break;

    /* Domain or subdomain match
     * k == -1: exact match
     * k >= 0 && what[k] == '.': subdomain match
     * k >= 0 && list[i][0] == '.': dot-prefixed subdomain match
     */
    if (j == -1 && (k == -1 || what[k] == '.' || list[i][0] == '.'))
      return true;
  }

  return false;
}

#if defined DEBUG_MALLOC || defined TESTING
void host_cleanup(void) {
  wget_mutex_lock(&dns_cache_lock);
  if (host_name_addresses_map) {
    hash_table_iterator iter;
    for (hash_table_iterate(host_name_addresses_map, &iter); hash_table_iter_next(&iter);) {
      char* host = iter.key;
      struct address_list* al = iter.value;
      xfree(host);
      assert(al->refcount == 1);
      address_list_delete(al);
    }
    hash_table_destroy(host_name_addresses_map);
    host_name_addresses_map = NULL;
  }
  wget_mutex_unlock(&dns_cache_lock);
#ifdef HAVE_LIBCARES
  ares_clear_socket_state();
#endif
}
#endif

bool is_valid_ip_address(const char* name) {
  const char* endp;

  endp = name + strlen(name);
  if (is_valid_ipv4_address(name, endp))
    return true;
#ifdef ENABLE_IPV6
  if (is_valid_ipv6_address(name, endp))
    return true;
#endif
  return false;
}
