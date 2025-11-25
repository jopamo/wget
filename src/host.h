/* Declarations for host.c
 * src/host.h
 */

#ifndef HOST_H
#define HOST_H

#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct url;
struct address_list;

/* Tagged IP address representation used by the resolver layer */

typedef struct {
  /* Address family, one of AF_INET or AF_INET6 */
  int family;

  /* The actual data, in the form of struct in_addr or struct in6_addr */
  union {
    struct in_addr d4; /* IPv4 address */
#ifdef ENABLE_IPV6
    struct in6_addr d6; /* IPv6 address */
#endif
  } data;

  /* Optional IPv6 scope id returned by getaddrinfo for link-local addresses */
#if defined ENABLE_IPV6 && defined HAVE_SOCKADDR_IN6_SCOPE_ID
  int ipv6_scope;
#endif
} ip_address;

/*
 * IP_INADDR_DATA returns a void pointer suitable for inet_ntop and similar
 * helpers that accept either struct in_addr* or struct in6_addr*
 */
#define IP_INADDR_DATA(x) ((void*)&(x)->data)

enum { LH_SILENT = 1, LH_BIND = 2, LH_REFRESH = 4 };

struct address_list* lookup_host(const char* host, int flags);

void address_list_get_bounds(const struct address_list* al, int* first, int* last);
const ip_address* address_list_address_at(const struct address_list* al, int index);
bool address_list_contains(const struct address_list* al, const ip_address* addr);
void address_list_set_faulty(struct address_list* al, int index);
void address_list_set_connected(struct address_list* al);
bool address_list_connected_p(const struct address_list* al);
void address_list_release(struct address_list* al);

const char* print_address(const ip_address* addr);
#ifdef ENABLE_IPV6
bool is_valid_ipv6_address(const char* name, const char* end);
#endif

bool is_valid_ip_address(const char* name);

bool accept_domain(struct url* u);
bool sufmatch(const char** patterns, const char* text);

#ifdef HAVE_LIBCARES
struct ares_options;
/* Apply project defaults to c-ares resolver options before initialization */
void host_prepare_ares_options(struct ares_options* options, int* optmask);
#endif

/* Cleanup any resolver level global state */
void host_cleanup(void);

#endif /* HOST_H */
