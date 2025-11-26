/* Persistent HTTP connection management
 * src/http-pconn.h
 */
#ifndef HTTP_PCONN_H
#define HTTP_PCONN_H

#include <stdbool.h>
#include "wget.h"

#ifdef ENABLE_NTLM
#include "http-ntlm.h"
#endif

/* Simple description of a single reusable HTTP connection
 *
 * Lifetime rules:
 * - pconn describes at most one live TCP socket at a time
 * - host/port/ssl identify which target the socket is bound to
 * - authorized is connection-level (NTLM-style) auth state
 */
struct pconn_data {
  /* underlying socket file descriptor */
  int socket;

  /* origin this connection is currently bound to */
  char* host;
  int port;

  /* true if TLS has been negotiated on this socket */
  bool ssl;

  /* true if the connection carries connection-level auth state
     (only used for NTLM, which authenticates the connection itself) */
  bool authorized;

#ifdef ENABLE_NTLM
  /* NTLM handshake state for this connection */
  struct ntlmdata ntlm;
#endif
};

/* global pool of at most one persistent connection */
extern struct pconn_data pconn;
extern bool pconn_active;

/* drop any existing persistent connection and reset pconn */
void invalidate_persistent(void);

/* record a new persistent connection bound to host:port and fd
 * ssl=true if the socket has completed a TLS handshake
 */
void register_persistent(const char* host, int port, int fd, bool ssl);

/* check if a persistent connection is usable for host:port/ssl
 * returns true if pconn matches and is still considered alive
 * sets *host_lookup_failed when DNS failure should skip reuse
 */
bool persistent_available_p(const char* host, int port, bool ssl, bool* host_lookup_failed);

#endif /* HTTP_PCONN_H */
