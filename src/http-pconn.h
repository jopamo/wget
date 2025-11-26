#ifndef HTTP_PCONN_H
#define HTTP_PCONN_H

#include <stdbool.h>
#include "wget.h"

#ifdef ENABLE_NTLM
#include "http-ntlm.h"
#endif

struct pconn_data {
  /* The socket of the connection.  */
  int socket;

  /* Host and port of the currently active persistent connection. */
  char* host;
  int port;

  /* Whether a ssl handshake has occurred on this connection.  */
  bool ssl;

  /* Whether the connection was authorized.  This is only done by
     NTLM, which authorizes *connections* rather than individual
     requests.  (That practice is peculiar for HTTP, but it is a
     useful optimization.)  */
  bool authorized;

#ifdef ENABLE_NTLM
  /* NTLM data of the current connection.  */
  struct ntlmdata ntlm;
#endif
};

extern struct pconn_data pconn;
extern bool pconn_active;

void invalidate_persistent(void);
void register_persistent(const char* host, int port, int fd, bool ssl);
bool persistent_available_p(const char* host, int port, bool ssl, bool* host_lookup_failed);

#endif /* HTTP_PCONN_H */
