/* Declarations for HTTP persistent connections.
 * src/http-pconn.h
 *
 * Copyright (C) 2024 Free Software Foundation, Inc.
 *
 * This file is part of GNU Wget.
 *
 * GNU Wget is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNU Wget is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Wget.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef HTTP_PCONN_H
#define HTTP_PCONN_H

#include <stdbool.h>

#ifdef ENABLE_NTLM
#include "http-ntlm.h"
#endif

struct pconn_t {
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

extern bool pconn_active;
extern struct pconn_t pconn;

void invalidate_persistent(void);
void register_persistent(const char* host, int port, int fd, bool ssl);
bool persistent_available_p(const char* host, int port, bool ssl, bool* host_lookup_failed);
void pconn_cleanup(void);

#endif /* HTTP_PCONN_H */
