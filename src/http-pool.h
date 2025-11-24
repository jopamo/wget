/* Declarations for HTTP connection pooling.
 * src/http-pool.h
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

#ifndef HTTP_POOL_H
#define HTTP_POOL_H

#include <stdbool.h>
#include <time.h>

#ifdef ENABLE_NTLM
#include "http-ntlm.h"
#endif

/* Connection pool configuration */
typedef struct pool_config {
  size_t max_connections;       /* Maximum connections per host */
  size_t max_idle_connections;  /* Maximum idle connections to keep */
  time_t idle_timeout;          /* Seconds before idle connection is closed */
  time_t health_check_interval; /* Seconds between health checks */
} pool_config_t;

/* Individual connection in the pool */
typedef struct pooled_conn {
  int socket;        /* The socket of the connection */
  char* host;        /* Host of the connection */
  int port;          /* Port of the connection */
  bool ssl;          /* Whether SSL handshake occurred */
  bool authorized;   /* Whether connection was authorized */
  time_t created_at; /* When connection was created */
  time_t last_used;  /* When connection was last used */
  bool in_use;       /* Whether connection is currently in use */

#ifdef ENABLE_NTLM
  struct ntlmdata ntlm; /* NTLM data of the current connection */
#endif
} pooled_conn_t;

/* Host-specific connection pool */
typedef struct host_pool {
  char* host; /* Host name */
  int port;   /* Port number */
  bool ssl;   /* SSL requirement */

  pooled_conn_t** connections; /* Array of connections */
  size_t connection_count;     /* Current number of connections */
  size_t active_count;         /* Number of connections currently in use */

  pool_config_t config;     /* Pool configuration */
  time_t last_health_check; /* Last time health check was performed */
} host_pool_t;

/* Connection pool API */

/* Initialize the connection pool system */
void pool_init(void);

/* Cleanup the connection pool system */
void pool_cleanup(void);

/* Get a connection from the pool for a specific host */
int pool_get_connection(const char* host, int port, bool ssl, bool* host_lookup_failed);

/* Return a connection to the pool */
void pool_return_connection(int socket, const char* host, int port, bool ssl);

/* Register a connection for pooling */
void pool_register_connection(const char* host, int port, int fd, bool ssl);

/* Invalidate a connection in the pool */
void pool_invalidate_connection(int socket);

/* Check if a connection is available in the pool */
bool pool_connection_available_p(const char* host, int port, bool ssl, bool* host_lookup_failed);

/* Set pool configuration for a specific host */
void pool_set_host_config(const char* host, int port, bool ssl, const pool_config_t* config);

/* Get pool statistics */
void pool_get_stats(const char* host, int port, bool ssl, size_t* total_connections, size_t* active_connections, size_t* idle_connections);

#endif /* HTTP_POOL_H */