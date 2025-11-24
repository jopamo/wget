/* HTTP connection pooling.
 * src/http-pool.c
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

#include "wget.h"

#include <string.h>
#include <time.h>

#include "http-pool.h"
#include "log.h"
#include "utils.h"
#include "host.h"
#include "connect.h"
#include "c-strcase.h"
#include "xalloc.h"
#include "hash.h"

/* Global connection pool hash table */
static struct hash_table* pool_table = NULL;

/* Default pool configuration */
static const pool_config_t default_config = {
    .max_connections = 5,
    .max_idle_connections = 2,
    .idle_timeout = 30,         /* 30 seconds */
    .health_check_interval = 60 /* 60 seconds */
};

/* Create a host pool key string */
static char* create_pool_key(const char* host, int port, bool ssl) {
  return aprintf("%s:%d:%s", host, port, ssl ? "ssl" : "plain");
}

/* Find or create a host pool */
static host_pool_t* get_host_pool(const char* host, int port, bool ssl) {
  if (!pool_table) {
    return NULL;
  }

  char* key = create_pool_key(host, port, ssl);
  host_pool_t* pool = hash_table_get(pool_table, key);

  if (!pool) {
    pool = xnew0(host_pool_t);
    pool->host = xstrdup(host);
    pool->port = port;
    pool->ssl = ssl;
    pool->connections = NULL;
    pool->connection_count = 0;
    pool->active_count = 0;
    pool->config = default_config;
    pool->last_health_check = time(NULL);

    hash_table_put(pool_table, key, pool);
  }
  else {
    xfree(key);
  }

  return pool;
}

/* Check if a connection is still healthy */
static bool connection_is_healthy(pooled_conn_t* conn) {
  if (!test_socket_open(conn->socket)) {
    return false;
  }

  /* Check if connection has been idle too long */
  time_t now = time(NULL);
  if ((now - conn->last_used) > default_config.idle_timeout) {
    return false;
  }

  return true;
}

/* Perform health check on a pool */
static void health_check_pool(host_pool_t* pool) {
  time_t now = time(NULL);
  if ((now - pool->last_health_check) < pool->config.health_check_interval) {
    return;
  }

  pool->last_health_check = now;

  for (size_t i = 0; i < pool->connection_count; i++) {
    pooled_conn_t* conn = pool->connections[i];
    if (!conn->in_use && !connection_is_healthy(conn)) {
      /* Remove unhealthy connection */
      DEBUGP(("Removing unhealthy connection %d from pool for %s:%d\n", conn->socket, pool->host, pool->port));
      fd_close(conn->socket);
      xfree(conn->host);
      xfree(conn);

      /* Shift remaining connections */
      for (size_t j = i; j < pool->connection_count - 1; j++) {
        pool->connections[j] = pool->connections[j + 1];
      }
      pool->connection_count--;
      i--; /* Recheck current index after shift */
    }
  }
}

/* Initialize the connection pool system */
void pool_init(void) {
  if (pool_table) {
    return;
  }

  pool_table = make_nocase_string_hash_table(0);
  DEBUGP(("Connection pool system initialized\n"));
}

/* Cleanup the connection pool system */
void pool_cleanup(void) {
  if (!pool_table) {
    return;
  }

  hash_table_iterator iter;
  hash_table_iterate(pool_table, &iter);

  while (hash_table_iter_next(&iter)) {
    host_pool_t* pool = iter.value;

    /* Close all connections in the pool */
    for (size_t i = 0; i < pool->connection_count; i++) {
      pooled_conn_t* conn = pool->connections[i];
      fd_close(conn->socket);
      xfree(conn->host);
      xfree(conn);
    }

    xfree(pool->connections);
    xfree(pool->host);
    xfree(pool);
  }

  hash_table_destroy(pool_table);
  pool_table = NULL;
  DEBUGP(("Connection pool system cleaned up\n"));
}

/* Get a connection from the pool for a specific host */
int pool_get_connection(const char* host, int port, bool ssl, bool* host_lookup_failed WGET_ATTR_UNUSED) {
  if (!pool_table) {
    return -1;
  }

  host_pool_t* pool = get_host_pool(host, port, ssl);
  if (!pool) {
    return -1;
  }

  health_check_pool(pool);

  /* Find first available healthy connection */
  for (size_t i = 0; i < pool->connection_count; i++) {
    pooled_conn_t* conn = pool->connections[i];
    if (!conn->in_use && connection_is_healthy(conn)) {
      conn->in_use = true;
      conn->last_used = time(NULL);
      pool->active_count++;

      DEBUGP(("Reusing pooled connection %d for %s:%d\n", conn->socket, host, port));
      return conn->socket;
    }
  }

  return -1; /* No available connection */
}

/* Return a connection to the pool */
void pool_return_connection(int socket, const char* host, int port, bool ssl) {
  if (!pool_table || socket < 0) {
    return;
  }

  host_pool_t* pool = get_host_pool(host, port, ssl);
  if (!pool) {
    return;
  }

  /* Find the connection and mark it as available */
  for (size_t i = 0; i < pool->connection_count; i++) {
    pooled_conn_t* conn = pool->connections[i];
    if (conn->socket == socket && conn->in_use) {
      conn->in_use = false;
      conn->last_used = time(NULL);
      pool->active_count--;

      DEBUGP(("Returned connection %d to pool for %s:%d\n", socket, host, port));
      break;
    }
  }
}

/* Register a connection for pooling */
void pool_register_connection(const char* host, int port, int fd, bool ssl) {
  if (!pool_table || fd < 0) {
    return;
  }

  host_pool_t* pool = get_host_pool(host, port, ssl);
  if (!pool) {
    return;
  }

  /* Check if we're at the connection limit */
  if (pool->connection_count >= pool->config.max_connections) {
    DEBUGP(("Connection pool for %s:%d is full (%zu connections)\n", host, port, pool->connection_count));
    return;
  }

  /* Create new pooled connection */
  pooled_conn_t* conn = xnew0(pooled_conn_t);
  conn->socket = fd;
  conn->host = xstrdup(host);
  conn->port = port;
  conn->ssl = ssl;
  conn->authorized = false;
  conn->created_at = time(NULL);
  conn->last_used = time(NULL);
  conn->in_use = false;

  /* Add to pool */
  pool->connections = xrealloc(pool->connections, (pool->connection_count + 1) * sizeof(pooled_conn_t*));
  pool->connections[pool->connection_count] = conn;
  pool->connection_count++;

  DEBUGP(("Registered connection %d for pooling to %s:%d\n", fd, host, port));
}

/* Invalidate a connection in the pool */
void pool_invalidate_connection(int socket) {
  if (!pool_table || socket < 0) {
    return;
  }

  hash_table_iterator iter;
  hash_table_iterate(pool_table, &iter);

  while (hash_table_iter_next(&iter)) {
    host_pool_t* pool = iter.value;

    for (size_t i = 0; i < pool->connection_count; i++) {
      pooled_conn_t* conn = pool->connections[i];
      if (conn->socket == socket) {
        /* Remove the connection */
        fd_close(conn->socket);
        xfree(conn->host);
        xfree(conn);

        /* Shift remaining connections */
        for (size_t j = i; j < pool->connection_count - 1; j++) {
          pool->connections[j] = pool->connections[j + 1];
        }
        pool->connection_count--;

        if (conn->in_use) {
          pool->active_count--;
        }

        DEBUGP(("Invalidated connection %d from pool for %s:%d\n", socket, pool->host, pool->port));
        return;
      }
    }
  }
}

/* Check if a connection is available in the pool */
bool pool_connection_available_p(const char* host, int port, bool ssl, bool* host_lookup_failed WGET_ATTR_UNUSED) {
  if (!pool_table) {
    return false;
  }

  host_pool_t* pool = get_host_pool(host, port, ssl);
  if (!pool) {
    return false;
  }

  health_check_pool(pool);

  /* Check for available healthy connection */
  for (size_t i = 0; i < pool->connection_count; i++) {
    pooled_conn_t* conn = pool->connections[i];
    if (!conn->in_use && connection_is_healthy(conn)) {
      return true;
    }
  }

  return false;
}

/* Set pool configuration for a specific host */
void pool_set_host_config(const char* host, int port, bool ssl, const pool_config_t* config) {
  if (!pool_table || !config) {
    return;
  }

  host_pool_t* pool = get_host_pool(host, port, ssl);
  if (pool) {
    pool->config = *config;
    DEBUGP(("Set pool config for %s:%d: max_connections=%zu, idle_timeout=%ld\n", host, port, config->max_connections, config->idle_timeout));
  }
}

/* Get pool statistics */
void pool_get_stats(const char* host, int port, bool ssl, size_t* total_connections, size_t* active_connections, size_t* idle_connections) {
  if (total_connections)
    *total_connections = 0;
  if (active_connections)
    *active_connections = 0;
  if (idle_connections)
    *idle_connections = 0;

  if (!pool_table) {
    return;
  }

  host_pool_t* pool = get_host_pool(host, port, ssl);
  if (pool) {
    if (total_connections)
      *total_connections = pool->connection_count;
    if (active_connections)
      *active_connections = pool->active_count;
    if (idle_connections)
      *idle_connections = pool->connection_count - pool->active_count;
  }
}