/* Persistent connection pool for wget
 * src/pconn.c
 */

#include "pconn.h"
#include "hash.h"
#include "utils.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#define INITIAL_BUCKET_COUNT 16
#define DEFAULT_MAX_IDLE_PER_HOST 5
#define DEFAULT_MAX_IDLE_TIME 300 /* 5 minutes */

/* Internal helper functions */
static size_t pconn_hash_key(const struct pconn_key* key);
static struct pconn_entry* pconn_find_entry(struct pconn_pool* pool, const struct pconn_key* key);
static void pconn_add_entry(struct pconn_pool* pool, const struct pconn_key* key, struct net_conn* conn);
static void pconn_remove_entry(struct pconn_pool* pool, const struct pconn_key* key, struct net_conn* conn);
static void pconn_cleanup_expired(struct pconn_pool* pool);

struct pconn_pool* pconn_pool_new(struct ev_loop* loop) {
  struct pconn_pool* pool = xmalloc(sizeof(struct pconn_pool));

  pool->loop = loop;
  pool->bucket_count = INITIAL_BUCKET_COUNT;
  pool->entry_count = 0;
  pool->max_idle_per_host = DEFAULT_MAX_IDLE_PER_HOST;
  pool->max_idle_time = DEFAULT_MAX_IDLE_TIME;

  pool->buckets = xcalloc(pool->bucket_count, sizeof(struct pconn_entry*));

  return pool;
}

void pconn_pool_free(struct pconn_pool* pool) {
  if (!pool)
    return;

  /* Close all connections */
  pconn_shutdown_all(pool);

  /* Free buckets array */
  free(pool->buckets);
  free(pool);
}

struct net_conn* pconn_acquire(struct pconn_pool* pool,
                               const char* scheme,
                               const char* host,
                               const char* port,
                               bool use_tls,
                               void (*on_ready)(struct net_conn*, void*),
                               void (*on_error)(struct net_conn*, void*),
                               void* arg) {
  if (!pool || !scheme || !host || !port) {
    return NULL;
  }

  /* Clean up expired connections first */
  pconn_cleanup_expired(pool);

  /* Create key for lookup */
  struct pconn_key key = {.scheme = (char*)scheme, .host = (char*)host, .port = (char*)port, .use_tls = use_tls};

  /* Try to find an idle connection */
  struct pconn_entry* entry = pconn_find_entry(pool, &key);
  if (entry) {
    /* Found idle connection - remove from pool and return it */
    struct net_conn* conn = entry->conn;
    pconn_remove_entry(pool, &key, conn);

    /* Update connection callbacks */
    conn_set_readable_callback(conn, NULL, NULL);
    conn_set_writable_callback(conn, NULL, NULL);

    /* Set the new callbacks */
    if (on_ready || on_error) {
      /* For pool connections, we need to set the appropriate callbacks */
      /* The connection should already be in CONN_READY state */
      if (on_ready) {
        on_ready(conn, arg);
      }
    }

    DEBUGP(("[pconn] Reusing idle connection for %s://%s:%s\n", scheme, host, port));
    return conn;
  }

  /* No idle connection available - create a new one */
  struct net_conn* conn = conn_new(pool->loop, host, port, use_tls, on_ready, on_error, arg);
  if (!conn) {
    DEBUGP(("[pconn] Failed to create new connection for %s://%s:%s\n", scheme, host, port));
    return NULL;
  }

  DEBUGP(("[pconn] Created new connection for %s://%s:%s\n", scheme, host, port));
  return conn;
}

void pconn_release(struct pconn_pool* pool, struct net_conn* conn, bool keep_alive_ok) {
  if (!pool || !conn)
    return;

  /* Clean up expired connections first */
  pconn_cleanup_expired(pool);

  if (keep_alive_ok && conn_get_state(conn) == CONN_READY) {
    /* Connection can be reused - add to pool */

    /* Create key for this connection */
    struct pconn_key key = {.scheme = conn_get_use_tls(conn) ? "https" : "http", .host = conn_get_host(conn), .port = conn_get_port(conn), .use_tls = conn_get_use_tls(conn)};

    /* Check if we're at the limit for this host */
    size_t host_count = 0;
    struct pconn_entry* entry = pconn_find_entry(pool, &key);
    while (entry) {
      host_count++;
      entry = entry->next;
    }

    if (host_count < pool->max_idle_per_host) {
      /* Add to pool */
      pconn_add_entry(pool, &key, conn);

      /* Clear callbacks for pooled connection */
      conn_set_readable_callback(conn, NULL, NULL);
      conn_set_writable_callback(conn, NULL, NULL);

      DEBUGP(("[pconn] Added connection to pool for %s://%s:%s (idle: %zu)\n", key.scheme, key.host, key.port, host_count + 1));
    }
    else {
      /* At limit - close connection */
      DEBUGP(("[pconn] Closing connection (pool limit reached) for %s://%s:%s\n", key.scheme, key.host, key.port));
      conn_close(conn);
    }
  }
  else {
    /* Connection cannot be reused - close it */
    DEBUGP(("[pconn] Closing connection (keep-alive not OK) for %s://%s:%s\n", conn_get_use_tls(conn) ? "https" : "http", conn_get_host(conn), conn_get_port(conn)));
    conn_close(conn);
  }
}

void pconn_flush_for_host(struct pconn_pool* pool, const char* host) {
  if (!pool || !host)
    return;

  DEBUGP(("[pconn] Flushing connections for host: %s\n", host));

  for (size_t i = 0; i < pool->bucket_count; i++) {
    struct pconn_entry** entry_ptr = &pool->buckets[i];
    while (*entry_ptr) {
      struct pconn_entry* entry = *entry_ptr;
      if (strcmp(conn_get_host(entry->conn), host) == 0) {
        /* Remove from list */
        *entry_ptr = entry->next;

        /* Close connection */
        conn_close(entry->conn);
        free(entry);
        pool->entry_count--;
      }
      else {
        entry_ptr = &(*entry_ptr)->next;
      }
    }
  }
}

void pconn_shutdown_all(struct pconn_pool* pool) {
  if (!pool)
    return;

  DEBUGP(("[pconn] Shutting down all connections (%zu total)\n", pool->entry_count));

  for (size_t i = 0; i < pool->bucket_count; i++) {
    struct pconn_entry* entry = pool->buckets[i];
    while (entry) {
      struct pconn_entry* next = entry->next;
      conn_close(entry->conn);
      free(entry);
      entry = next;
    }
    pool->buckets[i] = NULL;
  }

  pool->entry_count = 0;
}

size_t pconn_get_idle_count(struct pconn_pool* pool) {
  return pool ? pool->entry_count : 0;
}

size_t pconn_get_total_count(struct pconn_pool* pool) {
  return pool ? pool->entry_count : 0;
}

/* Internal helper functions */

static size_t pconn_hash_key(const struct pconn_key* key) {
  /* Simple hash function for connection key */
  size_t hash = 5381;
  const char* str;

  str = key->scheme;
  while (*str) {
    hash = ((hash << 5) + hash) + *str++; /* hash * 33 + c */
  }

  str = key->host;
  while (*str) {
    hash = ((hash << 5) + hash) + *str++;
  }

  str = key->port;
  while (*str) {
    hash = ((hash << 5) + hash) + *str++;
  }

  hash = ((hash << 5) + hash) + (key->use_tls ? 1 : 0);

  return hash;
}

static struct pconn_entry* pconn_find_entry(struct pconn_pool* pool, const struct pconn_key* key) {
  size_t bucket = pconn_hash_key(key) % pool->bucket_count;
  struct pconn_entry* entry = pool->buckets[bucket];

  while (entry) {
    struct net_conn* conn = entry->conn;
    if (strcmp(key->scheme, conn_get_use_tls(conn) ? "https" : "http") == 0 && strcmp(key->host, conn_get_host(conn)) == 0 && strcmp(key->port, conn_get_port(conn)) == 0 &&
        key->use_tls == conn_get_use_tls(conn)) {
      return entry;
    }
    entry = entry->next;
  }

  return NULL;
}

static void pconn_add_entry(struct pconn_pool* pool, const struct pconn_key* key, struct net_conn* conn) {
  size_t bucket = pconn_hash_key(key) % pool->bucket_count;

  struct pconn_entry* entry = xmalloc(sizeof(struct pconn_entry));
  entry->conn = conn;
  entry->last_used = time(NULL);

  /* Add to front of bucket list */
  entry->next = pool->buckets[bucket];
  pool->buckets[bucket] = entry;
  pool->entry_count++;
}

static void pconn_remove_entry(struct pconn_pool* pool, const struct pconn_key* key, struct net_conn* conn) {
  size_t bucket = pconn_hash_key(key) % pool->bucket_count;
  struct pconn_entry** entry_ptr = &pool->buckets[bucket];

  while (*entry_ptr) {
    struct pconn_entry* entry = *entry_ptr;
    if (entry->conn == conn) {
      /* Remove from list */
      *entry_ptr = entry->next;
      free(entry);
      pool->entry_count--;
      return;
    }
    entry_ptr = &(*entry_ptr)->next;
  }
}

static void pconn_cleanup_expired(struct pconn_pool* pool) {
  time_t now = time(NULL);

  for (size_t i = 0; i < pool->bucket_count; i++) {
    struct pconn_entry** entry_ptr = &pool->buckets[i];
    while (*entry_ptr) {
      struct pconn_entry* entry = *entry_ptr;

      if (now - entry->last_used > pool->max_idle_time) {
        /* Connection expired - remove and close */
        *entry_ptr = entry->next;
        conn_close(entry->conn);
        free(entry);
        pool->entry_count--;

        DEBUGP(("[pconn] Cleaned up expired connection for %s://%s:%s\n", conn_get_use_tls(entry->conn) ? "https" : "http", conn_get_host(entry->conn), conn_get_port(entry->conn)));
      }
      else {
        entry_ptr = &(*entry_ptr)->next;
      }
    }
  }
}