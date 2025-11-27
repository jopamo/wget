/* Persistent connection pool for wget
 * src/pconn.h
 */

#ifndef PCONN_H
#define PCONN_H

#include "wget.h"
#include "evloop.h"
#include "net_conn.h"

/* Forward declarations */
struct pconn_pool;

/* Connection pool key structure */
struct pconn_key {
  const char* scheme;
  const char* host;
  const char* port;
  bool use_tls;
};

/* Pool entry structure */
struct pconn_entry {
  struct net_conn* conn;
  struct pconn_entry* next;
  time_t last_used;
};

/* Main pool structure */
struct pconn_pool {
  struct ev_loop* loop;

  /* Hash table for pool entries */
  struct pconn_entry** buckets;
  size_t bucket_count;
  size_t entry_count;

  /* Configuration */
  size_t max_idle_per_host;
  time_t max_idle_time;
};

/* Connection pool API */
struct pconn_pool* pconn_pool_new(struct ev_loop* loop);
void pconn_pool_free(struct pconn_pool* pool);

/* Connection acquisition and release */
struct net_conn* pconn_acquire(struct pconn_pool* pool,
                               const char* scheme,
                               const char* host,
                               const char* port,
                               bool use_tls,
                               void (*on_ready)(struct net_conn*, void*),
                               void (*on_error)(struct net_conn*, void*),
                               void* arg);

void pconn_release(struct pconn_pool* pool, struct net_conn* conn, bool keep_alive_ok);

/* Pool management */
void pconn_flush_for_host(struct pconn_pool* pool, const char* host);
void pconn_shutdown_all(struct pconn_pool* pool);

/* Statistics */
size_t pconn_get_idle_count(struct pconn_pool* pool);
size_t pconn_get_total_count(struct pconn_pool* pool);

#endif /* PCONN_H */