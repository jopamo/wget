/* HTTP transaction state machine and execution
 * src/http-transaction.h
 */
#ifndef HTTP_TRANSACTION_H
#define HTTP_TRANSACTION_H

#include "wget.h"
#include "url.h"
#include "http-stat.h"
#include "iri.h"
#include "evloop.h"
#include "net_conn.h"

/* Forward declarations */
struct http_transaction;

/* Callback types for async transaction */
typedef void (*http_txn_cb)(struct http_transaction* txn, void* arg);

/*
 * Async HTTP Transaction API
 */

/* Create a new transaction */
/* The 'hs' (http_stat) is currently used to store results.
   In the future, we might want a cleaner result struct,
   but for compatibility we pass 'hs' to be filled. */
struct http_transaction*
http_txn_new(struct ev_loop* loop, const struct url* u, struct url* original_url, struct http_stat* hs, int* dt, struct url* proxy, struct iri* iri, int count, http_txn_cb on_complete, void* cb_arg);

/* Start the transaction */
void http_txn_start(struct http_transaction* txn);

/* Cancel/Stop the transaction */
void http_txn_stop(struct http_transaction* txn);

/* Free the transaction */
void http_txn_free(struct http_transaction* txn);

/* Get the final error code */
uerr_t http_txn_get_error(struct http_transaction* txn);

/*
 * Legacy Synchronous Wrapper
 * Executes a single transaction in a blocking manner using the event loop.
 */
uerr_t http_transaction_run(const struct url* u, struct url* original_url, struct http_stat* hs, int* dt, struct url* proxy, struct iri* iri, int count);

#endif /* HTTP_TRANSACTION_H */
