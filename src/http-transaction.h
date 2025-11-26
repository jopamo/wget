#ifndef HTTP_TRANSACTION_H
#define HTTP_TRANSACTION_H

#include "wget.h"
#include "url.h"
#include "http-stat.h"
#include "iri.h"

uerr_t http_transaction_run(const struct url* u, struct url* original_url, struct http_stat* hs, int* dt, struct url* proxy, struct iri* iri, int count);

#endif /* HTTP_TRANSACTION_H */