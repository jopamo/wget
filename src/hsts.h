/* Declarations for hsts.c
 * src/hsts.h
 */

#ifndef WGET_HSTS_H
#define WGET_HSTS_H

#include "wget.h"
#include "url.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_HSTS

typedef struct hsts_store* hsts_store_t;

hsts_store_t hsts_store_open(const char* filename);

void hsts_store_save(hsts_store_t store, const char* filename);
void hsts_store_close(hsts_store_t store);
bool hsts_store_has_changed(hsts_store_t store);

bool hsts_store_entry(hsts_store_t store, enum url_scheme scheme, const char* host, int port, int64_t max_age, bool include_subdomains);

bool hsts_match(hsts_store_t store, struct url* url);

#endif /* HAVE_HSTS */

#ifdef __cplusplus
}
#endif

#endif /* WGET_HSTS_H */
