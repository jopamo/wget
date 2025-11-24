/* HTTP body transfer helper APIs.
 * src/http_body.h
 */

#ifndef WGET_HTTP_BODY_H
#define WGET_HTTP_BODY_H

#include <stdio.h>

#include "http_internal.h"
#include "host.h"

struct ip_address;

typedef void (*http_body_done_cb)(struct http_stat* hs, int status, wgint qtyread, wgint qtywritten, double elapsed);

void http_body_download(struct http_stat* hs, int sock, FILE* fp, wgint contlen, wgint contrange, bool chunked_transfer_encoding, http_body_done_cb done_cb);

#endif /* WGET_HTTP_BODY_H */
