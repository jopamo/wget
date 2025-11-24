/* HTTP body transfer helper APIs.
 * src/http_body.h
 */

#ifndef WGET_HTTP_BODY_H
#define WGET_HTTP_BODY_H

#include <stdio.h>

#include "http_internal.h"
#include "host.h"

struct ip_address;

int http_body_download(struct http_stat* hs,
                       int sock,
                       FILE* fp,
                       wgint contlen,
                       wgint contrange,
                       bool chunked_transfer_encoding,
                       char* url,
                       char* warc_timestamp_str,
                       char* warc_request_uuid,
                       ip_address* warc_ip,
                       char* type,
                       int statcode,
                       char* head);

#endif /* WGET_HTTP_BODY_H */
