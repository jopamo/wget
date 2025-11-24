/* HTTP response parsing helpers.
 * src/http_response.h
 */

#ifndef WGET_HTTP_RESPONSE_H
#define WGET_HTTP_RESPONSE_H

#include "wget.h"

struct http_response;
struct http_stat;
struct url;

char* http_response_read_head(int fd);
struct http_response* http_response_parse(char* head);

void http_response_free(struct http_response** resp_ref);

int http_response_status(const struct http_response* resp, char** message);
int http_response_header_locate(const struct http_response* resp,
                                const char* name,
                                int start,
                                const char** begptr,
                                const char** endptr);
bool http_response_header_get(const struct http_response* resp,
                              const char* name,
                              const char** begptr,
                              const char** endptr);
bool http_response_header_copy(const struct http_response* resp, const char* name, char* buf, int bufsize);
char* http_response_header_strdup(const struct http_response* resp, const char* name);

void http_response_print(const struct http_response* resp, const char* prefix);

void http_stat_reset(struct http_stat* hs);
void http_stat_set_message(struct http_stat* hs, const char* message);
void http_stat_record_status(struct http_stat* hs, int statcode, const char* message);
void http_stat_capture_headers(struct http_stat* hs,
                               const struct http_response* resp,
                               const struct url* u,
                               const char* content_type,
                               char* scratch,
                               size_t scratch_size);
void http_stat_release(struct http_stat* hs);

#endif /* WGET_HTTP_RESPONSE_H */
