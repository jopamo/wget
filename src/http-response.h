/* HTTP response parsing and header management
 * src/http-response.h
 */
#ifndef HTTP_RESPONSE_H
#define HTTP_RESPONSE_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque HTTP response head parsed from a raw header buffer */
struct response;

/* Create a parsed response from a raw header buffer
 * The buffer should contain the full HTTP header block and remain valid
 * for the lifetime of the response object unless the implementation copies it
 */
struct response* resp_new(char* head);

/* Low level header lookup
 * name    header field name (case-insensitive)
 * start   index of first match candidate (0-based)
 * begptr  set to start of header value slice (excluding name and colon)
 * endptr  set to first char after header value slice
 * Returns index of matched header or -1 when not found
 */
int resp_header_locate(const struct response* resp, const char* name, int start, const char** begptr, const char** endptr);

/* Convenience lookup for a single header occurrence
 * Returns true when a header is found and fills begptr/endptr
 */
bool resp_header_get(const struct response* resp, const char* name, const char** begptr, const char** endptr);

/* Copy header value into caller buffer as a C string
 * Returns true on success, false on missing header or insufficient bufsize
 */
bool resp_header_copy(const struct response* resp, const char* name, char* buf, int bufsize);

/* Allocate and return a NUL-terminated copy of the header value
 * Caller owns the returned buffer and must free it with xfree or free
 */
char* resp_header_strdup(const struct response* resp, const char* name);

/* Extract numeric status code and optional status message
 * message may be NULL; when non-NULL it is set to point inside the response
 */
int resp_status(const struct response* resp, char** message);

/* Destroy response and clear caller reference */
void resp_free(struct response** resp_ref);

/* Dump response headers to stderr/stdout with an optional prefix for each line */
void print_server_response(const struct response* resp, const char* prefix);

/* Read HTTP response header block from a nonblocking or blocking socket
 * Returns a newly allocated buffer containing the header block, or NULL on error
 */
char* read_http_response_head(int fd);

#ifdef __cplusplus
}
#endif

#endif /* HTTP_RESPONSE_H */
