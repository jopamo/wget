/* HTTP request management
 * src/http-request.c
 */

#include "wget.h"
#include "http-request.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "c-ctype.h"
#include "c-strcase.h"
#include "connect.h"
#include "gettext.h"
#include "log.h"
#include "options.h"
#include "utils.h"
#include "version.h"
#include "xalloc.h"
#include "xstrndup.h"

struct request {
  const char* method;
  char* arg;

  struct request_header {
    char* name;
    char* value;
    enum rp release_policy;
  }* headers;
  int hcount;
  int hcapacity;
};

/* Allocate a new request with the given method and URI path
 * METHOD must outlive the request, ARG is owned and freed by request_free
 */
struct request* request_new(const char* method, char* arg) {
  struct request* req = xnew0(struct request);

  req->hcapacity = 8;
  req->headers = xnew_array(struct request_header, req->hcapacity);
  req->method = method;
  req->arg = arg;

  return req;
}

/* Return the HTTP method associated with this request */
const char* request_method(const struct request* req) {
  return req->method;
}

/* Release a single header according to its release policy */
static void release_header(struct request_header* hdr) {
  switch (hdr->release_policy) {
    case rel_none:
      break;
    case rel_name:
      xfree(hdr->name);
      break;
    case rel_value:
      xfree(hdr->value);
      break;
    case rel_both:
      xfree(hdr->name);
      xfree(hdr->value);
      break;
  }
}

/* Set or replace a header on REQ
 *
 * name,value      header field name and value
 * release_policy  controls ownership cleanup in request_free:
 *                 - rel_none  keep both pointers
 *                 - rel_name  free name only
 *                 - rel_value free value only
 *                 - rel_both  free both name and value
 *
 * Passing value == NULL is a no-op; name is freed if requested
 * The most recent value for a header name wins
 */
void request_set_header(struct request* req, const char* name, const char* value, enum rp release_policy) {
  struct request_header* hdr;
  int i;

  if (!value) {
    /* NULL value means do nothing but honor requested name ownership */
    if (release_policy == rel_name || release_policy == rel_both)
      xfree(name);
    return;
  }

  for (i = 0; i < req->hcount; i++) {
    hdr = &req->headers[i];
    if (c_strcasecmp(name, hdr->name) == 0) {
      /* Replace existing header */
      release_header(hdr);
      hdr->name = (char*)name;
      hdr->value = (char*)value;
      hdr->release_policy = release_policy;
      return;
    }
  }

  /* Append new header */

  if (req->hcount >= req->hcapacity) {
    req->hcapacity <<= 1;
    req->headers = xrealloc(req->headers, (size_t)req->hcapacity * sizeof(*hdr));
  }

  hdr = &req->headers[req->hcount++];
  hdr->name = (char*)name;
  hdr->value = (char*)value;
  hdr->release_policy = release_policy;
}

/* Parse a raw header line and install it on REQ
 * Example: "Foo: bar" becomes header Foo = "bar"
 */
void request_set_user_header(struct request* req, const char* header) {
  const char *name, *p;

  p = strchr(header, ':');
  if (!p)
    return;

  name = xstrndup(header, (size_t)(p - header));

  ++p;
  while (c_isspace(*p))
    ++p;

  request_set_header(req, name, p, rel_name);
}

/* Remove the header with the given NAME from REQ
 * Returns true if a header was removed
 */
bool request_remove_header(struct request* req, const char* name) {
  int i;

  for (i = 0; i < req->hcount; i++) {
    struct request_header* hdr = &req->headers[i];

    if (c_strcasecmp(name, hdr->name) == 0) {
      release_header(hdr);

      /* compact remaining headers in place */
      if (i < req->hcount - 1)
        memmove(hdr, hdr + 1, (size_t)(req->hcount - i - 1) * sizeof(*hdr));

      --req->hcount;
      return true;
    }
  }

  return false;
}

/* Set User-Agent on REQ using either user configuration or default */
void request_set_user_agent(struct request* req) {
  if (opt.useragent)
    request_set_header(req, "User-Agent", opt.useragent, rel_none);
  else
    request_set_header(req, "User-Agent", "Wget/" PACKAGE_VERSION, rel_none);
}

#define APPEND(p, str)          \
  do {                          \
    size_t A_len = strlen(str); \
    memcpy(p, (str), A_len);    \
    (p) += A_len;               \
  } while (0)

/* Serialize REQ as an HTTP/1.1 request string.
 * Returns a newly allocated string that must be freed by caller.
 * If len is not NULL, it is set to the length of the string (excluding NUL).
 */
char* request_string(const struct request* req, size_t* len) {
  char *str, *p;
  int i;
  int size;

  /* Compute total request size
   * METHOD SP ARG SP "HTTP/1.1" CRLF
   */
  size = (int)strlen(req->method) + 1 + (int)strlen(req->arg) + 1 + 8 + 2;

  for (i = 0; i < req->hcount; i++) {
    struct request_header* hdr = &req->headers[i];
    /* NAME ": " VALUE CRLF */
    size += (int)strlen(hdr->name) + 2 + (int)strlen(hdr->value) + 2;
  }

  /* final CRLF and trailing NUL */
  size += 3;

  p = str = xmalloc((size_t)size);

  /* Start line */

  APPEND(p, req->method);
  *p++ = ' ';
  APPEND(p, req->arg);
  *p++ = ' ';
  memcpy(p, "HTTP/1.1\r\n", 10);
  p += 10;

  /* Header fields */

  for (i = 0; i < req->hcount; i++) {
    struct request_header* hdr = &req->headers[i];
    APPEND(p, hdr->name);
    *p++ = ':';
    *p++ = ' ';
    APPEND(p, hdr->value);
    *p++ = '\r';
    *p++ = '\n';
  }

  *p++ = '\r';
  *p++ = '\n';
  *p++ = '\0';

  assert(p - str == size);

  if (len)
    *len = (size_t)size - 1;

  return str;
}

/* Serialize REQ as an HTTP/1.1 request and write to fd
 * If warc_tmp is non-NULL, a copy of the bytes is also written there
 * Returns negative on error, >= 0 on success
 */
int request_send(const struct request* req, int fd, FILE* warc_tmp) {
  char* req_str;
  size_t size;
  int write_error;

  req_str = request_string(req, &size);

  DEBUGP(("\n---request begin---\n%s---request end---\n", req_str));

  /* Send bytes to the server */

  write_error = fd_write(fd, req_str, size, -1);
  if (write_error < 0)
    logprintf(LOG_VERBOSE, _("Failed writing HTTP request: %s.\n"), fd_errstr(fd));
  else if (warc_tmp) {
    /* mirror request into WARC payload */
    size_t want = size;
    size_t wrote = fwrite(req_str, 1, want, warc_tmp);
    if (wrote != want)
      write_error = -2;
  }

  xfree(req_str);
  return write_error;
}

#undef APPEND

/* Free REQ and clear the caller's reference
 * Safe to call with a pointer to NULL
 */
void request_free(struct request** req_ref) {
  int i;
  struct request* req = *req_ref;

  if (!req)
    return;

  xfree(req->arg);

  for (i = 0; i < req->hcount; i++)
    release_header(&req->headers[i]);

  xfree(req->headers);
  xfree(req);
  *req_ref = NULL;
}
