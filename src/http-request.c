/* HTTP request management.
   Separated from http.c. */

#include "wget.h"
#include "http-request.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "utils.h"
#include "xalloc.h"
#include "xstrndup.h"
#include "c-strcase.h"
#include "c-ctype.h"
#include "connect.h"
#include "log.h"
#include "gettext.h"
#include "options.h"
#include "version.h"

struct request {
  const char* method;
  char* arg;

  struct request_header {
    char *name, *value;
    enum rp release_policy;
  }* headers;
  int hcount, hcapacity;
};

/* Create a new, empty request. Set the request's method and its
   arguments.  METHOD should be a literal string (or it should outlive
   the request) because it will not be freed.  ARG will be freed by
   request_free.  */

struct request* request_new(const char* method, char* arg) {
  struct request* req = xnew0(struct request);
  req->hcapacity = 8;
  req->headers = xnew_array(struct request_header, req->hcapacity);
  req->method = method;
  req->arg = arg;
  return req;
}

/* Return the method string passed with the last call to
   request_set_method.  */

const char* request_method(const struct request* req) {
  return req->method;
}

/* Free one header according to the release policy specified with
   request_set_header.  */

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

/* Set the request named NAME to VALUE.  Specifically, this means that
   a "NAME: VALUE\r\n" header line will be used in the request.  If a
   header with the same name previously existed in the request, its
   value will be replaced by this one.  A NULL value means do nothing.

   RELEASE_POLICY determines whether NAME and VALUE should be released
   (freed) with request_free.  Allowed values are:

    - rel_none     - don't free NAME or VALUE
    - rel_name     - free NAME when done
    - rel_value    - free VALUE when done
    - rel_both     - free both NAME and VALUE when done

   Setting release policy is useful when arguments come from different
   sources.  For example:

     // Don't free literal strings!
     request_set_header (req, "Pragma", "no-cache", rel_none);

     // Don't free a global variable, we'll need it later.
     request_set_header (req, "Referer", opt.referer, rel_none);

     // Value freshly allocated, free it when done.
     request_set_header (req, "Range",
                         aprintf ("bytes=%s-", number_to_static_string (hs->restval)),
                         rel_value);
   */

void request_set_header(struct request* req, const char* name, const char* value, enum rp release_policy) {
  struct request_header* hdr;
  int i;

  if (!value) {
    /* A NULL value is a no-op; if freeing the name is requested,
       free it now to avoid leaks.  */
    if (release_policy == rel_name || release_policy == rel_both)
      xfree(name);
    return;
  }

  for (i = 0; i < req->hcount; i++) {
    hdr = &req->headers[i];
    if (0 == c_strcasecmp(name, hdr->name)) {
      /* Replace existing header. */
      release_header(hdr);
      hdr->name = (void*)name;
      hdr->value = (void*)value;
      hdr->release_policy = release_policy;
      return;
    }
  }

  /* Install new header. */

  if (req->hcount >= req->hcapacity) {
    req->hcapacity <<= 1;
    req->headers = xrealloc(req->headers, req->hcapacity * sizeof(*hdr));
  }
  hdr = &req->headers[req->hcount++];
  hdr->name = (void*)name;
  hdr->value = (void*)value;
  hdr->release_policy = release_policy;
}

/* Like request_set_header, but sets the whole header line, as
   provided by the user using the `--header' option.  For example,
   request_set_user_header (req, "Foo: bar") works just like
   request_set_header (req, "Foo", "bar").  */

void request_set_user_header(struct request* req, const char* header) {
  const char *name, *p;

  if (!(p = strchr(header, ':')))
    return;

  name = xstrndup(header, p - header);

  ++p;
  while (c_isspace(*p))
    ++p;

  request_set_header(req, name, p, rel_name);
}

/* Remove the header with specified name from REQ.  Returns true if
   the header was actually removed, false otherwise.  */

bool request_remove_header(struct request* req, const char* name) {
  int i;
  for (i = 0; i < req->hcount; i++) {
    struct request_header* hdr = &req->headers[i];
    if (0 == c_strcasecmp(name, hdr->name)) {
      release_header(hdr);
      /* Move the remaining headers by one. */
      if (i < req->hcount - 1)
        memmove(hdr, hdr + 1, (req->hcount - i - 1) * sizeof(*hdr));
      --req->hcount;
      return true;
    }
  }
  return false;
}

void request_set_user_agent(struct request* req) {
  if (opt.useragent)
    request_set_header(req, "User-Agent", opt.useragent, rel_none);
  else
    request_set_header(req, "User-Agent", "Wget/" PACKAGE_VERSION, rel_none);
}

#define APPEND(p, str)       \
  do {                       \
    int A_len = strlen(str); \
    memcpy(p, str, A_len);   \
    p += A_len;              \
  } while (0)

/* Construct the request and write it to FD using fd_write.
   If warc_tmp is set to a file pointer, the request string will
   also be written to that file. */

int request_send(const struct request* req, int fd, FILE* warc_tmp) {
  char *request_string, *p;
  int i, size, write_error;

  /* Count the request size. */
  size = 0;

  /* METHOD " " ARG " " "HTTP/1.0" "\r\n" */
  size += strlen(req->method) + 1 + strlen(req->arg) + 1 + 8 + 2;

  for (i = 0; i < req->hcount; i++) {
    struct request_header* hdr = &req->headers[i];
    /* NAME ": " VALUE "\r\n" */
    size += strlen(hdr->name) + 2 + strlen(hdr->value) + 2;
  }

  /* "\r\n\0" */
  size += 3;

  p = request_string = xmalloc(size);

  /* Generate the request. */

  APPEND(p, req->method);
  *p++ = ' ';
  APPEND(p, req->arg);
  *p++ = ' ';
  memcpy(p, "HTTP/1.1\r\n", 10);
  p += 10;

  for (i = 0; i < req->hcount; i++) {
    struct request_header* hdr = &req->headers[i];
    APPEND(p, hdr->name);
    *p++ = ':', *p++ = ' ';
    APPEND(p, hdr->value);
    *p++ = '\r', *p++ = '\n';
  }

  *p++ = '\r', *p++ = '\n', *p++ = '\0';
  assert(p - request_string == size);

#undef APPEND

  DEBUGP(("\n---request begin---\n%s---request end---\n", request_string));

  /* Send the request to the server. */

  write_error = fd_write(fd, request_string, size - 1, -1);
  if (write_error < 0)
    logprintf(LOG_VERBOSE, _("Failed writing HTTP request: %s.\n"), fd_errstr(fd));
  else if (warc_tmp != NULL) {
    /* Write a copy of the data to the WARC record. */
    int warc_tmp_written = fwrite(request_string, 1, size - 1, warc_tmp);
    if (warc_tmp_written != size - 1)
      write_error = -2;
  }
  xfree(request_string);
  return write_error;
}

/* Release the resources used by REQ.
   It is safe to call it with a valid pointer to a NULL pointer.
   It is not safe to call it with an invalid or NULL pointer.  */

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
