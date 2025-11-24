/* HTTP request helpers.
 * src/http_request.c
 */

#include "wget.h"

#include <assert.h>
#include <string.h>

#include "c-ctype.h"
#include "c-strcase.h"
#include "connect.h"
#include "http_request.h"
#include "utils.h"
#include "xstrndup.h"

struct request_header {
  char *name, *value;
  enum rp release_policy;
};

struct request {
  const char* method;
  char* arg;
  struct request_header* headers;
  int hcount;
  int hcapacity;
};

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

struct request* request_new(const char* method, char* arg) {
  struct request* req = xnew0(struct request);
  req->hcapacity = 8;
  req->headers = xnew_array(struct request_header, req->hcapacity);
  req->method = method;
  req->arg = arg;
  return req;
}

const char* request_method(const struct request* req) {
  return req->method;
}

void request_set_header(struct request* req, const char* name, const char* value, enum rp release_policy) {
  struct request_header* hdr;
  int i;

  if (!value) {
    if (release_policy == rel_name || release_policy == rel_both)
      xfree(name);
    return;
  }

  for (i = 0; i < req->hcount; i++) {
    hdr = &req->headers[i];
    if (0 == c_strcasecmp(name, hdr->name)) {
      release_header(hdr);
      hdr->name = (void*)name;
      hdr->value = (void*)value;
      hdr->release_policy = release_policy;
      return;
    }
  }

  if (req->hcount >= req->hcapacity) {
    req->hcapacity <<= 1;
    req->headers = xrealloc(req->headers, req->hcapacity * sizeof(*hdr));
  }
  hdr = &req->headers[req->hcount++];
  hdr->name = (void*)name;
  hdr->value = (void*)value;
  hdr->release_policy = release_policy;
}

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

bool request_remove_header(struct request* req, const char* name) {
  int i;
  for (i = 0; i < req->hcount; i++) {
    struct request_header* hdr = &req->headers[i];
    if (0 == c_strcasecmp(name, hdr->name)) {
      release_header(hdr);
      if (i < req->hcount - 1)
        memmove(hdr, hdr + 1, (req->hcount - i - 1) * sizeof(*hdr));
      --req->hcount;
      return true;
    }
  }
  return false;
}

int request_send(const struct request* req, int fd, FILE* warc_tmp) {
  char *request_string, *p;
  int i, size, write_error;

#define APPEND(p_, str)      \
  do {                       \
    int A_len = strlen(str); \
    memcpy(p_, str, A_len);  \
    p_ += A_len;             \
  } while (0)

  size = 0;
  size += strlen(req->method) + 1 + strlen(req->arg) + 1 + 8 + 2;

  for (i = 0; i < req->hcount; i++) {
    struct request_header* hdr = &req->headers[i];
    size += strlen(hdr->name) + 2 + strlen(hdr->value) + 2;
  }

  size += 3;

  p = request_string = xmalloc(size);

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

  write_error = fd_write(fd, request_string, size - 1, -1);
  if (write_error < 0)
    logprintf(LOG_VERBOSE, _("Failed writing HTTP request: %s.\n"), fd_errstr(fd));
  else if (warc_tmp != NULL) {
    int warc_tmp_written = fwrite(request_string, 1, size - 1, warc_tmp);
    if (warc_tmp_written != size - 1)
      write_error = -2;
  }
  xfree(request_string);
  return write_error;
}

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
