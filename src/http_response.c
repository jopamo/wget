/* HTTP response parsing helpers.
 * src/http_response.c
 */

#include "http_response.h"

#include <assert.h>
#include <string.h>

#include "c-strcase.h"
#include "retr.h"
#include "utils.h"
#include "http_internal.h"
#include "url.h"

/* Some status code validation macros: */

struct http_response {
  char* data;
  const char** headers;
};

/* The maximum size of a single HTTP response we care to read.  Rather
   than being a limit of the reader implementation, this limit
   prevents Wget from slurping all available memory upon encountering
   malicious or buggy server output, thus protecting the user.  Define
   it to 0 to remove the limit.  */
#define HTTP_RESPONSE_MAX_SIZE 65536

/* Determine whether [START, PEEKED + PEEKLEN) contains an empty line.
   If so, return the pointer to the position after the line, otherwise
   return NULL.  This is used as callback to fd_read_hunk.  The data
   between START and PEEKED has been read and cannot be "unread"; the
   data after PEEKED has only been peeked.  */
static const char* response_head_terminator(const char* start, const char* peeked, int peeklen) {
  const char *p, *end;

  /* If at first peek, verify whether HUNK starts with "HTTP".  If
     not, this is a HTTP/0.9 request and we must bail out without
     reading anything.  */
  if (start == peeked && 0 != memcmp(start, "HTTP", MIN(peeklen, 4)))
    return start;

  /* Look for "\n[\r]\n", and return the following position if found.
     Start two chars before the current to cover the possibility that
     part of the terminator (e.g. "\n\r") arrived in the previous
     batch.  */
  p = peeked - start < 2 ? start : peeked - 2;
  end = peeked + peeklen;

  /* Check for \n\r\n or \n\n anywhere in [p, end-2). */
  for (; p < end - 2; p++)
    if (*p == '\n') {
      if (p[1] == '\r' && p[2] == '\n')
        return p + 3;
      else if (p[1] == '\n')
        return p + 2;
    }
  /* p==end-2: check for \n\n directly preceding END. */
  if (peeklen >= 2 && p[0] == '\n' && p[1] == '\n')
    return p + 2;

  return NULL;
}

char* http_response_read_head(int fd) {
  return fd_read_hunk(fd, response_head_terminator, 512, HTTP_RESPONSE_MAX_SIZE);
}

struct http_response* http_response_parse(char* head) {
  char* hdr;
  int count, size;
  struct http_response* resp;

  if (!head)
    return NULL;

  resp = xnew0(struct http_response);
  resp->data = head;

  if (*head == '\0') {
    /* Empty head means that we're dealing with a headerless
       (HTTP/0.9) response.  In that case, don't set HEADERS at
       all.  */
    return resp;
  }

  /* Split HEAD into header lines, so that resp_header_* functions
     don't need to do this over and over again.  */

  size = count = 0;
  hdr = head;
  while (1) {
    DO_REALLOC(resp->headers, size, count + 1, const char*);
    resp->headers[count++] = hdr;

    /* Break upon encountering an empty line. */
    if (!hdr[0] || (hdr[0] == '\r' && hdr[1] == '\n') || hdr[0] == '\n')
      break;

    /* Find the end of HDR, including continuations. */
    for (;;) {
      char* end = strchr(hdr, '\n');

      if (!end) {
        hdr += strlen(hdr);
        break;
      }

      hdr = end + 1;

      if (*hdr != ' ' && *hdr != '\t')
        break;

      /* continuation, transform \r and \n into spaces */
      *end = ' ';
      if (end > head && end[-1] == '\r')
        end[-1] = ' ';
    }
  }
  DO_REALLOC(resp->headers, size, count + 1, const char*);
  resp->headers[count] = NULL;

  return resp;
}

int http_response_header_locate(const struct http_response* resp, const char* name, int start, const char** begptr, const char** endptr) {
  int i;
  const char** headers;
  int name_len;

  if (!resp)
    return -1;

  headers = resp->headers;

  if (!headers || !headers[1])
    return -1;

  name_len = strlen(name);
  if (start > 0)
    i = start;
  else
    i = 1;
  for (; headers[i + 1]; i++) {
    const char *b, *e;

    b = headers[i];
    e = headers[i + 1];
    if (b >= e)
      continue;

    if (b[name_len] != ':')
      continue;
    if (0 != c_strncasecmp(name, b, name_len))
      continue;

    /* Header name is matched; advance over the colon. */
    b += name_len + 1;

    /* Find the beginning and end of the header contents, ignoring
       leading and trailing whitespace. */
    while (b < e && c_isspace(*b))
      ++b;
    while (b < e && c_isspace(e[-1]))
      --e;
    if (b == e)
      continue;

    if (begptr)
      *begptr = b;
    if (endptr)
      *endptr = e;
    return i;
  }
  return -1;
}

bool http_response_header_get(const struct http_response* resp, const char* name, const char** begptr, const char** endptr) {
  int pos = http_response_header_locate(resp, name, 0, begptr, endptr);
  return pos != -1;
}

bool http_response_header_copy(const struct http_response* resp, const char* name, char* buf, int bufsize) {
  const char *b, *e;
  if (!http_response_header_get(resp, name, &b, &e))
    return false;
  if (bufsize <= 0)
    return true;
  int len = MIN(e - b, bufsize - 1);
  memcpy(buf, b, len);
  buf[len] = '\0';
  return true;
}

char* http_response_header_strdup(const struct http_response* resp, const char* name) {
  const char *b, *e;
  if (!http_response_header_get(resp, name, &b, &e))
    return NULL;
  return strdupdelim(b, e);
}

int http_response_status(const struct http_response* resp, char** message) {
  int status;
  const char *p, *end;

  if (!resp || !resp->headers) {
    /* For a HTTP/0.9 response, assume status 200. */
    if (message)
      *message = xstrdup(_("No headers, assuming HTTP/0.9"));
    return 200;
  }

  p = resp->headers[0];
  end = resp->headers[1];

  if (!end)
    return -1;

  /* "HTTP" */
  if (end - p < 4 || 0 != strncmp(p, "HTTP", 4))
    return -1;
  p += 4;

  /* Match the HTTP version.  This is optional because Gnutella
     servers have been reported to not specify HTTP version.  */
  if (p < end && *p == '/') {
    ++p;
    while (p < end && c_isdigit(*p))
      ++p;
    if (p < end && *p == '.')
      ++p;
    while (p < end && c_isdigit(*p))
      ++p;
  }

  while (p < end && c_isspace(*p))
    ++p;
  if (end - p < 3 || !c_isdigit(p[0]) || !c_isdigit(p[1]) || !c_isdigit(p[2]))
    return -1;

  status = 100 * (p[0] - '0') + 10 * (p[1] - '0') + (p[2] - '0');
  p += 3;

  if (message) {
    while (p < end && c_isspace(*p))
      ++p;
    while (p < end && c_isspace(end[-1]))
      --end;
    *message = strdupdelim(p, end);
  }

  return status;
}

void http_response_free(struct http_response** resp_ref) {
  struct http_response* resp;

  if (!resp_ref)
    return;

  resp = *resp_ref;
  if (!resp)
    return;

  xfree(resp->headers);
  xfree(resp->data);
  xfree(resp);

  *resp_ref = NULL;
}

static void print_response_line(const char* prefix, const char* b, const char* e) {
  char buf[1024], *copy;
  size_t len = e - b;

  if (len < sizeof(buf))
    copy = buf;
  else
    copy = xmalloc(len + 1);

  memcpy(copy, b, len);
  copy[len] = 0;

  logprintf(LOG_ALWAYS, "%s%s\n", prefix, quotearg_style(escape_quoting_style, copy));

  if (copy != buf)
    xfree(copy);
}

void http_response_print(const struct http_response* resp, const char* prefix) {
  int i;
  const char** headers;

  if (!resp)
    return;

  headers = resp->headers;
  if (!headers)
    return;

  for (i = 0; headers[i + 1]; i++) {
    const char* b = headers[i];
    const char* e = headers[i + 1];
    /* Skip CRLF */
    if (b < e && e[-1] == '\n')
      --e;
    if (b < e && e[-1] == '\r')
      --e;
    print_response_line(prefix, b, e);
  }
}

void http_stat_reset(struct http_stat* hs) {
  if (!hs)
    return;

  hs->len = 0;
  hs->contlen = -1;
  hs->res = -1;
  xfree(hs->rderrmsg);
  hs->rderrmsg = NULL;
  xfree(hs->newloc);
  hs->newloc = NULL;
  xfree(hs->remote_time);
  hs->remote_time = NULL;
  xfree(hs->error);
  hs->error = NULL;
  xfree(hs->message);
  hs->message = NULL;
  hs->local_encoding = ENC_NONE;
  hs->remote_encoding = ENC_NONE;
}

void http_stat_set_message(struct http_stat* hs, const char* message) {
  if (!hs)
    return;

  xfree(hs->message);
  hs->message = message ? xstrdup(message) : NULL;
}

void http_stat_record_status(struct http_stat* hs, int statcode, const char* message) {
  if (!hs)
    return;

  hs->statcode = statcode;

  xfree(hs->error);
  if (statcode == -1)
    hs->error = xstrdup(_("Malformed status line"));
  else if (!message || !*message)
    hs->error = xstrdup(_("(no description)"));
  else
    hs->error = xstrdup(message);

  if (!hs->message && message)
    hs->message = xstrdup(message);
}

void http_stat_capture_headers(struct http_stat* hs, const struct http_response* resp, const struct url* u, const char* content_type, char* scratch, size_t scratch_size) {
  if (!hs || !resp)
    return;

  xfree(hs->newloc);
  hs->newloc = http_response_header_strdup(resp, "Location");

  xfree(hs->remote_time);
  hs->remote_time = http_response_header_strdup(resp, "Last-Modified");
  if (!hs->remote_time)
    hs->remote_time = http_response_header_strdup(resp, "X-Archive-Orig-last-modified");

  if (!scratch || scratch_size == 0)
    return;

  if (!http_response_header_copy(resp, "Content-Encoding", scratch, scratch_size))
    return;

  hs->local_encoding = ENC_INVALID;

  switch (scratch[0]) {
    case 'b':
    case 'B':
      if (0 == c_strcasecmp(scratch, "br"))
        hs->local_encoding = ENC_BROTLI;
      break;
    case 'c':
    case 'C':
      if (0 == c_strcasecmp(scratch, "compress"))
        hs->local_encoding = ENC_COMPRESS;
      break;
    case 'd':
    case 'D':
      if (0 == c_strcasecmp(scratch, "deflate"))
        hs->local_encoding = ENC_DEFLATE;
      break;
    case 'g':
    case 'G':
      if (0 == c_strcasecmp(scratch, "gzip"))
        hs->local_encoding = ENC_GZIP;
      break;
    case 'i':
    case 'I':
      if (0 == c_strcasecmp(scratch, "identity"))
        hs->local_encoding = ENC_NONE;
      break;
    case 'x':
    case 'X':
      if (0 == c_strcasecmp(scratch, "x-compress"))
        hs->local_encoding = ENC_COMPRESS;
      else if (0 == c_strcasecmp(scratch, "x-gzip"))
        hs->local_encoding = ENC_GZIP;
      break;
    case '\0':
      hs->local_encoding = ENC_NONE;
      break;
  }

  if (hs->local_encoding == ENC_INVALID) {
    DEBUGP(("Unrecognized Content-Encoding: %s\n", scratch));
    hs->local_encoding = ENC_NONE;
  }
#if defined(HAVE_LIBZ) && defined(ENABLE_COMPRESSION)
  else if (hs->local_encoding == ENC_GZIP && opt.compression != compression_none) {
    const char* p;
    const char* type = content_type;

    /* Make sure the Content-Type is not gzip before decompressing */
    if (type) {
      p = strchr(type, '/');
      if (p == NULL) {
        hs->remote_encoding = ENC_GZIP;
        hs->local_encoding = ENC_NONE;
      }
      else {
        p++;
        if (c_tolower(p[0]) == 'x' && p[1] == '-')
          p += 2;
        if (0 != c_strcasecmp(p, "gzip")) {
          hs->remote_encoding = ENC_GZIP;
          hs->local_encoding = ENC_NONE;
        }
      }
    }
    else {
      hs->remote_encoding = ENC_GZIP;
      hs->local_encoding = ENC_NONE;
    }

    /* don't uncompress if a file ends with '.gz' or '.tgz' */
    if (hs->remote_encoding == ENC_GZIP && u && u->file) {
      p = strrchr(u->file, '.');
      if (p && (c_strcasecmp(p, ".gz") == 0 || c_strcasecmp(p, ".tgz") == 0)) {
        DEBUGP(("Enabling broken server workaround. Will not decompress this GZip file.\n"));
        hs->remote_encoding = ENC_NONE;
      }
    }
  }
#endif
}

void http_stat_release(struct http_stat* hs) {
  if (!hs)
    return;

  xfree(hs->newloc);
  hs->newloc = NULL;
  xfree(hs->remote_time);
  hs->remote_time = NULL;
  xfree(hs->error);
  hs->error = NULL;
  xfree(hs->rderrmsg);
  hs->rderrmsg = NULL;
  xfree(hs->local_file);
  hs->local_file = NULL;
  xfree(hs->orig_file_name);
  hs->orig_file_name = NULL;
  xfree(hs->message);
  hs->message = NULL;
}
