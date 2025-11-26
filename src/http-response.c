/* HTTP response management.
   Separated from http.c. */

#include "wget.h"
#include "http-response.h"

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
#include "quotearg.h"
#include "log.h"
#include "gettext.h"
#include "retr.h"

/* The maximum size of a single HTTP response we care to read.  Rather
   than being a limit of the reader implementation, this limit
   prevents Wget from slurping all available memory upon encountering
   malicious or buggy server output, thus protecting the user.  Define
   it to 0 to remove the limit.  */

#define HTTP_RESPONSE_MAX_SIZE 65536

struct response {
  /* The response data. */
  const char* data;

  /* The array of pointers that indicate where each header starts.
     For example, given this HTTP response:

       HTTP/1.0 200 Ok
       Description: some
        text
       Etag: x

     The headers are located like this:

     "HTTP/1.0 200 Ok\r\nDescription: some\r\n text\r\nEtag: x\r\n\r\n"
     ^                   ^                             ^          ^
     headers[0]          headers[1]                    headers[2] headers[3]

     I.e. headers[0] points to the beginning of the request,
     headers[1] points to the end of the first header and the
     beginning of the second one, etc.  */

  const char** headers;
};

/* Create a new response object from the text of the HTTP response,
   available in HEAD.  That text is automatically split into
   constituent header lines for fast retrieval using
   resp_header_*.  */

struct response* resp_new(char* head) {
  char* hdr;
  int count, size;

  struct response* resp = xnew0(struct response);
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

      // continuation, transform \r and \n into spaces
      *end = ' ';
      if (end > head && end[-1] == '\r')
        end[-1] = ' ';
    }
  }
  DO_REALLOC(resp->headers, size, count + 1, const char*);
  resp->headers[count] = NULL;

  return resp;
}

/* Locate the header named NAME in the request data, starting with
   position START.  This allows the code to loop through the request
   data, filtering for all requests of a given name.  Returns the
   found position, or -1 for failure.  The code that uses this
   function typically looks like this:

     for (pos = 0; (pos = resp_header_locate (...)) != -1; pos++)
       ... do something with header ...

   If you only care about one header, use resp_header_get instead of
   this function.  */

int resp_header_locate(const struct response* resp, const char* name, int start, const char** begptr, const char** endptr) {
  int i;
  const char** headers = resp->headers;
  int name_len;

  if (!headers || !headers[1])
    return -1;

  name_len = strlen(name);
  if (start > 0)
    i = start;
  else
    i = 1;

  for (; headers[i + 1]; i++) {
    const char* b = headers[i];
    const char* e = headers[i + 1];
    if (e - b > name_len && b[name_len] == ':' && 0 == c_strncasecmp(b, name, name_len)) {
      b += name_len + 1;
      while (b < e && c_isspace(*b))
        ++b;
      while (b < e && c_isspace(e[-1]))
        --e;
      *begptr = b;
      *endptr = e;
      return i;
    }
  }
  return -1;
}

/* Find and retrieve the header named NAME in the request data.  If
   found, set *BEGPTR to its starting, and *ENDPTR to its ending
   position, and return true.  Otherwise return false.

   This function is used as a building block for resp_header_copy
   and resp_header_strdup.  */

bool resp_header_get(const struct response* resp, const char* name, const char** begptr, const char** endptr) {
  int pos = resp_header_locate(resp, name, 0, begptr, endptr);
  return pos != -1;
}

/* Copy the response header named NAME to buffer BUF, no longer than
   BUFSIZE (BUFSIZE includes the terminating 0).  If the header
   exists, true is returned, false otherwise.  If there should be no
   limit on the size of the header, use resp_header_strdup instead.

   If BUFSIZE is 0, no data is copied, but the boolean indication of
   whether the header is present is still returned.  */

bool resp_header_copy(const struct response* resp, const char* name, char* buf, int bufsize) {
  const char *b, *e;
  if (!resp_header_get(resp, name, &b, &e))
    return false;
  if (bufsize) {
    int len = MIN(e - b, bufsize - 1);
    memcpy(buf, b, len);
    buf[len] = '\0';
  }
  return true;
}

/* Return the value of header named NAME in RESP, allocated with
   malloc.  If such a header does not exist in RESP, return NULL.  */

char* resp_header_strdup(const struct response* resp, const char* name) {
  const char *b, *e;
  if (!resp_header_get(resp, name, &b, &e))
    return NULL;
  return strdupdelim(b, e);
}

/* Parse the HTTP status line, which is of format:

   HTTP-Version SP Status-Code SP Reason-Phrase

   The function returns the status-code, or -1 if the status line
   appears malformed.  The pointer to "reason-phrase" message is
   returned in *MESSAGE.  */

int resp_status(const struct response* resp, char** message) {
  int status;
  const char *p, *end;

  if (!resp->headers) {
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

/* Release the resources used by RESP.
   It is safe to call it with a valid pointer to a NULL pointer.
   It is not safe to call it with a invalid or NULL pointer.  */

void resp_free(struct response** resp_ref) {
  struct response* resp = *resp_ref;

  if (!resp)
    return;

  xfree(resp->headers);
  xfree(resp);

  *resp_ref = NULL;
}

/* Print a single line of response, the characters [b, e).  We tried
   getting away with
      logprintf (LOG_VERBOSE, "%s%.*s\n", prefix, (int) (e - b), b);
   but that failed to escape the non-printable characters and, in fact,
   caused crashes in UTF-8 locales.  */

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

/* Print the server response, line by line, omitting the trailing CRLF
   from individual header lines, and prefixed with PREFIX.  */

void print_server_response(const struct response* resp, const char* prefix) {
  int i;
  if (!resp->headers)
    return;
  for (i = 0; resp->headers[i + 1]; i++) {
    const char* b = resp->headers[i];
    const char* e = resp->headers[i + 1];
    /* Skip CRLF */
    if (b < e && e[-1] == '\n')
      --e;
    if (b < e && e[-1] == '\r')
      --e;
    print_response_line(prefix, b, e);
  }
}

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

/* Read the HTTP request head from FD and return it.  The error
   conditions are the same as with fd_read_hunk.

   To support HTTP/0.9 responses, this function tries to make sure
   that the data begins with "HTTP".  If this is not the case, no data
   is read and an empty request is returned, so that the remaining
   data can be treated as body.  */

char* read_http_response_head(int fd) {
  return fd_read_hunk(fd, response_head_terminator, 512, HTTP_RESPONSE_MAX_SIZE);
}
