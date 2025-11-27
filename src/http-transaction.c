/* HTTP transaction state machine
 * src/http-transaction.c
 */

#include "wget.h"
#include "http-transaction.h"
#include "http-request.h"
#include "http-response.h"
#include "http-auth.h"
#include "http-pconn.h"
#include "http-proxy.h"
#include "http-stat.h"
#include "utils.h"
#include "url.h"
#include "connect.h"
#include "retr.h"
#include "cookies.h"
#include "hsts.h"
#include "netrc.h"
#include "host.h"
#include "spider.h"
#include "warc.h"
#include "version.h"
#include "c-strcase.h"
#include "xalloc.h"
#include "xstrndup.h"
#include "log.h"
#include "gettext.h"
#include "iri.h"
#include "convert.h"
#include "http.h" /* for extract_param */

#ifdef ENABLE_XATTR
#include "xattr.h"
#endif

#ifdef HAVE_SSL
#include "ssl.h"
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Cookie jar defined in http.c */
extern struct cookie_jar* wget_cookie_jar;

/* Helper macros */
#define TEXTHTML_S "text/html"
#define TEXTXHTML_S "application/xhtml+xml"
#define TEXTCSS_S "text/css"

/* HTTP/1.0 status codes from RFC1945, provided for reference */
#define HTTP_STATUS_OK 200
#define HTTP_STATUS_CREATED 201
#define HTTP_STATUS_ACCEPTED 202
#define HTTP_STATUS_NO_CONTENT 204
#define HTTP_STATUS_PARTIAL_CONTENTS 206
#define HTTP_STATUS_MULTIPLE_CHOICES 300
#define HTTP_STATUS_MOVED_PERMANENTLY 301
#define HTTP_STATUS_MOVED_TEMPORARILY 302
#define HTTP_STATUS_SEE_OTHER 303
#define HTTP_STATUS_NOT_MODIFIED 304
#define HTTP_STATUS_TEMPORARY_REDIRECT 307
#define HTTP_STATUS_PERMANENT_REDIRECT 308
#define HTTP_STATUS_BAD_REQUEST 400
#define HTTP_STATUS_UNAUTHORIZED 401
#define HTTP_STATUS_FORBIDDEN 403
#define HTTP_STATUS_NOT_FOUND 404
#define HTTP_STATUS_RANGE_NOT_SATISFIABLE 416
#define HTTP_STATUS_INTERNAL 500
#define HTTP_STATUS_NOT_IMPLEMENTED 501
#define HTTP_STATUS_BAD_GATEWAY 502
#define HTTP_STATUS_UNAVAILABLE 503
#define HTTP_STATUS_GATEWAY_TIMEOUT 504

/* Some status code validation macros */
#define H_10X(x) (((x) >= 100) && ((x) < 200))
#define H_20X(x) (((x) >= 200) && ((x) < 300))
#define H_PARTIAL(x) ((x) == HTTP_STATUS_PARTIAL_CONTENTS)
#define H_REDIRECTED(x) \
  ((x) == HTTP_STATUS_MOVED_PERMANENTLY || (x) == HTTP_STATUS_MOVED_TEMPORARILY || (x) == HTTP_STATUS_SEE_OTHER || (x) == HTTP_STATUS_TEMPORARY_REDIRECT || (x) == HTTP_STATUS_PERMANENT_REDIRECT)

#define BEGINS_WITH(line, string_constant) (!c_strncasecmp(line, string_constant, sizeof(string_constant) - 1) && (c_isspace(line[sizeof(string_constant) - 1]) || !line[sizeof(string_constant) - 1]))

/* The idea behind these two CLOSE macros is to distinguish between
   two cases: one when the job we've been doing is finished, and we
   want to close the connection and leave, and two when something is
   seriously wrong and we're closing the connection as part of
   cleanup

   In case of keep_alive, CLOSE_FINISH should leave the connection
   open, while CLOSE_INVALIDATE should still close it

   Note that the semantics of the flag `keep_alive' is "this
   connection *will* be reused (the server has promised not to close
   the connection once we're done)", while the semantics of
   `pc_active_p && (fd) == pc_last_fd' is "we're *now* using an
   active, registered connection" */

#define CLOSE_FINISH(fd)                        \
  do {                                          \
    if (!keep_alive) {                          \
      if (pconn_active && (fd) == pconn.socket) \
        invalidate_persistent();                \
      else                                      \
        fd_close(fd);                           \
      fd = -1;                                  \
    }                                           \
  } while (0)

#define CLOSE_INVALIDATE(fd)                  \
  do {                                        \
    if (pconn_active && (fd) == pconn.socket) \
      invalidate_persistent();                \
    else                                      \
      fd_close(fd);                           \
    fd = -1;                                  \
  } while (0)

static int body_file_send(int sock, const char* file_name, wgint promised_size, FILE* warc_tmp) {
  static char chunk[8192];
  wgint written = 0;
  int write_error;
  FILE* fp;

  DEBUGP(("writing BODY file %s ... ", file_name));

  fp = fopen(file_name, "rb");
  if (!fp)
    return -1;

  while (!feof(fp) && written < promised_size) {
    int length = fread(chunk, 1, sizeof(chunk), fp);
    if (length == 0)
      break;

    int towrite = MIN(promised_size - written, length);
    write_error = fd_write(sock, chunk, towrite, -1);
    if (write_error < 0) {
      fclose(fp);
      return -1;
    }

    if (warc_tmp != NULL) {
      /* copy the payload into the WARC staging file */
      int warc_tmp_written = fwrite(chunk, 1, towrite, warc_tmp);
      if (warc_tmp_written != towrite) {
        fclose(fp);
        return -2;
      }
    }

    written += towrite;
  }

  fclose(fp);

  /* If we've written less than was promised, report a likely protocol mismatch rather than silently underflow */
  if (written < promised_size) {
    errno = EINVAL;
    return -1;
  }

  assert(written == promised_size);
  DEBUGP(("done\n"));
  return 0;
}

static bool skip_short_body(int fd, wgint contlen, bool chunked) {
  enum {
    SKIP_SIZE = 512,      /* size of the download buffer */
    SKIP_THRESHOLD = 4096 /* the largest size we read */
  };
  wgint remaining_chunk_size = 0;
  char dlbuf[SKIP_SIZE + 1];

  dlbuf[SKIP_SIZE] = '\0'; /* so DEBUGP can safely print it */

  /* If the body is too large, it makes more sense to simply close the
     connection than to try to read the body */
  if (contlen > SKIP_THRESHOLD)
    return false;

  while (contlen > 0 || chunked) {
    int ret;

    if (chunked) {
      if (remaining_chunk_size == 0) {
        char* line = fd_read_line(fd);
        char* endl;

        if (line == NULL)
          break;

        remaining_chunk_size = strtol(line, &endl, 16);
        xfree(line);

        if (remaining_chunk_size < 0)
          return false;

        if (remaining_chunk_size == 0) {
          line = fd_read_line(fd);
          xfree(line);
          break;
        }
      }

      contlen = MIN(remaining_chunk_size, SKIP_SIZE);
    }

    DEBUGP(("Skipping %s bytes of body: [", number_to_static_string(contlen)));

    ret = fd_read(fd, dlbuf, MIN(contlen, SKIP_SIZE), -1);
    if (ret <= 0) {
      /* Don't normally report the error since this is an
         optimization that should be invisible to the user */
      DEBUGP(("] aborting (%s).\n", ret < 0 ? fd_errstr(fd) : "EOF received"));
      return false;
    }

    contlen -= ret;

    if (chunked) {
      remaining_chunk_size -= ret;
      if (remaining_chunk_size == 0) {
        char* line = fd_read_line(fd);
        if (line == NULL)
          return false;
        xfree(line);
      }
    }

    /* Safe even if %.*s bogusly expects terminating \0 because
       we've zero-terminated dlbuf above */
    DEBUGP(("%.*s", ret, dlbuf));
  }

  DEBUGP(("] done.\n"));
  return true;
}

static void append_value_to_filename(char** filename, param_token const* const value, bool is_url_encoded) {
  int original_length = (int)strlen(*filename);
  int value_len = (int)(value->e - value->b);
  int new_length = original_length + value_len;

  *filename = xrealloc(*filename, (size_t)new_length + 1);
  memcpy(*filename + original_length, value->b, (size_t)value_len);
  (*filename)[new_length] = '\0';

  if (is_url_encoded)
    url_unescape(*filename + original_length);
}

static bool parse_content_disposition(const char* hdr, char** filename) {
  param_token name, value;
  bool is_url_encoded = false;

  char* encodedFilename = NULL;
  char* unencodedFilename = NULL;

  for (; extract_param(&hdr, &name, &value, ';', &is_url_encoded); is_url_encoded = false) {
    int isFilename = BOUNDED_EQUAL_NO_CASE(name.b, name.e, "filename");
    if (isFilename && value.b != NULL) {
      /* Make the file name begin at the last slash or backslash */
      bool isEncodedFilename;
      char** outFilename;
      const char* last_slash = memrchr(value.b, '/', (size_t)(value.e - value.b));
      const char* last_bs = memrchr(value.b, '\\', (size_t)(value.e - value.b));

      if (last_slash && last_bs)
        value.b = 1 + (MAX(last_slash, last_bs));
      else if (last_slash || last_bs)
        value.b = 1 + (last_slash ? last_slash : last_bs);

      if (value.b == value.e)
        continue;

      /* Check if the name is "filename*" as specified in RFC 6266
       * Since "filename" could be broken up as "filename*N" (RFC 2231),
       * a check is needed to make sure this is not the case */
      isEncodedFilename = (*name.e == '*' && !c_isdigit(*(name.e + 1)));
      outFilename = isEncodedFilename ? &encodedFilename : &unencodedFilename;

      if (*outFilename)
        append_value_to_filename(outFilename, &value, is_url_encoded);
      else {
        *outFilename = strdupdelim(value.b, value.e);
        if (is_url_encoded)
          url_unescape(*outFilename);
      }
    }
  }

  if (encodedFilename) {
    xfree(unencodedFilename);
    *filename = encodedFilename;
  }
  else {
    xfree(encodedFilename);
    *filename = unencodedFilename;
  }

  return *filename != NULL;
}

#ifdef HAVE_HSTS
static bool parse_strict_transport_security(const char* header, int64_t* max_age, bool* include_subdomains) {
  param_token name, value;
  char* c_max_age = NULL;
  bool include = false;
  bool is_url_encoded = false;
  bool success = false;

  if (!header || !*header)
    return false;

  for (; extract_param(&header, &name, &value, ';', &is_url_encoded); is_url_encoded = false) {
    if (!name.b || name.b == name.e)
      continue;

    /* handle valueless flags like preload and includeSubDomains */
    if (!value.b || value.b == value.e) {
      if (BOUNDED_EQUAL_NO_CASE(name.b, name.e, "includeSubDomains"))
        include = true;
      /* ignore preload and other flags */
      continue;
    }

    if (BOUNDED_EQUAL_NO_CASE(name.b, name.e, "max-age")) {
      xfree(c_max_age);
      c_max_age = strdupdelim(value.b, value.e);
    }
  }

  if (!c_max_age) {
    logprintf(LOG_VERBOSE, "Could not parse Strict-Transport-Security header\n");
    return false;
  }

  if (max_age)
    *max_age = (int64_t)strtoll(c_max_age, NULL, 10);
  if (include_subdomains)
    *include_subdomains = include;

  DEBUGP(("Parsed Strict-Transport-Security max-age = %s, includeSubDomains = %s\n", c_max_age, include ? "true" : "false"));

  xfree(c_max_age);
  success = true;

  return success;
}
#endif

static uerr_t time_to_rfc1123(time_t time_val, char* buf, size_t bufsize) {
  static const char* wkday[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
  static const char* month[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

  struct tm* gtm = gmtime(&time_val);
  if (!gtm) {
    logprintf(LOG_NOTQUIET, _("gmtime failed. This is probably a bug.\n"));
    return TIMECONV_ERR;
  }

  /* rfc1123 example: Thu, 01 Jan 1998 22:12:57 GMT */
  snprintf(buf, bufsize, "%s, %02d %s %04d %02d:%02d:%02d GMT", wkday[gtm->tm_wday], gtm->tm_mday, month[gtm->tm_mon], gtm->tm_year + 1900, gtm->tm_hour, gtm->tm_min, gtm->tm_sec);

  return RETROK;
}

static uerr_t set_file_timestamp(struct http_stat* hs) {
  bool local_dot_orig_file_exists = false;
  char* local_filename = NULL;
  struct stat st;
  char buf[1024];

  if (opt.backup_converted) {
    size_t filename_len = strlen(hs->local_file);
    char* filename_plus_orig_suffix;

    if (filename_len + sizeof(ORIG_SFX) > sizeof(buf))
      filename_plus_orig_suffix = xmalloc(filename_len + sizeof(ORIG_SFX));
    else
      filename_plus_orig_suffix = buf;

    memcpy(filename_plus_orig_suffix, hs->local_file, filename_len);
    memcpy(filename_plus_orig_suffix + filename_len, ORIG_SFX, sizeof(ORIG_SFX));

    /* Try to stat() the .orig file */
    if (stat(filename_plus_orig_suffix, &st) == 0) {
      local_dot_orig_file_exists = true;
      local_filename = filename_plus_orig_suffix;
    }
  }

  if (!local_dot_orig_file_exists) {
    /* Couldn't stat() <file>.orig, so try to stat() <file> */
    if (stat(hs->local_file, &st) == 0) {
      if (local_filename != buf)
        xfree(local_filename);
      local_filename = hs->local_file;
    }
  }

  if (local_filename != NULL) {
    if (local_filename == buf || local_filename == hs->local_file)
      hs->orig_file_name = xstrdup(local_filename);
    else
      hs->orig_file_name = local_filename;

    hs->orig_file_size = st.st_size;
    hs->orig_file_tstamp = st.st_mtime;
    hs->timestamp_checked = true;
  }

  return RETROK;
}

static uerr_t check_file_output(const struct url* u, struct http_stat* hs, struct response* resp, char* hdrval, size_t hdrsize) {
  /* Determine the local filename if needed; if -O is used
   * hstat.local_file is set by http_loop to the argument of -O */
  if (!hs->local_file) {
    char* local_file = NULL;

    /* Honor Content-Disposition when possible */
    if (!opt.content_disposition || !resp_header_copy(resp, "Content-Disposition", hdrval, hdrsize) || !parse_content_disposition(hdrval, &local_file)) {
      /* The Content-Disposition header is missing or broken
       * choose unique filename based on URL */
      hs->local_file = url_file_name(u, NULL);
    }
    else {
      DEBUGP(("Parsed filename from Content-Disposition: %s\n", local_file));
      hs->local_file = url_file_name(u, local_file);
    }

    xfree(local_file);
  }

  hs->temporary = opt.delete_after || opt.spider || !acceptable(hs->local_file);
  if (hs->temporary) {
    char* tmp = aprintf("%s.tmp", hs->local_file);
    xfree(hs->local_file);
    hs->local_file = tmp;
  }

  /* perform existence checks once per transaction */
  if (!hs->existence_checked && file_exists_p(hs->local_file, NULL)) {
    if (opt.noclobber && !opt.output_document) {
      /* If opt.noclobber is turned on and file already exists, do not
         retrieve the file. But if the output_document was given, then this
         test was already done and the file didn't exist */
      return RETRUNNEEDED;
    }
    else if (!ALLOW_CLOBBER) {
      char* unique = unique_name_passthrough(hs->local_file);
      if (unique != hs->local_file)
        xfree(hs->local_file);
      hs->local_file = unique;
    }
  }

  hs->existence_checked = true;

  /* Support timestamping */
  if (opt.timestamping && !hs->timestamp_checked) {
    uerr_t timestamp_err = set_file_timestamp(hs);
    if (timestamp_err != RETROK)
      return timestamp_err;
  }

  return RETROK;
}

static uerr_t
check_auth(const struct url* u, char* user, char* passwd, struct response* resp, struct request* req, bool* ntlm_seen_ref, bool* retry, bool* basic_auth_finished_ref, bool* auth_finished_ref) {
  uerr_t auth_err = RETROK;
  bool basic_auth_finished = *basic_auth_finished_ref;
  bool auth_finished = *auth_finished_ref;
  bool ntlm_seen = *ntlm_seen_ref;
  char buf[256];
  char* tmp = NULL;

  *retry = false;

  if (!req || !resp)
    goto cleanup;

  if (!auth_finished && user && passwd) {
    /* IIS sends multiple copies of WWW-Authenticate, one with
       the value "negotiate", and other(s) with data. Loop over
       all the occurrences and pick the one we recognize */
    int wapos;
    const char* www_authenticate = NULL;
    const char *wabeg, *waend;
    const char *digest = NULL, *basic = NULL, *ntlm = NULL;

    for (wapos = 0; !ntlm && (wapos = resp_header_locate(resp, "WWW-Authenticate", wapos, &wabeg, &waend)) != -1; ++wapos) {
      param_token name, value;
      size_t len = (size_t)(waend - wabeg);

      if (tmp != buf)
        xfree(tmp);

      if (len < sizeof(buf))
        tmp = buf;
      else
        tmp = xmalloc(len + 1);

      memcpy(tmp, wabeg, len);
      tmp[len] = '\0';

      www_authenticate = tmp;

      for (;;) {
        /* extract the auth-scheme */
        while (c_isspace(*www_authenticate))
          www_authenticate++;

        name.e = name.b = www_authenticate;
        while (*name.e && !c_isspace(*name.e))
          name.e++;

        if (name.b == name.e)
          break;

        DEBUGP(("Auth scheme found '%.*s'\n", (int)(name.e - name.b), name.b));

        if (known_authentication_scheme_p(name.b, name.e)) {
          if (BEGINS_WITH(name.b, "NTLM")) {
            ntlm = name.b;
            break; /* NTLM challenge wins */
          }
          else if (!digest && BEGINS_WITH(name.b, "Digest"))
            digest = name.b;
          else if (!basic && BEGINS_WITH(name.b, "Basic"))
            basic = name.b;
        }

        /* advance over auth-params */
        www_authenticate = name.e;
        DEBUGP(("Auth param list '%s'\n", www_authenticate));

        while (extract_param(&www_authenticate, &name, &value, ',', NULL) && name.b && value.b) {
          DEBUGP(("Auth param %.*s=%.*s\n", (int)(name.e - name.b), name.b, (int)(value.e - value.b), value.b));
        }
      }
    }

    if (!basic && !digest && !ntlm) {
      /* If the authentication header is missing or
         unrecognized, there's no sense in retrying */
      logputs(LOG_NOTQUIET, _("Unknown authentication scheme.\n"));
    }
    else if (!basic_auth_finished || !basic) {
      char* pth = url_full_path(u);
      const char* value;
      uerr_t* auth_stat = xmalloc(sizeof(uerr_t));

      *auth_stat = RETROK;

      if (ntlm)
        www_authenticate = ntlm;
      else if (digest)
        www_authenticate = digest;
      else
        www_authenticate = basic;

      logprintf(LOG_NOTQUIET, _("Authentication selected: %s\n"), www_authenticate);

      value = create_authorization_line(www_authenticate, user, passwd, request_method(req), pth, &auth_finished, auth_stat
#ifdef ENABLE_NTLM
                                        ,
                                        &pconn.ntlm
#endif
      );
      auth_err = *auth_stat;
      xfree(auth_stat);
      xfree(pth);

      if (auth_err == RETROK && value) {
        request_set_header(req, "Authorization", value, rel_value);

        if (BEGINS_WITH(www_authenticate, "NTLM"))
          ntlm_seen = true;
        else if (!u->user && BEGINS_WITH(www_authenticate, "Basic"))
          register_basic_auth_host(u->host);

        *retry = true;
        goto cleanup;
      }

      if (value && auth_err != RETROK)
        xfree(value);
    }
    else {
      /* already tried Basic auth with global credentials and it failed */
    }
  }

cleanup:
  if (tmp != buf)
    xfree(tmp);

  *ntlm_seen_ref = ntlm_seen;
  *basic_auth_finished_ref = basic_auth_finished;
  *auth_finished_ref = auth_finished;

  return auth_err;
}

static struct request* initialize_request(const struct url* u,
                                          struct http_stat* hs,
                                          int* dt,
                                          struct url* proxy,
                                          bool inhibit_keep_alive,
                                          bool* basic_auth_finished,
                                          wgint* body_data_size,
                                          char** user,
                                          char** passwd,
                                          uerr_t* ret) {
  bool head_only = !!(*dt & HEAD_ONLY);
  struct request* req;
  char* meth_arg;
  const char* meth = "GET";

  if (head_only)
    meth = "HEAD";
  else if (opt.method)
    meth = opt.method;

  /* Use full path, including leading slash and query part */
  if (proxy
#ifdef HAVE_SSL
      && u->scheme != SCHEME_HTTPS
#endif
  )
    meth_arg = xstrdup(u->url);
  else
    meth_arg = url_full_path(u);

  req = request_new(meth, meth_arg);

  /* Generate Host header, possibly including port and IPv6 brackets */
  {
    int add_port = (u->port != scheme_default_port(u->scheme));
    int add_squares = (strchr(u->host, ':') != NULL);
    char* host_header;

    if (add_port)
      host_header = aprintf(add_squares ? "[%s]:%d" : "%s:%d", u->host, u->port);
    else
      host_header = aprintf(add_squares ? "[%s]" : "%s", u->host);

    request_set_header(req, "Host", host_header, rel_value);
  }

  request_set_header(req, "Referer", hs->referer, rel_none);

  if (*dt & SEND_NOCACHE) {
    /* Cache-Control MUST be obeyed by all HTTP/1.1 caching mechanisms */
    request_set_header(req, "Cache-Control", "no-cache", rel_none);

    /* some HTTP/1.0 caches do not implement Cache-Control */
    request_set_header(req, "Pragma", "no-cache", rel_none);
  }

  if (*dt & IF_MODIFIED_SINCE) {
    char strtime[32];
    uerr_t err = time_to_rfc1123(hs->orig_file_tstamp, strtime, countof(strtime));

    if (err != RETROK) {
      logputs(LOG_VERBOSE, _("Cannot convert timestamp to http format. "
                             "Falling back to time 0 as last modification "
                             "time.\n"));
      strcpy(strtime, "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    request_set_header(req, "If-Modified-Since", xstrdup(strtime), rel_value);
  }

  if (hs->restval) {
    DEBUGP((_("DEBUG: Setting Range header: bytes=%s-\n"), number_to_static_string(hs->restval)));
    request_set_header(req, "Range", aprintf("bytes=%s-", number_to_static_string(hs->restval)), rel_value);
  }
  else {
    DEBUGP((_("DEBUG: No Range header (hs->restval=0)\n")));
  }

  request_set_user_agent(req);
  request_set_header(req, "Accept", "*/*", rel_none);

#ifdef HAVE_LIBZ
  if (opt.compression != compression_none)
    request_set_header(req, "Accept-Encoding", "gzip", rel_none);
  else
#endif
    request_set_header(req, "Accept-Encoding", "identity", rel_none);

  /* username priority */
  if (u->user)
    *user = u->user;
  else if (opt.user && (opt.use_askpass || opt.ask_passwd))
    *user = opt.user;
  else if (opt.http_user)
    *user = opt.http_user;
  else if (opt.user)
    *user = opt.user;
  else
    *user = NULL;

  /* password priority */
  if (u->passwd)
    *passwd = u->passwd;
  else if (opt.passwd && (opt.use_askpass || opt.ask_passwd))
    *passwd = opt.passwd;
  else if (opt.http_passwd)
    *passwd = opt.http_passwd;
  else if (opt.passwd)
    *passwd = opt.passwd;
  else
    *passwd = NULL;

  /* Check for ~/.netrc if none of the above match */
  if (opt.netrc && (!*user || !*passwd))
    search_netrc(u->host, (const char**)user, (const char**)passwd, 0, NULL);

  /* Site-wide authentication with global user/password unless overridden or challenge-less is disabled */
  if (*user && *passwd && (!u->user || opt.auth_without_challenge)) {
    /* If this host is registered for Basic, send creds preemptively */
    *basic_auth_finished = maybe_send_basic_creds(u->host, *user, *passwd, req);
  }

  if (inhibit_keep_alive)
    request_set_header(req, "Connection", "Close", rel_none);
  else {
    request_set_header(req, "Connection", "Keep-Alive", rel_none);
    if (proxy)
      request_set_header(req, "Proxy-Connection", "Keep-Alive", rel_none);
  }

  *body_data_size = 0;

  if (opt.method) {
    if (opt.body_data || opt.body_file) {
      request_set_header(req, "Content-Type", "application/x-www-form-urlencoded", rel_none);

      if (opt.body_data)
        *body_data_size = (wgint)strlen(opt.body_data);
      else {
        *body_data_size = file_size(opt.body_file);
        if (*body_data_size == -1) {
          logprintf(LOG_NOTQUIET, _("BODY data file %s missing: %s\n"), quote(opt.body_file), strerror(errno));
          request_free(&req);
          *ret = FILEBADFILE;
          return NULL;
        }
      }

      request_set_header(req, "Content-Length", xstrdup(number_to_static_string(*body_data_size)), rel_value);
    }
    else if (c_strcasecmp(opt.method, "post") == 0 || c_strcasecmp(opt.method, "put") == 0 || c_strcasecmp(opt.method, "patch") == 0) {
      request_set_header(req, "Content-Length", "0", rel_none);
    }
  }

  *ret = RETROK;
  return req;
}

static uerr_t
establish_connection(const struct url* u, const struct url** conn_ref, struct url* proxy, char** proxyauth, struct request** req_ref, bool* using_ssl, bool inhibit_keep_alive, int* sock_ref) {
  bool host_lookup_failed = false;
  int sock = *sock_ref;
  struct request* req = *req_ref;
  const struct url* conn = *conn_ref;

  if (!inhibit_keep_alive) {
    /* Look for a persistent connection to target host, unless a
       proxy is used. The exception is when SSL is in use, in which
       case the proxy is a passthrough to the target host */
    const struct url* relevant = conn;
#ifdef HAVE_SSL
    if (u->scheme == SCHEME_HTTPS)
      relevant = u;
#endif

    if (persistent_available_p(relevant->host, relevant->port,
#ifdef HAVE_SSL
                               relevant->scheme == SCHEME_HTTPS,
#else
                               false,
#endif
                               &host_lookup_failed)) {
      int family = socket_family(pconn.socket, ENDPOINT_PEER);
      sock = pconn.socket;
      *using_ssl = pconn.ssl;
#if ENABLE_IPV6
      if (family == AF_INET6)
        logprintf(LOG_VERBOSE, _("Reusing existing connection to [%s]:%d.\n"), quotearg_style(escape_quoting_style, pconn.host), pconn.port);
      else
#endif
        logprintf(LOG_VERBOSE, _("Reusing existing connection to %s:%d.\n"), quotearg_style(escape_quoting_style, pconn.host), pconn.port);

      DEBUGP(("Reusing fd %d.\n", sock));
      if (pconn.authorized)
        /* If the connection is already authorized, the "Basic"
           authorization added above is unnecessary */
        request_remove_header(req, "Authorization");
    }
    else if (host_lookup_failed) {
      logprintf(LOG_NOTQUIET, _("%s: unable to resolve host address %s\n"), exec_name, quote(relevant->host));
      return HOSTERR;
    }
    else if (sock != -1) {
      sock = -1;
    }
  }

  if (sock < 0) {
    sock = connect_to_host(conn->host, conn->port);
    if (sock == E_HOST)
      return HOSTERR;
    else if (sock < 0)
      return retryable_socket_connect_error(errno) ? CONERROR : CONIMPOSSIBLE;

#ifdef HAVE_SSL
    if (proxy && u->scheme == SCHEME_HTTPS) {
      uerr_t err = establish_proxy_tunnel(u, sock, proxyauth);
      if (err != RETROK) {
        CLOSE_INVALIDATE(sock);
        return err;
      }

      /* SOCK is now connected to u->host, so update CONN
         to reflect this for persistence bookkeeping */
      conn = u;
    }

    if (conn->scheme == SCHEME_HTTPS) {
      if (!ssl_connect_wget(sock, u->host, NULL)) {
        CLOSE_INVALIDATE(sock);
        return CONSSLERR;
      }
      else if (!ssl_check_certificate(sock, u->host)) {
        CLOSE_INVALIDATE(sock);
        return VERIFCERTERR;
      }
      *using_ssl = true;
    }
#endif /* HAVE_SSL */
  }

  *conn_ref = conn;
  *req_ref = req;
  *sock_ref = sock;
  return RETROK;
}

static uerr_t open_output_stream(struct http_stat* hs, int count, FILE** fp) {
  /* Open the local file for writing the payload */
  if (!output_stream) {
    mkalldirs(hs->local_file);

    if (opt.backups)
      rotate_backups(hs->local_file);

    if (hs->restval) {
      *fp = fopen(hs->local_file, "ab");
    }
    else if (ALLOW_CLOBBER || count > 0) {
      if (opt.unlink_requested && file_exists_p(hs->local_file, NULL)) {
        if (unlink(hs->local_file) < 0) {
          logprintf(LOG_NOTQUIET, "%s: %s\n", hs->local_file, strerror(errno));
          return UNLINKERR;
        }
      }

      if (hs->temporary) {
        int fd = open(hs->local_file, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
        if (fd < 0) {
          logprintf(LOG_NOTQUIET, "%s: %s\n", hs->local_file, strerror(errno));
          return FOPENERR;
        }
        *fp = fdopen(fd, "wb");
      }
      else {
        *fp = fopen(hs->local_file, "wb");
      }
    }
    else {
      *fp = fopen_excl(hs->local_file, true);
      if (!*fp && errno == EEXIST) {
        /* We cannot silently invent a new name; user was told which name would be used */
        logprintf(LOG_NOTQUIET, _("%s has sprung into existence.\n"), hs->local_file);
        return FOPEN_EXCL_ERR;
      }
    }

    if (!*fp) {
      logprintf(LOG_NOTQUIET, "%s: %s\n", hs->local_file, strerror(errno));
      return FOPENERR;
    }
  }
  else {
    /* When using --output-document, we need to handle the case where
     * the server ignored our range request and we need to restart from 0 */
    if (hs->restval == 0 && output_stream_regular) {
      /* Server ignored range request or we are doing a fresh download */
      logprintf(LOG_VERBOSE, _("Truncating output document due to ignored range request\n"));

      /* Use ftruncate to truncate the file to 0 bytes and reposition to start */
      int fd = fileno(output_stream);
      if (ftruncate(fd, 0) == -1) {
        logprintf(LOG_NOTQUIET, "%s: %s\n", opt.output_document, strerror(errno));
        return FOPENERR;
      }

      /* Reposition to the beginning of the file */
      rewind(output_stream);
      fflush(output_stream);
      DEBUGP((_("DEBUG: After truncating output_stream, position=%ld\n"), ftell(output_stream)));
    }
    else if (hs->restval == 0) {
      DEBUGP((_("DEBUG: hs->restval is 0 but output_stream_regular is false\n")));
    }
    *fp = output_stream;
  }

  /* Print fetch message, if opt.verbose */
  logprintf(LOG_VERBOSE, _("Saving to: %s\n"), HYPHENP(hs->local_file) ? quote("STDOUT") : quote(hs->local_file));

  return RETROK;
}

static void set_content_type(int* dt, const char* type) {
  /* If content-type is not given, assume text/html because of many broken CGI scripts */
  if (!type || 0 == c_strcasecmp(type, TEXTHTML_S) || 0 == c_strcasecmp(type, TEXTXHTML_S))
    *dt |= TEXTHTML;
  else
    *dt &= ~TEXTHTML;

  if (type && 0 == c_strcasecmp(type, TEXTCSS_S))
    *dt |= TEXTCSS;
  else
    *dt &= ~TEXTCSS;
}

static int read_response_body(struct http_stat* hs,
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
                              char* head) {
  int warc_payload_offset = 0;
  FILE* warc_tmp = NULL;
  int warcerr = 0;
  int flags = 0;

  if (opt.warc_filename != NULL) {
    /* Open a temporary file where we can write the response before we
       add it to the WARC record */
    warc_tmp = warc_tempfile();
    if (warc_tmp == NULL)
      warcerr = WARC_TMP_FOPENERR;

    if (warcerr == 0) {
      /* keep the response headers for the WARC record */
      int head_len = (int)strlen(head);
      int warc_tmp_written = (int)fwrite(head, 1, (size_t)head_len, warc_tmp);
      if (warc_tmp_written != head_len)
        warcerr = WARC_TMP_FWRITEERR;
      warc_payload_offset = head_len;
    }

    if (warcerr != 0) {
      if (warc_tmp != NULL)
        fclose(warc_tmp);
      return warcerr;
    }
  }

  if (fp != NULL) {
    /* This confuses the timestamping code that checks for file size
       #### The timestamping code should be smarter about file size */
    if (opt.save_headers && hs->restval == 0)
      fwrite(head, 1, strlen(head), fp);
  }

  /* Read the response body */
  if (contlen != -1)
    /* If content-length is present, read that much; otherwise, read
       until EOF. The HTTP spec does not require the server to
       close the connection when done sending data */
    flags |= rb_read_exactly;

  /* Only consider skipping bytes when the server sent a full response from byte 0 */
  if (fp != NULL && contrange == 0 && statcode == HTTP_STATUS_OK) {
    wgint skip_bytes = hs->original_restval > 0 ? hs->original_restval : hs->restval;

    /* Don't skip if we restarted from byte 0 and truncated the file */
    if (skip_bytes > 0 && hs->restval > 0) {
      DEBUGP((_("DEBUG: Setting rb_skip_startpos flag: skip_bytes=%s, contrange=%s\n"), number_to_static_string(skip_bytes), number_to_static_string(contrange)));
      flags |= rb_skip_startpos;
    }
    else {
      DEBUGP((_("DEBUG: NOT setting rb_skip_startpos flag: skip_bytes=%s, contrange=%s, hs->restval=%s\n"), number_to_static_string(skip_bytes), number_to_static_string(contrange),
              number_to_static_string(hs->restval)));
    }
  }

  if (chunked_transfer_encoding)
    flags |= rb_chunked_transfer_encoding;

  if (hs->remote_encoding == ENC_GZIP)
    flags |= rb_compressed_gzip;

  hs->len = hs->restval;
  hs->rd_size = 0;

  /* Download the response body and write it to fp.
     If we are working on a WARC file, write the
     response body to warc_tmp in parallel */
  hs->res = fd_read_body(hs->local_file, sock, fp, contlen != -1 ? contlen : 0, hs->restval, &hs->rd_size, &hs->len, &hs->dltime, flags, warc_tmp);
  DEBUGP((_("DEBUG: After fd_read_body, hs->res=%d, hs->rd_size=%s, hs->len=%s\n"), hs->res, number_to_static_string(hs->rd_size), number_to_static_string(hs->len)));
  if (hs->res >= 0) {
    if (warc_tmp != NULL) {
      /* Create a response record and write it to the WARC file.
         The request and response share the same date header and
         the response refers to the uuid of the request */
      bool r = warc_write_response_record(url, warc_timestamp_str, warc_request_uuid, warc_ip, warc_tmp, warc_payload_offset, type, statcode, hs->newloc);

      /* warc_write_response_record has closed warc_tmp */

      if (!r)
        return WARC_ERR;
    }

    return RETRFINISHED;
  }

  if (warc_tmp != NULL)
    fclose(warc_tmp);

  if (hs->res == -2) {
    /* Error while writing to fd */
    return FWRITEERR;
  }
  else if (hs->res == -3) {
    /* Error while writing to warc_tmp */
    return WARC_TMP_FWRITEERR;
  }
  else {
    /* A read error */
    xfree(hs->rderrmsg);
    hs->rderrmsg = xstrdup(fd_errstr(sock));
    return RETRFINISHED;
  }
}

/* The main transaction function (formerly gethttp) */
uerr_t http_transaction_run(const struct url* u, struct url* original_url, struct http_stat* hs, int* dt, struct url* proxy, struct iri* iri, int count) {
  struct request* req = NULL;

  char* type = NULL;
  char *user, *passwd;
  char* proxyauth = NULL;
  int statcode;
  int write_error;
  wgint contlen, contrange;
  const struct url* conn;
  FILE* fp;
  int err;
  uerr_t retval;

#ifdef HAVE_HSTS
#ifdef TESTING
  /* we don't link against main.o when we're testing */
  hsts_store_t hsts_store = NULL;
#else
  extern hsts_store_t hsts_store;
#endif
#endif

  int sock = -1;

#ifndef ENABLE_IRI
  (void)iri;
#endif

  /* Set to 1 when the authorization has already been sent and should
     not be tried again */
  bool auth_finished = false;

  /* Set to 1 when just globally-set Basic authorization has been sent;
   * should prevent further Basic negotiations, but not other
   * mechanisms */
  bool basic_auth_finished = false;

  /* Whether NTLM authentication is used for this request */
  bool ntlm_seen = false;

  /* Whether our connection to the remote host is through SSL */
  bool using_ssl = false;

  /* Whether a HEAD request will be issued (as opposed to GET or POST) */
  bool head_only = !!(*dt & HEAD_ONLY);

  char* head = NULL;
  struct response* resp = NULL;
  char hdrval[512];
  char* message = NULL;

  /* Declare WARC variables */
  bool warc_enabled = (opt.warc_filename != NULL);
  FILE* warc_tmp = NULL;
  char warc_timestamp_str[21];
  char warc_request_uuid[48];
  ip_address warc_ip_buf;
  ip_address* warc_ip = NULL;

  /* Initialize WARC variables if WARC is enabled */
  if (warc_enabled) {
    warc_timestamp(warc_timestamp_str, sizeof(warc_timestamp_str));
    warc_uuid_str(warc_request_uuid, sizeof(warc_request_uuid));
  }

  /* Whether keep-alive should be inhibited */
  bool inhibit_keep_alive = !opt.http_keep_alive || opt.ignore_length;

  /* Whether this connection will be kept alive after the HTTP request
     is done */
  bool keep_alive = !inhibit_keep_alive;

  /* Is the server using the chunked transfer encoding */
  bool chunked_transfer_encoding = false;

  /* Headers sent when using POST */
  wgint body_data_size = 0;

#ifdef HAVE_SSL
  if (u->scheme == SCHEME_HTTPS) {
    /* Initialize the SSL context; subsequent calls are no-ops */
    if (!ssl_init()) {
      scheme_disable(SCHEME_HTTPS);
      logprintf(LOG_NOTQUIET, _("Disabling SSL due to encountered errors.\n"));
      retval = SSLINITFAILED;
      goto cleanup;
    }
  }
#endif /* HAVE_SSL */

  /* Initialize certain elements of struct http_stat.
   * Since this function is called in a loop, we have to xfree certain
   * members */
  hs->len = 0;
  hs->contlen = -1;
  hs->res = -1;
  xfree(hs->rderrmsg);
  xfree(hs->newloc);
  xfree(hs->remote_time);
  xfree(hs->error);
  xfree(hs->message);

  /* If we're using a proxy, we will be connecting to the proxy server */
  conn = proxy ? proxy : u;

  /* Check for Basic auth header */
  if (opt.user && opt.passwd && opt.auth_without_challenge)
    basic_auth_finished = true;
  else if (u->user && u->passwd)
    basic_auth_finished = true;

  user = passwd = NULL; /* will be set by initialize_request */

retry_with_auth:
  /* On retry we must close any existing socket and discard the previous request */
  if (sock >= 0)
    CLOSE_INVALIDATE(sock);
  request_free(&req);

  /* Initialize the request */
  {
    uerr_t req_err;
    req = initialize_request(u, hs, dt, proxy, inhibit_keep_alive, &basic_auth_finished, &body_data_size, &user, &passwd, &req_err);
    if (!req) {
      retval = req_err;
      goto cleanup;
    }
  }

  /* Configure proxy headers and Proxy-Authorization if needed */
  proxyauth = NULL;
  if (proxy)
    initialize_proxy_configuration(u, req, proxy, &proxyauth);

  /* Initiate the connection */
  {
    uerr_t conn_err = establish_connection(u, &conn, proxy, &proxyauth, &req, &using_ssl, inhibit_keep_alive, &sock);
    if (conn_err != RETROK) {
      retval = conn_err;
      goto cleanup;
    }
  }

  /* We have a connection; if WARC is enabled, record the peer ip */
  if (warc_enabled) {
    if (socket_ip_address(sock, &warc_ip_buf, ENDPOINT_PEER))
      warc_ip = &warc_ip_buf;
  }

  /* Send the request */
  write_error = request_send(req, sock, warc_tmp);

  if (write_error < 0) {
    CLOSE_INVALIDATE(sock);

    if (warc_tmp != NULL)
      fclose(warc_tmp);

    retval = (write_error == -2) ? WARC_TMP_FWRITEERR : WRITEFAILED;
    goto cleanup;
  }

  logprintf(LOG_VERBOSE, _("%s request sent, awaiting response... "), proxy ? "Proxy" : "HTTP");
  contlen = -1;
  contrange = 0;
  *dt &= ~RETROKF;

  if (warc_enabled) {
    /* WARC request recording is not currently implemented for HTTP requests */
    /* The functionality to capture request bodies in warc_tmp is not yet available */
    /* This will be implemented when request body capture is added */
    DEBUGP(("WARC request recording skipped - not yet implemented\n"));
  }

  /* Repeat while we receive a 10x response code */
  {
    bool _repeat;

    do {
      head = read_http_response_head(sock);
      if (!head) {
        if (errno == 0) {
          logputs(LOG_NOTQUIET, _("No data received.\n"));
          CLOSE_INVALIDATE(sock);
          retval = HEOF;
        }
        else {
          logprintf(LOG_NOTQUIET, _("Read error (%s) in headers.\n"), fd_errstr(sock));
          CLOSE_INVALIDATE(sock);
          retval = HERR;
        }
        goto cleanup;
      }

      DEBUGP(("\n---response begin---\n%s---response end---\n", head));

      resp = resp_new(head);

      /* Check for status line */
      xfree(message);
      statcode = resp_status(resp, &message);
      if (statcode < 0) {
        char* tms = datetime_str(time(NULL));
        logprintf(LOG_VERBOSE, "%d\n", statcode);
        logprintf(LOG_NOTQUIET, _("%s ERROR %d: %s.\n"), tms, statcode, quotearg_style(escape_quoting_style, _("Malformed status line")));
        CLOSE_INVALIDATE(sock);
        retval = HERR;
        goto cleanup;
      }

      if (H_10X(statcode)) {
        xfree(head);
        resp_free(&resp);
        _repeat = true;
        DEBUGP(("Ignoring response\n"));
      }
      else {
        _repeat = false;
      }
    } while (_repeat);
  }

  xfree(hs->message);
  hs->message = xstrdup(message);

  if (!opt.server_response)
    logprintf(LOG_VERBOSE, "%2d %s\n", statcode, message ? quotearg_style(escape_quoting_style, message) : "");
  else {
    logprintf(LOG_VERBOSE, "\n");
    print_server_response(resp, "  ");
  }

  if (!opt.ignore_length && resp_header_copy(resp, "Content-Length", hdrval, sizeof(hdrval))) {
    wgint parsed;

    errno = 0;
    parsed = str_to_wgint(hdrval, NULL, 10);
    if (parsed == WGINT_MAX && errno == ERANGE) {
      /* Out of range; most likely >2G without LFS, so do not trust Content-Length */
      contlen = -1;
    }
    else if (parsed < 0) {
      /* Negative Content-Length makes no sense */
      contlen = -1;
    }
    else {
      contlen = parsed;
    }
  }

  /* Parse Content-Range so we know where the body starts when resuming */
  if (resp_header_copy(resp, "Content-Range", hdrval, sizeof(hdrval))) {
    const char* p = hdrval;

    while (c_isspace(*p))
      ++p;

    if (BEGINS_WITH(p, "bytes")) {
      p += 5;
      while (*p == ' ' || *p == '\t')
        ++p;

      if (*p == '*') {
        contrange = -1;
      }
      else {
        char* endptr = NULL;
        errno = 0;
        wgint start = str_to_wgint(p, &endptr, 10);
        if (errno == 0 && endptr != p && start >= 0)
          contrange = start;
        else
          contrange = -1;
      }
    }
  }

  /* Check for keep-alive related responses */
  if (!inhibit_keep_alive) {
    if (resp_header_copy(resp, "Connection", hdrval, sizeof(hdrval))) {
      if (0 == c_strcasecmp(hdrval, "Close"))
        keep_alive = false;
    }
  }

  chunked_transfer_encoding = false;
  if (resp_header_copy(resp, "Transfer-Encoding", hdrval, sizeof(hdrval)) && 0 == c_strcasecmp(hdrval, "chunked"))
    chunked_transfer_encoding = true;

  /* Handle (possibly multiple instances of) the Set-Cookie header */
  if (opt.cookies) {
    int scpos;
    const char *scbeg, *scend;

    /* The jar should have been created by now */
    assert(wget_cookie_jar != NULL);

    for (scpos = 0; (scpos = resp_header_locate(resp, "Set-Cookie", scpos, &scbeg, &scend)) != -1; ++scpos) {
      char buf_sc[1024];
      char* set_cookie;
      size_t len = (size_t)(scend - scbeg);

      if (len < sizeof(buf_sc))
        set_cookie = buf_sc;
      else
        set_cookie = xmalloc(len + 1);

      memcpy(set_cookie, scbeg, len);
      set_cookie[len] = '\0';

      cookie_handle_set_cookie(wget_cookie_jar, u->host, u->port, u->path, set_cookie);

      if (set_cookie != buf_sc)
        xfree(set_cookie);
    }
  }

  if (keep_alive)
    /* The server has promised that it will not close the connection
       when we're done. This means that we can register it */
    register_persistent(conn->host, conn->port, sock, using_ssl);

  if (statcode == HTTP_STATUS_UNAUTHORIZED) {
    /* Authorization is required */
    uerr_t auth_err = RETROK;
    bool retry;

    /* When WARC is enabled, we want the body; otherwise we can skip it when short */
    if (warc_enabled) {
      int _err;

      type = resp_header_strdup(resp, "Content-Type");
      _err = read_response_body(hs, sock, NULL, contlen, contrange, chunked_transfer_encoding, u->url, warc_timestamp_str, warc_request_uuid, warc_ip, type, statcode, head);
      xfree(type);
      type = NULL;

      if (_err != RETRFINISHED || hs->res < 0) {
        CLOSE_INVALIDATE(sock);
        retval = _err;
        goto cleanup;
      }

      CLOSE_FINISH(sock);
    }
    else {
      /* WARC disabled; try to skip body when possible */
      if (keep_alive && !head_only && skip_short_body(sock, contlen, chunked_transfer_encoding))
        CLOSE_FINISH(sock);
      else
        CLOSE_INVALIDATE(sock);
    }

    pconn.authorized = false;

    auth_err = check_auth(u, user, passwd, resp, req, &ntlm_seen, &retry, &basic_auth_finished, &auth_finished);
    if (auth_err == RETROK && retry) {
      resp_free(&resp);
      resp = NULL;
      xfree(message);
      message = NULL;
      xfree(head);
      head = NULL;
      goto retry_with_auth;
    }

    retval = (auth_err == RETROK) ? AUTHFAILED : auth_err;
    goto cleanup;
  }
  else {
    /* Kludge: if NTLM is used, mark the TCP connection as authorized */
    if (ntlm_seen)
      pconn.authorized = true;
  }

  {
    uerr_t ret = check_file_output(u, hs, resp, hdrval, sizeof hdrval);
    if (ret != RETROK) {
      retval = ret;
      goto cleanup;
    }
  }

  hs->statcode = statcode;
  xfree(hs->error);

  if (statcode == -1)
    hs->error = xstrdup(_("Malformed status line"));
  else if (!message || !*message)
    hs->error = xstrdup(_("(no description)"));
  else
    hs->error = xstrdup(message);

#ifdef HAVE_HSTS
  if (opt.hsts && hsts_store) {
    int64_t max_age;
    const char* hsts_params = resp_header_strdup(resp, "Strict-Transport-Security");
    bool include_subdomains;

    if (parse_strict_transport_security(hsts_params, &max_age, &include_subdomains)) {
      /* process strict transport security */
      if (hsts_store_entry(hsts_store, u->scheme, u->host, u->port, max_age, include_subdomains))
        DEBUGP(("Added new HSTS host: %s:%" PRIu32 " (max-age: %" PRId64 ", includeSubdomains: %s)\n", u->host, (uint32_t)u->port, max_age, include_subdomains ? "true" : "false"));
      else
        DEBUGP(("Updated HSTS host: %s:%" PRIu32 " (max-age: %" PRId64 ", includeSubdomains: %s)\n", u->host, (uint32_t)u->port, max_age, include_subdomains ? "true" : "false"));
    }

    xfree(hsts_params);
  }
#endif

  type = resp_header_strdup(resp, "Content-Type");
  if (type) {
    char* tmp = strchr(type, ';');
    if (tmp) {
#ifdef ENABLE_IRI
      char* tmp2 = tmp + 1;
#endif

      while (tmp > type && c_isspace(tmp[-1]))
        --tmp;
      *tmp = '\0';

#ifdef ENABLE_IRI
      /* Try to get remote encoding if needed */
      if (opt.enable_iri && !opt.encoding_remote) {
        tmp = parse_charset(tmp2);
        if (tmp)
          set_content_encoding(iri, tmp);
        xfree(tmp);
      }
#endif
    }
  }

  xfree(hs->newloc);
  hs->newloc = resp_header_strdup(resp, "Location");
  xfree(hs->remote_time);
  hs->remote_time = resp_header_strdup(resp, "Last-Modified");

  if (H_REDIRECTED(statcode) || statcode == HTTP_STATUS_MULTIPLE_CHOICES) {
    if (hs->newloc) {
      DEBUGP(("Redirect (%d) to %s\n", statcode, hs->newloc));
      keep_alive = false;     /* do not reuse redirect connections */
      CLOSE_INVALIDATE(sock); /* always close, no reuse */
      retval = NEWLOCATION;
      goto cleanup;
    }
    else {
      DEBUGP(("Redirect status %d but no Location header\n", statcode));
    }
  }

  set_content_type(dt, type);

  /* Handle 206 Partial Content */
  if (statcode == HTTP_STATUS_PARTIAL_CONTENTS) {
    if (!hs->restval)
      logputs(LOG_VERBOSE, _("Warning: 206 partial content, but REST not used\n"));
    else if (hs->restval != contrange) {
      if (opt.always_rest) {
        DEBUGP((_("DEBUG: Rest request ignored by server; will download from 0. hs->restval was %s, contrange=%s\n"), number_to_static_string(hs->restval), number_to_static_string(contrange)));
        /* Store the original restval for potential future use */
        hs->original_restval = hs->restval;
        /* The server did not start at our requested offset; treat as restart from 0 */
        hs->restval = 0;
        DEBUGP((_("DEBUG: After setting hs->restval to 0, original_restval=%s\n"), number_to_static_string(hs->original_restval)));
      }
      else if (contrange != -1) {
        logprintf(LOG_VERBOSE, _("Server requested starts at %s, but we asked for %s.\n"), number_to_static_string(contrange), number_to_static_string(hs->restval));
        retval = RANGEERR;
        goto cleanup;
      }
    }
  }
  else if (statcode == HTTP_STATUS_OK && hs->restval > 0) {
    /* The server completely ignored our Range request */
    if (opt.always_rest) {
      DEBUGP((_("DEBUG: Rest request ignored by server; will download from 0. hs->restval was %s\n"), number_to_static_string(hs->restval)));
      /* Store the original restval for skipping bytes later if we ever reuse this */
      hs->original_restval = hs->restval;
      hs->restval = 0;
      DEBUGP((_("DEBUG: After setting hs->restval to 0, original_restval=%s\n"), number_to_static_string(hs->original_restval)));
    }
    else {
      logprintf(LOG_VERBOSE, _("Server ignored the Range header.  We asked for %s.\n"), number_to_static_string(hs->restval));
      retval = RANGEERR;
      goto cleanup;
    }
  }

  /* Mark this transaction as having useful content when status is OKish */
  if (H_20X(statcode) || statcode == HTTP_STATUS_PARTIAL_CONTENTS)
    *dt |= RETROKF;
  else
    *dt &= ~RETROKF;

  if (opt.verbose) {
    if (hs->restval > 0) {
      logprintf(LOG_VERBOSE, _("Length: %s"), number_to_static_string(contlen + hs->restval));
      if (contlen != -1) {
        logprintf(LOG_VERBOSE, " (%s)", number_to_static_string(contlen));
        if (contlen + hs->restval >= 1024)
          logprintf(LOG_VERBOSE, " [%s]", human_readable(contlen + hs->restval, 10, 1));
      }
    }
    else {
      logprintf(LOG_VERBOSE, _("Length: %s"), contlen != -1 ? number_to_static_string(contlen) : _("unspecified"));
      if (contlen >= 1024)
        logprintf(LOG_VERBOSE, " [%s]", human_readable(contlen, 10, 1));
    }

    if (type) {
      if (c_strcasecmp(type, TEXTHTML_S) != 0 && c_strcasecmp(type, TEXTXHTML_S) != 0 && c_strcasecmp(type, TEXTCSS_S) != 0)
        logprintf(LOG_VERBOSE, " [%s]\n", quotearg_style(escape_quoting_style, type));
      else
        logputs(LOG_VERBOSE, "\n");
    }
  }

  /* Return if we have no intention of further downloading */
  if ((!(*dt & RETROKF) && !opt.content_on_error) || head_only || (opt.spider && !opt.recursive)) {
    /* In case the caller cares to look */
    hs->len = 0;
    hs->res = 0;
    hs->restval = 0;

    if (warc_enabled) {
      int _err = read_response_body(hs, sock, NULL, contlen, contrange, chunked_transfer_encoding, u->url, warc_timestamp_str, warc_request_uuid, warc_ip, type, statcode, head);

      if (_err != RETRFINISHED || hs->res < 0) {
        CLOSE_INVALIDATE(sock);
        retval = _err;
        goto cleanup;
      }

      CLOSE_FINISH(sock);
    }
    else {
      if (head_only) {
        /* Keep-alive is fine here; misbehaving servers can be handled with --no-http-keep-alive */
        CLOSE_FINISH(sock);
      }
      else if (opt.spider && !opt.recursive) {
        /* just existence check */
        CLOSE_INVALIDATE(sock);
      }
      else if (keep_alive && skip_short_body(sock, contlen, chunked_transfer_encoding)) {
        /* Successfully skipped the body and keep using the socket */
        CLOSE_FINISH(sock);
      }
      else {
        CLOSE_INVALIDATE(sock);
      }
    }

    if (statcode == HTTP_STATUS_GATEWAY_TIMEOUT)
      retval = GATEWAYTIMEOUT;
    else
      retval = RETRFINISHED;

    goto cleanup;
  }

  err = open_output_stream(hs, count, &fp);
  if (err != RETROK) {
    /* Preserve errno across SSL and fd_close actions */
    int tmp_errno = errno;
    CLOSE_INVALIDATE(sock);
    errno = tmp_errno;
    retval = err;
    goto cleanup;
  }

  DEBUGP((_("DEBUG: After open_output_stream, fp=%p, output_stream=%p\n"), (void*)fp, (void*)output_stream));

#ifdef ENABLE_XATTR
  if (opt.enable_xattr) {
    if (original_url != u)
      set_file_metadata(u, original_url, fp);
    else
      set_file_metadata(u, NULL, fp);
  }
#endif

  err = read_response_body(hs, sock, fp, contlen, contrange, chunked_transfer_encoding, u->url, warc_timestamp_str, warc_request_uuid, warc_ip, type, statcode, head);

  if (hs->res >= 0)
    CLOSE_FINISH(sock);
  else
    CLOSE_INVALIDATE(sock);

  if (!output_stream)
    fclose(fp);

  DEBUGP((_("DEBUG: Before cleanup, err=%d, hs->res=%d\n"), err, hs->res));

  retval = err;

cleanup:
  xfree(head);
  xfree(type);
  xfree(message);
  resp_free(&resp);
  request_free(&req);

  return retval;
}
