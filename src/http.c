/* HTTP support.
 * src/http.c
 */

#include "wget.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <locale.h>
#include <fcntl.h>

#include "hash.h"
#include "http.h"
#include "http_body.h"
#include "http_response.h"
#include "http_internal.h"
#include "http_auth.h"
#include "http_request.h"
#include "hsts.h"
#include "utils.h"
#include "url.h"
#include "host.h"
#include "retr.h"
#include "connect.h"
#include "netrc.h"
#ifdef HAVE_SSL
#include "ssl.h"
#endif
#ifdef ENABLE_NTLM
#include "http-ntlm.h"
#endif
#ifdef ENABLE_COOKIES
#include "cookies.h"
#endif
#include "md5.h"
#include "convert.h"
#include "spider.h"
#include "warc.h"
#include "c-strcase.h"
#include "c-strcasestr.h"
#include "version.h"
#include "xstrndup.h"
#ifdef ENABLE_XATTR
#include "xattr.h"
#endif
#include "http-header.h"
#include "http-pconn.h"
#include "http-pool.h"

#ifdef TESTING
#include "../tests/unit-tests.h"
#endif

/* Forward decls. */
static void ensure_extension(struct http_stat*, const char*, int*);
static uerr_t time_to_rfc1123(time_t time, char* buf, size_t bufsize);
static struct request* initialize_request(const struct url* u,
                                          struct http_stat* hs,
                                          int* dt,
                                          struct url* proxy,
                                          bool inhibit_keep_alive,
                                          bool* basic_auth_finished,
                                          wgint* body_data_size,
                                          char** user,
                                          char** passwd,
                                          uerr_t* ret);
static void initialize_proxy_configuration(const struct url* u, struct request* req, struct url* proxy, char** proxyauth);
static uerr_t establish_connection(const struct url* u,
                                   const struct url** conn_ref,
                                   struct http_stat* hs,
                                   struct url* proxy,
                                   char** proxyauth,
                                   struct request** req_ref,
                                   bool* using_ssl,
                                   bool inhibit_keep_alive,
                                   int* sock_ref);
static uerr_t set_file_timestamp(struct http_stat* hs);
static uerr_t check_file_output(const struct url* u, struct http_stat* hs, const struct http_response* resp, char* hdrval, size_t hdrsize);
static uerr_t
check_auth(const struct url* u, char* user, char* passwd, struct http_response* resp, struct request* req, bool* ntlm_seen_ref, bool* retry, bool* basic_auth_finished_ref, bool* auth_finished_ref);
static uerr_t open_output_stream(struct http_stat* hs, int count, FILE** fp);
static void set_content_type(int* dt, const char* type);
static bool skip_short_body(int fd, wgint contlen, bool chunked);
static bool parse_content_range(const char* hdr, wgint* first_byte_ptr, wgint* last_byte_ptr, wgint* entity_length_ptr);
static int body_file_send(int sock, const char* file_name, wgint promised_size, FILE* warc_tmp);

#ifdef HAVE_HSTS
static bool parse_strict_transport_security(const char* header, int64_t* max_age, bool* include_subdomains);
#endif

#define TEXTHTML_S "text/html"
#define TEXTXHTML_S "application/xhtml+xml"
#define TEXTCSS_S "text/css"
#define TEXTXML_S "text/xml"
#define APPXML_S "application/xml"

/* Some status code validation macros: */
#define H_10X(x) (((x) >= 100) && ((x) < 200))
#define H_20X(x) (((x) >= 200) && ((x) < 300))
#define H_PARTIAL(x) ((x) == HTTP_STATUS_PARTIAL_CONTENTS)
#define H_REDIRECTED(x) \
  ((x) == HTTP_STATUS_MOVED_PERMANENTLY || (x) == HTTP_STATUS_MOVED_TEMPORARILY || (x) == HTTP_STATUS_SEE_OTHER || (x) == HTTP_STATUS_TEMPORARY_REDIRECT || (x) == HTTP_STATUS_PERMANENT_REDIRECT)

/* HTTP/1.0 status codes from RFC1945, provided for reference.  */
/* Successful 2xx.  */
#define HTTP_STATUS_OK 200
#define HTTP_STATUS_CREATED 201
#define HTTP_STATUS_ACCEPTED 202
#define HTTP_STATUS_NO_CONTENT 204
#define HTTP_STATUS_PARTIAL_CONTENTS 206

/* Redirection 3xx.  */
#define HTTP_STATUS_MULTIPLE_CHOICES 300
#define HTTP_STATUS_MOVED_PERMANENTLY 301
#define HTTP_STATUS_MOVED_TEMPORARILY 302
#define HTTP_STATUS_SEE_OTHER 303 /* from HTTP/1.1 */
#define HTTP_STATUS_NOT_MODIFIED 304
#define HTTP_STATUS_TEMPORARY_REDIRECT 307 /* from HTTP/1.1 */
#define HTTP_STATUS_PERMANENT_REDIRECT 308 /* from HTTP/1.1 */

/* Client error 4xx.  */
#define HTTP_STATUS_BAD_REQUEST 400
#define HTTP_STATUS_UNAUTHORIZED 401
#define HTTP_STATUS_FORBIDDEN 403
#define HTTP_STATUS_NOT_FOUND 404
#define HTTP_STATUS_RANGE_NOT_SATISFIABLE 416

/* Server errors 5xx.  */
#define HTTP_STATUS_INTERNAL 500
#define HTTP_STATUS_NOT_IMPLEMENTED 501
#define HTTP_STATUS_BAD_GATEWAY 502
#define HTTP_STATUS_UNAVAILABLE 503
#define HTTP_STATUS_GATEWAY_TIMEOUT 504

/* The idea behind these two CLOSE macros is to distinguish between
   two cases: one when the job we've been doing is finished, and we
   want to close the connection and leave, and two when something is
   seriously wrong and we're closing the connection as part of
   cleanup.

   In case of keep_alive, CLOSE_FINISH should leave the connection
   open, while CLOSE_INVALIDATE should still close it.

   Note that the semantics of the flag `keep_alive' is "this
   connection *will* be reused (the server has promised not to close
   the connection once we're done)", while the semantics of
   `pc_active_p && (fd) == pc_last_fd' is "we're *now* using an
   active, registered connection".  */

#define CLOSE_FINISH(ctx)                                                                            \
  do {                                                                                               \
    if (!(ctx)->keep_alive) {                                                                        \
      if (pconn_active && (ctx)->sock == pconn.socket)                                               \
        invalidate_persistent();                                                                     \
      else                                                                                           \
        pool_return_connection((ctx)->sock, (ctx)->conn->host, (ctx)->conn->port, (ctx)->using_ssl); \
      (ctx)->sock = -1;                                                                              \
    }                                                                                                \
  } while (0)

#define CLOSE_INVALIDATE(ctx)                        \
  do {                                               \
    if (pconn_active && (ctx)->sock == pconn.socket) \
      invalidate_persistent();                       \
    else                                             \
      pool_invalidate_connection((ctx)->sock);       \
    (ctx)->sock = -1;                                \
  } while (0)

#define BEGINS_WITH(line, string_constant) (!c_strncasecmp(line, string_constant, sizeof(string_constant) - 1) && (c_isspace(line[sizeof(string_constant) - 1]) || !line[sizeof(string_constant) - 1]))

#define SET_USER_AGENT(req)                                                                 \
  do {                                                                                      \
    if (!opt.useragent)                                                                     \
      request_set_header(req, "User-Agent", aprintf("Wget/%s", version_string), rel_value); \
    else if (*opt.useragent)                                                                \
      request_set_header(req, "User-Agent", opt.useragent, rel_none);                       \
  } while (0)

static void http_get_body_done_cb(struct http_stat* hs, int status, wgint qtyread, wgint qtywritten, double elapsed) {
  struct http_transaction_ctx* ctx = (struct http_transaction_ctx*)hs->user_data;
  assert(ctx != NULL);

  hs->res = status;
  hs->rd_size += qtyread;
  hs->len += qtywritten;
  hs->dltime += elapsed;

  // Cleanup warc related fields in http_stat
  xfree(hs->url);
  xfree(hs->warc_timestamp_str);
  xfree(hs->warc_request_uuid);
  xfree(hs->type);
  xfree(hs->head);
  hs->url = NULL;
  hs->warc_timestamp_str = NULL;
  hs->warc_request_uuid = NULL;
  hs->type = NULL;
  hs->head = NULL;

  // Decide next state based on the result of the body download
  if (status >= 0) {
    if (ctx->state == HLS_READ_BODY_UNAUTHORIZED || ctx->state == HLS_READ_BODY_REDIRECTED || ctx->state == HLS_READ_BODY_ERROR) {
      CLOSE_FINISH(ctx);
      ctx->retval = RETRFINISHED;  // Body read for WARC completed, now proceed to cleanup or retry
      ctx->state = HLS_COMPLETED;
    }
    else if (ctx->state == HLS_READ_BODY_MAIN) {
      CLOSE_FINISH(ctx);
      ctx->retval = RETRFINISHED;
      ctx->state = HLS_COMPLETED;
    }
  }
  else {
    // An error occurred during body download
    CLOSE_INVALIDATE(ctx);
    if (hs->res == -2)
      ctx->retval = FWRITEERR;
    else if (hs->res == -3)
      ctx->retval = WARC_TMP_FWRITEERR;
    else {
      xfree(hs->rderrmsg);
      hs->rderrmsg = xstrdup(fd_errstr(ctx->sock));
      ctx->retval = RETRFINISHED;  // Indicate failure to body download
    }
    ctx->state = HLS_FAILED;
  }
  http_loop_continue_async(ctx, ctx->retval);
}

static void http_loop_cleanup_impl(struct http_transaction_ctx* ctx) {
  if (!ctx)
    return;

  xfree(ctx->type);
  xfree(ctx->message);
  http_response_free(&ctx->resp);
  request_free(&ctx->req);

  // Free WARC-related fields in http_stat if they were strdup'd
  xfree(ctx->hstat.url);
  xfree(ctx->hstat.warc_timestamp_str);
  xfree(ctx->hstat.warc_request_uuid);
  xfree(ctx->hstat.type);
  xfree(ctx->hstat.head);
  xfree(ctx->hstat.local_file);
  xfree(ctx->hstat.orig_file_name);
  xfree(ctx->hstat.newloc);
  xfree(ctx->hstat.remote_time);
  xfree(ctx->hstat.error);
  xfree(ctx->hstat.message);
  xfree(ctx->hstat.rderrmsg);

  xfree(ctx);
}

static void get_file_flags(const char* filename, int* dt) {
  (void)filename;
  (void)dt;
}

struct http_transaction_ctx* http_loop_start_async(const struct url* u,
                                                   struct url* original_url,
                                                   char** newloc,
                                                   char** local_file,
                                                   const char* referer,
                                                   int* dt,
                                                   struct url* proxy,
                                                   struct iri* iri,
                                                   struct transfer_context* tctx,
                                                   void (*final_cb)(struct http_transaction_ctx* ctx, uerr_t status)) {
  struct http_transaction_ctx* ctx = xcalloc(1, sizeof(struct http_transaction_ctx));
  if (!ctx)
    return NULL;

  ctx->u = u;
  ctx->original_url = original_url;
  ctx->newloc = newloc;
  ctx->local_file = local_file;
  ctx->referer = referer;
  ctx->dt = dt;
  ctx->proxy = proxy;
  ctx->iri = iri;
  ctx->tctx = tctx;
  ctx->final_cb = final_cb;

  // Initialize http_stat struct.
  xzero(ctx->hstat);
  ctx->hstat.referer = referer;
  // Initialize http_stat's user_data to point to this context, so http_body_done_cb can find it
  ctx->hstat.user_data = ctx;

  // Initialize WARC-related fields in http_stat
  ctx->hstat.url = xstrdup(u->url);

  ctx->sock = -1;
  ctx->warc_enabled = (opt.warc_filename != NULL);
  ctx->keep_alive = true;
  ctx->inhibit_keep_alive = !opt.http_keep_alive || opt.ignore_length;
  ctx->head_only = !!(*ctx->dt & HEAD_ONLY);
  ctx->cond_get = !!(*ctx->dt & IF_MODIFIED_SINCE);

  // Set initial state and call continue to start processing
  ctx->state = HLS_INIT;
  http_loop_continue_async(ctx, RETROK);  // Start the state machine

  return ctx;
}

void http_loop_continue_async(struct http_transaction_ctx* ctx, uerr_t prev_op_status) {
  // If a previous operation failed, transition to HLS_FAILED state
  if (prev_op_status != RETROK) {
    ctx->retval = prev_op_status;
    ctx->state = HLS_FAILED;
  }

  while (ctx->state != HLS_COMPLETED && ctx->state != HLS_FAILED) {
    switch (ctx->state) {
      case HLS_INIT: {
        // This is equivalent to the initial part of http_loop and gethttp
        // Logic from http_loop - initial setup
        if (opt.output_document) {
          ctx->hstat.local_file = xstrdup(opt.output_document);
        }
        else if (!opt.content_disposition) {
          ctx->hstat.local_file = url_file_name(opt.trustservernames ? ctx->u : ctx->original_url, NULL);
        }

        // Handle existing file / noclobber
        if (ctx->hstat.local_file && file_exists_p(ctx->hstat.local_file, NULL) && opt.noclobber && !opt.output_document) {
          get_file_flags(ctx->hstat.local_file, ctx->dt);
          ctx->retval = RETROK;
          ctx->state = HLS_COMPLETED;
          break;  // Exit switch and loop
        }

        // Initialize WARC timestamp and UUID
        if (ctx->warc_enabled) {
          warc_timestamp(ctx->hstat.warc_timestamp_str, sizeof(ctx->hstat.warc_timestamp_str));
          warc_uuid_str(ctx->hstat.warc_request_uuid, sizeof(ctx->hstat.warc_request_uuid));
        }

#ifdef HAVE_SSL
        if (ctx->u->scheme == SCHEME_HTTPS) {
          if (!ssl_init()) {
            scheme_disable(SCHEME_HTTPS);
            logprintf(LOG_NOTQUIET, _("Disabling SSL due to encountered errors.\n"));
            ctx->retval = SSLINITFAILED;
            ctx->state = HLS_FAILED;
            break;
          }
        }
#endif
        // Prepare request
        uerr_t ret_req_init;
        ctx->req = initialize_request(ctx->u, &ctx->hstat, ctx->dt, ctx->proxy, ctx->inhibit_keep_alive, &ctx->auth_finished, &ctx->body_data_size, &ctx->user, &ctx->passwd, &ret_req_init);
        if (ctx->req == NULL) {
          ctx->retval = ret_req_init;
          ctx->state = HLS_FAILED;
          break;
        }

        // Setup proxy configuration if needed
        if (ctx->proxy) {
          ctx->conn = ctx->proxy;
          initialize_proxy_configuration(ctx->u, ctx->req, ctx->proxy, &ctx->proxyauth);
        }
        else {
          ctx->conn = ctx->u;
        }

        ctx->state = HLS_ESTABLISH_CONNECTION;
        // Fall through to next state immediately
        __attribute__((fallthrough));
      }

      case HLS_ESTABLISH_CONNECTION: {
        // Logic from gethttp - establish connection
        uerr_t conn_err = establish_connection(ctx->u, &ctx->conn, &ctx->hstat, ctx->proxy, &ctx->proxyauth, &ctx->req, &ctx->using_ssl, ctx->inhibit_keep_alive, &ctx->sock);
        if (conn_err != RETROK) {
          ctx->retval = conn_err;
          ctx->state = HLS_FAILED;
          break;
        }

        ctx->state = HLS_SEND_REQUEST;
        // Fall through to next state immediately
        __attribute__((fallthrough));
      }

      case HLS_SEND_REQUEST: {
        // Logic from gethttp - send request
        if (ctx->warc_enabled) {
          ctx->warc_tmp = warc_tempfile();
          if (ctx->warc_tmp == NULL) {
            CLOSE_INVALIDATE(ctx);
            ctx->retval = WARC_TMP_FOPENERR;
            ctx->state = HLS_FAILED;
            break;
          }
          if (!ctx->proxy) {
            ctx->warc_ip = &ctx->warc_ip_buf;
            socket_ip_address(ctx->sock, ctx->warc_ip, ENDPOINT_PEER);
          }
        }

        ctx->write_error = request_send(ctx->req, ctx->sock, ctx->warc_tmp);

        if (ctx->write_error >= 0) {
          if (opt.body_data) {
            DEBUGP(("[BODY data: %s]\n", opt.body_data));
            ctx->write_error = fd_write(ctx->sock, opt.body_data, ctx->body_data_size, -1);
            if (ctx->write_error >= 0 && ctx->warc_tmp != NULL) {
              /* Remember end of headers / start of payload. */
              ctx->warc_payload_offset = ftello(ctx->warc_tmp);
              int warc_tmp_written = fwrite(opt.body_data, 1, ctx->body_data_size, ctx->warc_tmp);
              if (warc_tmp_written != ctx->body_data_size)
                ctx->write_error = -2;
            }
          }
          else if (opt.body_file && ctx->body_data_size != 0) {
            if (ctx->warc_tmp != NULL)
              ctx->warc_payload_offset = ftello(ctx->warc_tmp);
            ctx->write_error = body_file_send(ctx->sock, opt.body_file, ctx->body_data_size, ctx->warc_tmp);
          }
        }

        if (ctx->write_error < 0) {
          CLOSE_INVALIDATE(ctx);
          if (ctx->warc_tmp != NULL)
            fclose(ctx->warc_tmp);
          ctx->retval = (ctx->write_error == -2) ? WARC_TMP_FWRITEERR : WRITEFAILED;
          ctx->state = HLS_FAILED;
          break;
        }
        logprintf(LOG_VERBOSE, _("%s request sent, awaiting response... "), ctx->proxy ? "Proxy" : "HTTP");
        ctx->contlen = -1;
        ctx->contrange = 0;
        *ctx->dt &= ~RETROKF;

        // WARC request record
        if (ctx->warc_enabled) {
          bool warc_result = warc_write_request_record(ctx->u->url, ctx->hstat.warc_timestamp_str, ctx->hstat.warc_request_uuid, ctx->warc_ip, ctx->warc_tmp, ctx->warc_payload_offset);
          if (!warc_result) {
            CLOSE_INVALIDATE(ctx);
            ctx->retval = WARC_ERR;
            ctx->state = HLS_FAILED;
            break;
          }
          // warc_write_request_record has also closed warc_tmp.
          ctx->warc_tmp = NULL;
        }

        ctx->state = HLS_READ_RESPONSE_HEADERS;
        // Fall through to next state immediately
        __attribute__((fallthrough));
      }

      case HLS_READ_RESPONSE_HEADERS: {
        // Logic from gethttp - read response headers
        bool _repeat_10x;
        do {
          _repeat_10x = false;
          ctx->head = http_response_read_head(ctx->sock);
          if (!ctx->head) {
            if (errno == 0) {
              logputs(LOG_NOTQUIET, _("No data received.\n"));
              CLOSE_INVALIDATE(ctx);
              ctx->retval = HEOF;
            }
            else {
              logprintf(LOG_NOTQUIET, _("Read error (%s) in headers.\n"), fd_errstr(ctx->sock));
              CLOSE_INVALIDATE(ctx);
              ctx->retval = HERR;
            }
            ctx->state = HLS_FAILED;
            break;  // Break from do-while and switch
          }
          DEBUGP(("\n---response begin---\n%s---response end---\n", ctx->head));

          ctx->resp = http_response_parse(ctx->head);
          xfree(ctx->message);
          ctx->statcode = http_response_status(ctx->resp, &ctx->message);
          if (ctx->statcode < 0) {
            char* tms = datetime_str(time(NULL));
            logprintf(LOG_VERBOSE, "%d\n", ctx->statcode);
            logprintf(LOG_NOTQUIET, _("%s ERROR %d: %s.\n"), tms, ctx->statcode, quotearg_style(escape_quoting_style, _("Malformed status line")));
            CLOSE_INVALIDATE(ctx);
            ctx->retval = HERR;
            http_response_free(&ctx->resp);
            ctx->state = HLS_FAILED;
            break;  // Break from do-while and switch
          }

          if (H_10X(ctx->statcode)) {
            http_response_free(&ctx->resp);
            ctx->resp = NULL;
            _repeat_10x = true;
            DEBUGP(("Ignoring response\n"));
            xfree(ctx->head);
            ctx->head = NULL;
            xfree(ctx->message);
            ctx->message = NULL;
          }
        } while (_repeat_10x);

        if (ctx->state == HLS_FAILED)
          break;  // If an error occurred in the do-while, propagate it.

        http_stat_set_message(&ctx->hstat, ctx->message);
        if (!opt.server_response)
          logprintf(LOG_VERBOSE, "%2d %s\n", ctx->statcode, ctx->message ? quotearg_style(escape_quoting_style, ctx->message) : "");
        else {
          logprintf(LOG_VERBOSE, "\n");
          http_response_print(ctx->resp, "  ");
        }

        // Update hstat's statcode and head for potential WARC record creation
        ctx->hstat.statcode = ctx->statcode;
        ctx->hstat.head = xstrdup(ctx->head);

        if (!opt.ignore_length && http_response_header_copy(ctx->resp, "Content-Length", ctx->hdrval, sizeof(ctx->hdrval))) {
          wgint parsed;
          errno = 0;
          parsed = str_to_wgint(ctx->hdrval, NULL, 10);
          if (parsed == WGINT_MAX && errno == ERANGE)
            ctx->contlen = -1;
          else if (parsed < 0)
            ctx->contlen = -1;
          else
            ctx->contlen = parsed;
        }

        if (!ctx->inhibit_keep_alive) {
          if (http_response_header_copy(ctx->resp, "Connection", ctx->hdrval, sizeof(ctx->hdrval))) {
            if (0 == c_strcasecmp(ctx->hdrval, "Close"))
              ctx->keep_alive = false;
          }
        }

        ctx->chunked_transfer_encoding = false;
        if (http_response_header_copy(ctx->resp, "Transfer-Encoding", ctx->hdrval, sizeof(ctx->hdrval)) && 0 == c_strcasecmp(ctx->hdrval, "chunked"))
          ctx->chunked_transfer_encoding = true;

#ifdef ENABLE_COOKIES
        if (opt.cookies) {
          int scpos;
          const char *scbeg, *scend;
          for (scpos = 0; (scpos = http_response_header_locate(ctx->resp, "Set-Cookie", scpos, &scbeg, &scend)) != -1; ++scpos) {
            char buf[1024], *set_cookie;
            size_t len = scend - scbeg;

            if (len < sizeof(buf))
              set_cookie = buf;
            else
              set_cookie = xmalloc(len + 1);

            memcpy(set_cookie, scbeg, len);
            set_cookie[len] = 0;

            cookie_handle_set_cookie(ctx->u->host, ctx->u->port, ctx->u->path, set_cookie);

            if (set_cookie != buf)
              xfree(set_cookie);
          }
        }
#endif

        if (ctx->keep_alive)
          pool_register_connection(ctx->conn->host, ctx->conn->port, ctx->sock, ctx->using_ssl);

        // Check for UNAUTHORIZED, REDIRECTED, NO_CONTENT, RANGE_NOT_SATISFIABLE conditions
        if (ctx->statcode == HTTP_STATUS_UNAUTHORIZED) {
          ctx->hstat.type = http_response_header_strdup(ctx->resp, "Content-Type");
          ctx->state = HLS_READ_BODY_UNAUTHORIZED;
          goto read_body_async;  // Jump to async body read
        }
        else if (H_REDIRECTED(ctx->statcode) || ctx->statcode == HTTP_STATUS_MULTIPLE_CHOICES) {
          if (ctx->statcode == HTTP_STATUS_MULTIPLE_CHOICES && !ctx->hstat.newloc)
            *ctx->dt |= RETROKF;
          else {
            logprintf(LOG_VERBOSE, _("Location: %s%s\n"), ctx->hstat.newloc ? escnonprint_uri(ctx->hstat.newloc) : _("unspecified"), ctx->hstat.newloc ? _(" [following]") : "");
            ctx->hstat.len = 0;
            ctx->hstat.res = 0;
            ctx->hstat.restval = 0;
            ctx->hstat.type = http_response_header_strdup(ctx->resp, "Content-Type");
            ctx->state = HLS_READ_BODY_REDIRECTED;
            goto read_body_async;  // Jump to async body read
          }
        }
        else if (ctx->statcode == HTTP_STATUS_NO_CONTENT) {
          ctx->hstat.len = 0;
          ctx->hstat.res = 0;
          ctx->hstat.restval = 0;
          CLOSE_FINISH(ctx);
          ctx->retval = RETRFINISHED;
          ctx->state = HLS_COMPLETED;
          break;
        }
        else if (ctx->statcode == HTTP_STATUS_RANGE_NOT_SATISFIABLE ||
                 (!opt.timestamping && ctx->hstat.restval > 0 && ctx->statcode == HTTP_STATUS_OK && ctx->contrange == 0 && ctx->contlen >= 0 && ctx->hstat.restval >= ctx->contlen)) {
          logputs(LOG_VERBOSE, _("\n    The file is already fully retrieved; nothing to do.\n\n"));
          ctx->hstat.len = ctx->contlen;
          ctx->hstat.res = 0;
          *ctx->dt |= RETROKF;
          if (ctx->keep_alive && skip_short_body(ctx->sock, ctx->contlen, ctx->chunked_transfer_encoding))
            CLOSE_FINISH(ctx);
          else
            CLOSE_INVALIDATE(ctx);
          ctx->retval = RETRUNNEEDED;
          ctx->state = HLS_COMPLETED;
          break;
        }
        else if ((ctx->contrange != 0 && ctx->contrange != ctx->hstat.restval) || (H_PARTIAL(ctx->statcode) && !ctx->contrange && ctx->hstat.restval)) {
          CLOSE_INVALIDATE(ctx);
          ctx->retval = RANGEERR;
          ctx->state = HLS_FAILED;
          break;
        }

        ctx->state = HLS_READ_BODY_MAIN;
        // Fall through to main body reading or opening output stream
        __attribute__((fallthrough));
      }

      case HLS_READ_BODY_UNAUTHORIZED:
      case HLS_READ_BODY_REDIRECTED:
      case HLS_READ_BODY_ERROR:
      case HLS_READ_BODY_MAIN:
        // All body reading states fall through to the async body handling

      read_body_async:
        // This is the point where an async http_body_download call would be initiated
        // and we would return, waiting for the callback to call http_loop_continue_async again.
        {
          if ((ctx->state == HLS_READ_BODY_UNAUTHORIZED && ctx->warc_enabled) || (ctx->state == HLS_READ_BODY_REDIRECTED && ctx->warc_enabled) ||
              (ctx->state == HLS_READ_BODY_ERROR && ctx->warc_enabled) ||
              (ctx->state == HLS_READ_BODY_MAIN && ((!(*ctx->dt & RETROKF) && !opt.content_on_error) || ctx->head_only || (opt.spider && !opt.recursive)))) {
            // These are cases where we are interested in the body for WARC, or skipping it
            // This path will lead to a call to http_body_download (async)
          }
          else if (ctx->state == HLS_READ_BODY_UNAUTHORIZED || ctx->state == HLS_READ_BODY_REDIRECTED || ctx->state == HLS_READ_BODY_ERROR) {
            // If WARC is disabled, and we are in one of these states, we don't need to read the body
            if (ctx->keep_alive && !ctx->head_only && skip_short_body(ctx->sock, ctx->contlen, ctx->chunked_transfer_encoding))
              CLOSE_FINISH(ctx);
            else
              CLOSE_INVALIDATE(ctx);
            if (ctx->statcode == HTTP_STATUS_UNAUTHORIZED) {
              // Handle authentication retry
              bool retry;
              uerr_t auth_err = check_auth(ctx->u, ctx->user, ctx->passwd, ctx->resp, ctx->req, &ctx->ntlm_seen, &retry, &ctx->basic_auth_finished, &ctx->auth_finished);
              if (auth_err == RETROK && retry) {
                http_response_free(&ctx->resp);
                ctx->resp = NULL;
                xfree(ctx->message);
                ctx->message = NULL;
                // Need to re-initialize request if needed here for retry, then jump to HLS_ESTABLISH_CONNECTION
                // For now, simplify and just fail if auth fails
                ctx->retval = RETROK;                   // Set to RETROK to allow loop to proceed to retry if set by check_auth
                ctx->state = HLS_ESTABLISH_CONNECTION;  // Go back to re-establish connection
                break;                                  // Break from switch to allow loop to continue
              }
              else {
                ctx->retval = (auth_err == RETROK) ? AUTHFAILED : auth_err;
                ctx->state = HLS_FAILED;
                break;
              }
            }
            else if (H_REDIRECTED(ctx->statcode) || ctx->statcode == HTTP_STATUS_MULTIPLE_CHOICES) {
              switch (ctx->statcode) {
                case HTTP_STATUS_TEMPORARY_REDIRECT:
                case HTTP_STATUS_PERMANENT_REDIRECT:
                  ctx->retval = NEWLOCATION_KEEP_POST;
                  break;
                case HTTP_STATUS_MOVED_PERMANENTLY:
                  if (opt.method && c_strcasecmp(opt.method, "post") != 0) {
                    ctx->retval = NEWLOCATION_KEEP_POST;
                    break;
                  }
                  __attribute__((fallthrough));
                case HTTP_STATUS_MOVED_TEMPORARILY:
                  if (opt.method && c_strcasecmp(opt.method, "post") != 0) {
                    ctx->retval = NEWLOCATION_KEEP_POST;
                    break;
                  }
                  __attribute__((fallthrough));
                default:
                  ctx->retval = NEWLOCATION;
                  break;
              }
              ctx->state = HLS_COMPLETED;
              break;
            }
            else {
              // Error response without WARC and no body to skip
              if (ctx->statcode == HTTP_STATUS_GATEWAY_TIMEOUT)
                ctx->retval = GATEWAYTIMEOUT;
              else
                ctx->retval = RETRFINISHED;
              ctx->state = HLS_COMPLETED;
              break;
            }
          }
          else if (((!(*ctx->dt & RETROKF) && !opt.content_on_error) || ctx->head_only || (opt.spider && !opt.recursive)) && !ctx->warc_enabled) {
            if (ctx->head_only)
              CLOSE_FINISH(ctx);
            else if (opt.spider && !opt.recursive)
              CLOSE_INVALIDATE(ctx);
            else if (ctx->keep_alive && skip_short_body(ctx->sock, ctx->contlen, ctx->chunked_transfer_encoding))
              CLOSE_FINISH(ctx);
            else
              CLOSE_INVALIDATE(ctx);

            if (ctx->statcode == HTTP_STATUS_GATEWAY_TIMEOUT)
              ctx->retval = GATEWAYTIMEOUT;
            else
              ctx->retval = RETRFINISHED;
            ctx->state = HLS_COMPLETED;
            break;
          }

          // Common part for body download or opening output stream for main download
          // This is the actual main download path
          uerr_t ret = check_file_output(ctx->u, &ctx->hstat, ctx->resp, ctx->hdrval, sizeof ctx->hdrval);
          if (ret != RETROK) {
            ctx->retval = ret;
            ctx->state = HLS_FAILED;
            break;
          }

          http_stat_record_status(&ctx->hstat, ctx->statcode, ctx->message);

#ifdef HAVE_HSTS
          if (opt.hsts && hsts_store) {
            int64_t max_age;
            const char* hsts_params = http_response_header_strdup(ctx->resp, "Strict-Transport-Security");
            bool include_subdomains;

            if (parse_strict_transport_security(hsts_params, &max_age, &include_subdomains)) {
              if (hsts_store_entry(hsts_store, ctx->u->scheme, ctx->u->host, ctx->u->port, max_age, include_subdomains))
                DEBUGP(("Added new HSTS host: %s:%" PRIu32 " (max-age: %" PRId64 ", includeSubdomains: %s)\n", ctx->u->host, (uint32_t)ctx->u->port, max_age, (include_subdomains ? "true" : "false")));
              else
                DEBUGP(("Updated HSTS host: %s:%" PRIu32 " (max-age: %" PRId64 ", includeSubdomains: %s)\n", ctx->u->host, (uint32_t)ctx->u->port, max_age, (include_subdomains ? "true" : "false")));
            }
            xfree(hsts_params);
          }
#endif

          ctx->hstat.type = http_response_header_strdup(ctx->resp, "Content-Type");
          if (ctx->hstat.type) {
            char* tmp = strchr(ctx->hstat.type, ';');
            if (tmp) {
#ifdef ENABLE_IRI
              char* tmp2 = tmp + 1;
#endif
              while (tmp > ctx->hstat.type && c_isspace(tmp[-1]))
                --tmp;
              *tmp = '\0';
#ifdef ENABLE_IRI
              if (opt.enable_iri && !opt.encoding_remote) {
                tmp = parse_charset(tmp2);
                if (tmp)
                  set_content_encoding(ctx->iri, tmp);
                xfree(tmp);
              }
#endif
            }
          }
          http_stat_capture_headers(&ctx->hstat, ctx->resp, ctx->u, ctx->hstat.type, ctx->hdrval, sizeof(ctx->hdrval));

          if (http_response_header_copy(ctx->resp, "Content-Range", ctx->hdrval, sizeof(ctx->hdrval))) {
            wgint first_byte_pos, last_byte_pos, entity_length;
            if (parse_content_range(ctx->hdrval, &first_byte_pos, &last_byte_pos, &entity_length)) {
              ctx->contrange = first_byte_pos;
              ctx->contlen = last_byte_pos - first_byte_pos + 1;
            }
          }
          if (H_20X(ctx->statcode))
            *ctx->dt |= RETROKF;

          set_content_type(ctx->dt, ctx->hstat.type);

          if (opt.adjust_extension) {
            const char* encoding_ext = NULL;
            switch (ctx->hstat.local_encoding) {
              case ENC_INVALID:
              case ENC_NONE:
                break;
              case ENC_BROTLI:
                encoding_ext = ".br";
                break;
              case ENC_COMPRESS:
                encoding_ext = ".Z";
                break;
              case ENC_DEFLATE:
                encoding_ext = ".zlib";
                break;
              case ENC_GZIP:
                encoding_ext = ".gz";
                break;
              default:
                DEBUGP(("No extension found for encoding %d\n", ctx->hstat.local_encoding));
            }
            if (encoding_ext != NULL) {
              char* file_ext = strrchr(ctx->hstat.local_file, '.');
              if (file_ext != NULL && 0 == strcasecmp(file_ext, encoding_ext))
                *file_ext = '\0';
            }
            if (*ctx->dt & TEXTHTML)
              ensure_extension(&ctx->hstat, ".html", ctx->dt);
            else if (*ctx->dt & TEXTCSS)
              ensure_extension(&ctx->hstat, ".css", ctx->dt);
            if (encoding_ext != NULL)
              ensure_extension(&ctx->hstat, encoding_ext, ctx->dt);
          }

          if (ctx->cond_get) {
            if (ctx->statcode == HTTP_STATUS_OK && ctx->hstat.remote_time) {
              time_t tmr = http_atotm(ctx->hstat.remote_time);
              if (tmr != (time_t)-1 && tmr <= ctx->hstat.orig_file_tstamp && (ctx->contlen == -1 || ctx->contlen == ctx->hstat.orig_file_size)) {
                logprintf(LOG_VERBOSE,
                          _("Server ignored If-Modified-Since header for file %s.\n"
                            "You might want to add --no-if-modified-since option.\n\n"),
                          quote(ctx->hstat.local_file));
                *ctx->dt |= RETROKF;
                CLOSE_INVALIDATE(ctx);
                ctx->retval = RETRUNNEEDED;
                ctx->state = HLS_COMPLETED;
                break;
              }
            }
          }

          if (ctx->contlen == -1)
            ctx->hstat.contlen = -1;
          else if (ctx->hstat.remote_encoding == ENC_GZIP)
            ctx->hstat.contlen = -1;
          else
            ctx->hstat.contlen = ctx->contlen + ctx->contrange;

          if (opt.verbose) {
            if (*ctx->dt & RETROKF) {
              logputs(LOG_VERBOSE, _("Length: "));
              if (ctx->contlen != -1) {
                logputs(LOG_VERBOSE, number_to_static_string(ctx->contlen + ctx->contrange));
                if (ctx->contlen + ctx->contrange >= 1024)
                  logprintf(LOG_VERBOSE, " (%s)", human_readable(ctx->contlen + ctx->contrange, 10, 1));
                if (ctx->contrange) {
                  if (ctx->contlen >= 1024)
                    logprintf(LOG_VERBOSE, _(", %s (%s) remaining"), number_to_static_string(ctx->contlen), human_readable(ctx->contlen, 10, 1));
                  else
                    logprintf(LOG_VERBOSE, _(", %s remaining"), number_to_static_string(ctx->contlen));
                }
              }
              else
                logputs(LOG_VERBOSE, opt.ignore_length ? _("ignored") : _("unspecified"));
              if (ctx->hstat.type)
                logprintf(LOG_VERBOSE, " [%s]\n", quotearg_style(escape_quoting_style, ctx->hstat.type));
              else
                logputs(LOG_VERBOSE, "\n");
            }
          }

          ctx->err = open_output_stream(&ctx->hstat, ctx->count, &ctx->fp);
          if (ctx->err != RETROK) {
            int tmp_errno = errno;
            CLOSE_INVALIDATE(ctx);
            errno = tmp_errno;
            ctx->retval = ctx->err;
            ctx->state = HLS_FAILED;
            break;
          }

#ifdef ENABLE_XATTR
          if (opt.enable_xattr) {
            if (ctx->original_url != ctx->u)
              set_file_metadata(ctx->u, ctx->original_url, ctx->fp);
            else
              set_file_metadata(ctx->u, NULL, ctx->fp);
          }
#endif

          // Start asynchronous body download
          http_body_download(&ctx->hstat, ctx->sock, ctx->fp, ctx->contlen, ctx->contrange, ctx->chunked_transfer_encoding, http_get_body_done_cb);
          return;  // Return and wait for http_get_body_done_cb to call http_loop_continue_async
        }

      case HLS_COMPLETED:
        break;  // Exit loop
      case HLS_FAILED:
        break;  // Exit loop
    }
  }

  // Final cleanup and callback
  if (ctx->retval == RETROK && (ctx->state == HLS_COMPLETED || ctx->state == HLS_FAILED)) {
    if (ctx->fp && !output_stream)
      fclose(ctx->fp);
  }

  if (ctx->final_cb)
    ctx->final_cb(ctx, ctx->retval);
  else
    http_loop_cleanup_impl(ctx);  // If no final_cb, clean up now
}

void http_loop_cleanup(struct http_transaction_ctx* ctx) {
  http_loop_cleanup_impl(ctx);
}

void http_cleanup(void) {
  pconn_cleanup();
  pool_cleanup();
#ifdef ENABLE_COOKIES
  cookies_cleanup();
#endif
  http_auth_cleanup();
}

/* Legacy helper utilities from the previous synchronous HTTP path. */
static int body_file_send(int sock, const char* file_name, wgint promised_size, FILE* warc_tmp) {
  static char chunk[8192];
  wgint written = 0;
  int write_error;
  FILE* fp;

  DEBUGP(("[writing BODY file %s ... ", file_name));

  fp = fopen(file_name, "rb");
  if (!fp)
    return -1;
  while (!feof(fp) && written < promised_size) {
    int towrite;
    int length = fread(chunk, 1, sizeof(chunk), fp);
    if (length == 0)
      break;
    towrite = MIN(promised_size - written, length);
    write_error = fd_write(sock, chunk, towrite, -1);
    if (write_error < 0) {
      fclose(fp);
      return -1;
    }
    if (warc_tmp != NULL) {
      /* Write a copy of the data to the WARC record. */
      int warc_tmp_written = fwrite(chunk, 1, towrite, warc_tmp);
      if (warc_tmp_written != towrite) {
        fclose(fp);
        return -2;
      }
    }
    written += towrite;
  }
  fclose(fp);

  /* If we've written less than was promised, report a (probably
     nonsensical) error rather than break the promise.  */
  if (written < promised_size) {
    errno = EINVAL;
    return -1;
  }

  assert(written == promised_size);
  DEBUGP(("done]\n"));
  return 0;
}

static bool parse_content_range(const char* hdr, wgint* first_byte_ptr, wgint* last_byte_ptr, wgint* entity_length_ptr) {
  wgint num;

  /* Ancient versions of Netscape proxy server, presumably predating
     rfc2068, sent out `Content-Range' without the "bytes"
     specifier.  */
  if (0 == strncasecmp(hdr, "bytes", 5)) {
    hdr += 5;
    /* "JavaWebServer/1.1.1" sends "bytes: x-y/z", contrary to the
       HTTP spec. */
    if (*hdr == ':')
      ++hdr;
    while (c_isspace(*hdr))
      ++hdr;
    if (!*hdr)
      return false;
  }
  if (!c_isdigit(*hdr))
    return false;
  for (num = 0; c_isdigit(*hdr); hdr++)
    num = 10 * num + (*hdr - '0');
  if (*hdr != '-' || !c_isdigit(*(hdr + 1)))
    return false;
  *first_byte_ptr = num;
  ++hdr;
  for (num = 0; c_isdigit(*hdr); hdr++)
    num = 10 * num + (*hdr - '0');
  if (*hdr != '/')
    return false;
  *last_byte_ptr = num;
  if (!(c_isdigit(*(hdr + 1)) || *(hdr + 1) == '*'))
    return false;
  if (*last_byte_ptr < *first_byte_ptr)
    return false;
  ++hdr;
  if (*hdr == '*')
    num = -1;
  else
    for (num = 0; c_isdigit(*hdr); hdr++)
      num = 10 * num + (*hdr - '0');
  *entity_length_ptr = num;
  if ((*entity_length_ptr <= *last_byte_ptr) && *entity_length_ptr != -1)
    return false;
  return true;
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
     connection than to try to read the body.  */
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
         optimization that should be invisible to the user.  */
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
        else
          xfree(line);
      }
    }

    /* Safe even if %.*s bogusly expects terminating \0 because
       we've zero-terminated dlbuf above.  */
    DEBUGP(("%.*s", ret, dlbuf));
  }

  DEBUGP(("] done.\n"));
  return true;
}

static uerr_t time_to_rfc1123(time_t time, char* buf, size_t bufsize) {
  static const char* wkday[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
  static const char* month[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

  struct tm* gtm = gmtime(&time);
  if (!gtm) {
    logprintf(LOG_NOTQUIET, _("gmtime failed. This is probably a bug.\n"));
    return TIMECONV_ERR;
  }

  /* rfc1123 example: Thu, 01 Jan 1998 22:12:57 GMT  */
  snprintf(buf, bufsize, "%s, %02d %s %04d %02d:%02d:%02d GMT", wkday[gtm->tm_wday], gtm->tm_mday, month[gtm->tm_mon], gtm->tm_year + 1900, gtm->tm_hour, gtm->tm_min, gtm->tm_sec);

  return RETROK;
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

  /* Prepare the request to send. */
  {
    char* meth_arg;
    const char* meth = "GET";
    if (head_only)
      meth = "HEAD";
    else if (opt.method)
      meth = opt.method;
    /* Use the full path, i.e. one that includes the leading slash and
       the query string.  E.g. if u->path is "foo/bar" and u->query is
       "param=value", full_path will be "/foo/bar?param=value".  */
    if (proxy
#ifdef HAVE_SSL
        /* When using SSL over proxy, CONNECT establishes a direct
           connection to the HTTPS server.  Therefore use the same
           argument as when talking to the server directly. */
        && u->scheme != SCHEME_HTTPS
#endif
    )
      meth_arg = xstrdup(u->url);
    else
      meth_arg = url_full_path(u);
    req = request_new(meth, meth_arg);
  }

  /* Generate the Host header, HOST:PORT.  Take into account that:

     - Broken server-side software often doesn't recognize the PORT
       argument, so we must generate "Host: www.server.com" instead of
       "Host: www.server.com:80" (and likewise for https port).

     - IPv6 addresses contain ":", so "Host: 3ffe:8100:200:2::2:1234"
       becomes ambiguous and needs to be rewritten as "Host:
       [3ffe:8100:200:2::2]:1234".  */
  {
    /* Formats arranged for hfmt[add_port][add_squares].  */
    static const char* hfmt[][2] = {{"%s", "[%s]"}, {"%s:%d", "[%s]:%d"}};
    int add_port = u->port != scheme_default_port(u->scheme);
    int add_squares = strchr(u->host, ':') != NULL;
    request_set_header(req, "Host", aprintf(hfmt[add_port][add_squares], u->host, u->port), rel_value);
  }

  request_set_header(req, "Referer", hs->referer, rel_none);
  if (*dt & SEND_NOCACHE) {
    /* Cache-Control MUST be obeyed by all HTTP/1.1 caching mechanisms...  */
    request_set_header(req, "Cache-Control", "no-cache", rel_none);

    /* ... but some HTTP/1.0 caches doesn't implement Cache-Control.  */
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
  if (hs->restval)
    request_set_header(req, "Range", aprintf("bytes=%s-", number_to_static_string(hs->restval)), rel_value);
  SET_USER_AGENT(req);
  request_set_header(req, "Accept", "*/*", rel_none);
#if defined(HAVE_LIBZ) && defined(ENABLE_COMPRESSION)
  if (opt.compression != compression_none)
    request_set_header(req, "Accept-Encoding", "gzip", rel_none);
  else
#endif
    request_set_header(req, "Accept-Encoding", "identity", rel_none);

  /* Find the username with priority */
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

  /* Find the password with priority */
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

  /* We only do "site-wide" authentication with "global" user/password
   * values unless --auth-no-challenge has been requested; URL user/password
   * info overrides. */
  if (*user && *passwd && (!u->user || opt.auth_without_challenge)) {
    /* If this is a host for which we've already received a Basic
     * challenge, we'll go ahead and send Basic authentication creds. */
    *basic_auth_finished = http_auth_maybe_send_basic_creds(u->host, *user, *passwd, req);
  }

  if (inhibit_keep_alive)
    request_set_header(req, "Connection", "Close", rel_none);
  else {
    request_set_header(req, "Connection", "Keep-Alive", rel_none);
    if (proxy)
      request_set_header(req, "Proxy-Connection", "Keep-Alive", rel_none);
  }

  if (opt.method) {
    if (opt.body_data || opt.body_file) {
      request_set_header(req, "Content-Type", "application/x-www-form-urlencoded", rel_none);

      if (opt.body_data)
        *body_data_size = strlen(opt.body_data);
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
    else if (c_strcasecmp(opt.method, "post") == 0 || c_strcasecmp(opt.method, "put") == 0 || c_strcasecmp(opt.method, "patch") == 0)
      request_set_header(req, "Content-Length", "0", rel_none);
  }
  return req;
}

static void initialize_proxy_configuration(const struct url* u, struct request* req, struct url* proxy, char** proxyauth) {
  char *proxy_user, *proxy_passwd;
  /* For normal username and password, URL components override
     command-line/wgetrc parameters.  With proxy
     authentication, it's the reverse, because proxy URLs are
     normally the "permanent" ones, so command-line args
     should take precedence.  */
  if (opt.proxy_user && opt.proxy_passwd) {
    proxy_user = opt.proxy_user;
    proxy_passwd = opt.proxy_passwd;
  }
  else {
    proxy_user = proxy->user;
    proxy_passwd = proxy->passwd;
  }
  /* #### This does not appear right.  Can't the proxy request,
     say, `Digest' authentication?  */
  if (proxy_user && proxy_passwd)
    *proxyauth = http_auth_basic_encode(proxy_user, proxy_passwd);

  /* Proxy authorization over SSL is handled below. */
#ifdef HAVE_SSL
  if (u->scheme != SCHEME_HTTPS)
#endif
    request_set_header(req, "Proxy-Authorization", *proxyauth, rel_value);
}

static uerr_t establish_connection(const struct url* u,
                                   const struct url** conn_ref,
                                   struct http_stat* hs,
                                   struct url* proxy,
                                   char** proxyauth,
                                   struct request** req_ref,
                                   bool* using_ssl,
                                   bool inhibit_keep_alive,
                                   int* sock_ref) {
  bool host_lookup_failed = false;
  int sock = *sock_ref;
  struct request* req = *req_ref;
  const struct url* conn = *conn_ref;
  struct http_response* resp;
  int write_error;
  int statcode;

  if (!inhibit_keep_alive) {
    /* Look for a persistent connection to target host, unless a
       proxy is used.  The exception is when SSL is in use, in which
       case the proxy is nothing but a passthrough to the target
       host, registered as a connection to the latter.  */
    const struct url* relevant = conn;
#ifdef HAVE_SSL
    if (u->scheme == SCHEME_HTTPS)
      relevant = u;
#endif

    /* Try to get a connection from the pool first */
    sock = pool_get_connection(relevant->host, relevant->port,
#ifdef HAVE_SSL
                               relevant->scheme == SCHEME_HTTPS,
#else
                               0,
#endif
                               &host_lookup_failed);

    if (sock >= 0) {
      /* Successfully got a connection from the pool */
      *using_ssl = (relevant->scheme == SCHEME_HTTPS);
#if ENABLE_IPV6
      int family = socket_family(sock, ENDPOINT_PEER);
      if (family == AF_INET6)
        logprintf(LOG_VERBOSE, _("Reusing pooled connection to [%s]:%d.\n"), quotearg_style(escape_quoting_style, relevant->host), relevant->port);
      else
#endif
        logprintf(LOG_VERBOSE, _("Reusing pooled connection to %s:%d.\n"), quotearg_style(escape_quoting_style, relevant->host), relevant->port);
      DEBUGP(("Reusing pooled fd %d.\n", sock));
      /* Note: Authorization handling would need to be tracked per connection in the pool */
    }
    else if (persistent_available_p(relevant->host, relevant->port,
#ifdef HAVE_SSL
                                    relevant->scheme == SCHEME_HTTPS,
#else
                                    0,
#endif
                                    &host_lookup_failed)) {
      /* Fall back to legacy persistent connection */
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
           authorization added by code above is unnecessary and
           only hurts us.  */
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
      return (retryable_socket_connect_error(errno) ? CONERROR : CONIMPOSSIBLE);

#ifdef HAVE_SSL
    if (proxy && u->scheme == SCHEME_HTTPS) {
      char* head;
      char* message;
      /* When requesting SSL URLs through proxies, use the
         CONNECT method to request passthrough.  */
      struct request* connreq = request_new("CONNECT", aprintf("%s:%d", u->host, u->port));
      SET_USER_AGENT(connreq);
      if (proxyauth) {
        request_set_header(connreq, "Proxy-Authorization", *proxyauth, rel_value);
        /* Now that PROXYAUTH is part of the CONNECT request,
           zero it out so we don't send proxy authorization with
           the regular request below.  */
        *proxyauth = NULL;
      }
      request_set_header(connreq, "Host", aprintf("%s:%d", u->host, u->port), rel_value);

      write_error = request_send(connreq, sock, 0);
      request_free(&connreq);
      if (write_error < 0) {
        fd_close(sock);
        return WRITEFAILED;
      }

      head = http_response_read_head(sock);
      if (!head) {
        logprintf(LOG_VERBOSE, _("Failed reading proxy response: %s\n"), fd_errstr(sock));
        fd_close(sock);
        return HERR;
      }
      message = NULL;
      if (!*head) {
        xfree(head);
        goto failed_tunnel;
      }
      DEBUGP(("proxy responded with: [%s]\n", head));

      resp = http_response_parse(head);
      statcode = http_response_status(resp, &message);
      if (statcode < 0) {
        char* tms = datetime_str(time(NULL));
        logprintf(LOG_VERBOSE, "%d\n", statcode);
        logprintf(LOG_NOTQUIET, _("%s ERROR %d: %s.\n"), tms, statcode, quotearg_style(escape_quoting_style, _("Malformed status line")));
        http_response_free(&resp);
        return HERR;
      }
      http_stat_set_message(hs, message);
      http_response_free(&resp);
      if (statcode != 200) {
      failed_tunnel:
        logprintf(LOG_NOTQUIET, _("Proxy tunneling failed: %s"), message ? quotearg_style(escape_quoting_style, message) : "?");
        xfree(message);
        return CONSSLERR;
      }
      xfree(message);

      /* SOCK is now *really* connected to u->host, so update CONN
         to reflect this.  That way register_persistent will
         register SOCK as being connected to u->host:u->port.  */
      conn = u;
    }

    if (conn->scheme == SCHEME_HTTPS) {
      if (!ssl_connect_wget(sock, u->host, NULL)) {
        fd_close(sock);
        return CONSSLERR;
      }
      else if (!ssl_check_certificate(sock, u->host)) {
        fd_close(sock);
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

static uerr_t set_file_timestamp(struct http_stat* hs) {
  bool local_dot_orig_file_exists = false;
  char* local_filename = NULL;
  struct stat st;
  char buf[1024];

  if (opt.backup_converted)
  /* If -K is specified, we'll act on the assumption that it was specified
      last time these files were downloaded as well, and instead of just
      comparing local file X against server file X, we'll compare local
      file X.orig (if extant, else X) against server file X.  If -K
      _wasn't_ specified last time, or the server contains files called
      *.orig, -N will be back to not operating correctly with -k. */
  {
    size_t filename_len = strlen(hs->local_file);
    char* filename_plus_orig_suffix;

    if (filename_len + sizeof(ORIG_SFX) > sizeof(buf))
      filename_plus_orig_suffix = xmalloc(filename_len + sizeof(ORIG_SFX));
    else
      filename_plus_orig_suffix = buf;

    memcpy(filename_plus_orig_suffix, hs->local_file, filename_len);
    memcpy(filename_plus_orig_suffix + filename_len, ORIG_SFX, sizeof(ORIG_SFX));

    if (stat(filename_plus_orig_suffix, &st) == 0) {
      local_dot_orig_file_exists = true;
      local_filename = filename_plus_orig_suffix;
    }
  }

  if (!local_dot_orig_file_exists)
    if (stat(hs->local_file, &st) == 0) {
      if (local_filename != buf)
        xfree(local_filename);
      local_filename = hs->local_file;
    }

  if (local_filename != NULL) {
    if (local_filename == buf || local_filename == hs->local_file)
      hs->orig_file_name = xstrdup(local_filename);
    else
      hs->orig_file_name = local_filename;
    hs->orig_file_size = st.st_size;
    hs->orig_file_tstamp = st.st_mtime;
#ifdef WINDOWS
    ++hs->orig_file_tstamp;
#endif
    hs->timestamp_checked = true;
  }

  return RETROK;
}

static uerr_t check_file_output(const struct url* u, struct http_stat* hs, const struct http_response* resp, char* hdrval, size_t hdrsize) {
  if (!hs->local_file) {
    char* local_file = NULL;

    if (!opt.content_disposition || !http_response_header_copy(resp, "Content-Disposition", hdrval, hdrsize) || !parse_content_disposition(hdrval, &local_file)) {
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

  if (!hs->existence_checked && file_exists_p(hs->local_file, NULL)) {
    if (opt.noclobber && !opt.output_document)
      return RETRUNNEEDED;
    else if (!ALLOW_CLOBBER) {
      char* unique = unique_name_passthrough(hs->local_file);
      if (unique != hs->local_file)
        xfree(hs->local_file);
      hs->local_file = unique;
    }
  }
  hs->existence_checked = true;

  if (opt.timestamping && !hs->timestamp_checked) {
    uerr_t timestamp_err = set_file_timestamp(hs);
    if (timestamp_err != RETROK)
      return timestamp_err;
  }
  return RETROK;
}

static uerr_t
check_auth(const struct url* u, char* user, char* passwd, struct http_response* resp, struct request* req, bool* ntlm_seen_ref, bool* retry, bool* basic_auth_finished_ref, bool* auth_finished_ref) {
  uerr_t auth_err = RETROK;
  bool basic_auth_finished = *basic_auth_finished_ref;
  bool auth_finished = *auth_finished_ref;
  bool ntlm_seen = *ntlm_seen_ref;
  char buf[256], *tmp = NULL;

  *retry = false;

  if (!auth_finished && (user && passwd)) {
    int wapos;
    const char* www_authenticate = NULL;
    const char *wabeg, *waend;
    const char *digest = NULL, *basic = NULL, *ntlm = NULL;

    for (wapos = 0; !ntlm && (wapos = http_response_header_locate(resp, "WWW-Authenticate", wapos, &wabeg, &waend)) != -1; ++wapos) {
      param_token name, value;
      size_t len = waend - wabeg;

      if (tmp != buf)
        xfree(tmp);

      if (len < sizeof(buf))
        tmp = buf;
      else
        tmp = xmalloc(len + 1);

      memcpy(tmp, wabeg, len);
      tmp[len] = 0;

      www_authenticate = tmp;

      for (; !ntlm;) {
        while (c_isspace(*www_authenticate))
          www_authenticate++;
        name.e = name.b = www_authenticate;
        while (*name.e && !c_isspace(*name.e))
          name.e++;

        if (name.b == name.e)
          break;

        DEBUGP(("Auth scheme found '%.*s'\n", (int)(name.e - name.b), name.b));

        if (http_auth_known_scheme(name.b, name.e)) {
          if (BEGINS_WITH(name.b, "NTLM")) {
            ntlm = name.b;
            break;
          }
          else if (!digest && BEGINS_WITH(name.b, "Digest"))
            digest = name.b;
          else if (!basic && BEGINS_WITH(name.b, "Basic"))
            basic = name.b;
        }

        www_authenticate = name.e;
        DEBUGP(("Auth param list '%s'\n", www_authenticate));
        while (extract_param(&www_authenticate, &name, &value, ',', NULL) && name.b && value.b) {
          DEBUGP(("Auth param %.*s=%.*s\n", (int)(name.e - name.b), name.b, (int)(value.e - value.b), value.b));
        }
      }
    }

    if (!basic && !digest && !ntlm) {
      logputs(LOG_NOTQUIET, _("Unknown authentication scheme.\n"));
    }
    else if (!basic_auth_finished || !basic) {
      char* pth = url_full_path(u);
      const char* value;
      uerr_t* auth_stat;
      auth_stat = xmalloc(sizeof(uerr_t));
      *auth_stat = RETROK;

      if (ntlm)
        www_authenticate = ntlm;
      else if (digest)
        www_authenticate = digest;
      else
        www_authenticate = basic;

      logprintf(LOG_NOTQUIET, _("Authentication selected: %s\n"), www_authenticate);

      struct ntlmdata* ntlm_state = NULL;
#ifdef ENABLE_NTLM
      ntlm_state = &pconn.ntlm;
#endif
      value = http_auth_create_authorization_line(www_authenticate, user, passwd, request_method(req), pth, ntlm_state, &auth_finished, auth_stat);

      auth_err = *auth_stat;
      xfree(auth_stat);
      xfree(pth);
      if (auth_err == RETROK) {
        request_set_header(req, "Authorization", value, rel_value);

        if (BEGINS_WITH(www_authenticate, "NTLM"))
          ntlm_seen = true;
        else if (!u->user && BEGINS_WITH(www_authenticate, "Basic")) {
          http_auth_register_basic_challenge(u->host);
        }

        *retry = true;
        goto cleanup;
      }
      else {
        xfree(value);
      }
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

static uerr_t open_output_stream(struct http_stat* hs, int count, FILE** fp) {
#ifdef __VMS
#define FOPEN_OPT_ARGS "fop=sqo", "acc", acc_cb, &open_id
#define FOPEN_BIN_FLAG 3
#else
#define FOPEN_BIN_FLAG true
#endif

  if (!output_stream) {
    mkalldirs(hs->local_file);
    if (opt.backups)
      rotate_backups(hs->local_file);
    if (hs->restval) {
#ifdef __VMS
      int open_id;

      open_id = 21;
      *fp = fopen(hs->local_file, "ab", FOPEN_OPT_ARGS);
#else
      *fp = fopen(hs->local_file, "ab");
#endif
    }
    else if (ALLOW_CLOBBER || count > 0) {
      if (opt.unlink_requested && file_exists_p(hs->local_file, NULL)) {
        if (unlink(hs->local_file) < 0) {
          logprintf(LOG_NOTQUIET, "%s: %s\n", hs->local_file, strerror(errno));
          return UNLINKERR;
        }
      }

#ifdef __VMS
      int open_id;

      open_id = 22;
      *fp = fopen(hs->local_file, "wb", FOPEN_OPT_ARGS);
#else
      if (hs->temporary) {
        *fp = fdopen(open(hs->local_file, O_BINARY | O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR), "wb");
      }
      else {
        *fp = fopen(hs->local_file, "wb");
      }

#endif
    }
    else {
      *fp = fopen_excl(hs->local_file, FOPEN_BIN_FLAG);
      if (!*fp && errno == EEXIST) {
        logprintf(LOG_NOTQUIET, _("%s has sprung into existence.\n"), hs->local_file);
        return FOPEN_EXCL_ERR;
      }
    }
    if (!*fp) {
      logprintf(LOG_NOTQUIET, "%s: %s\n", hs->local_file, strerror(errno));
      return FOPENERR;
    }
  }
  else
    *fp = output_stream;

  logprintf(LOG_VERBOSE, _("Saving to: %s\n"), HYPHENP(hs->local_file) ? quote("STDOUT") : quote(hs->local_file));

  return RETROK;
}

static void set_content_type(int* dt, const char* type) {
  if (!type || 0 == c_strcasecmp(type, TEXTHTML_S) || 0 == c_strcasecmp(type, TEXTXHTML_S))
    *dt |= TEXTHTML;
  else
    *dt &= ~TEXTHTML;

  if (type && 0 == c_strcasecmp(type, TEXTCSS_S))
    *dt |= TEXTCSS;
  else
    *dt &= ~TEXTCSS;

  if (type && (0 == c_strcasecmp(type, TEXTXML_S) || 0 == c_strcasecmp(type, APPXML_S) || c_strcasestr(type, "+xml")))
    *dt |= TEXTXML;
  else
    *dt &= ~TEXTXML;
}

#ifdef HAVE_HSTS
static bool parse_strict_transport_security(const char* header, int64_t* max_age, bool* include_subdomains) {
  param_token name, value;
  const char* c_max_age = NULL;
  bool is = false;
  bool is_url_encoded = false;
  bool success = false;

  if (header) {
    for (; extract_param(&header, &name, &value, ';', &is_url_encoded); is_url_encoded = false) {
      if (BOUNDED_EQUAL_NO_CASE(name.b, name.e, "max-age")) {
        xfree(c_max_age);
        c_max_age = strdupdelim(value.b, value.e);
      }
      else if (BOUNDED_EQUAL_NO_CASE(name.b, name.e, "includeSubDomains"))
        is = true;
    }

    if (c_max_age) {
      if (max_age)
        *max_age = (int64_t)strtoll(c_max_age, NULL, 10);
      if (include_subdomains)
        *include_subdomains = is;

      DEBUGP(("Parsed Strict-Transport-Security max-age = %s, includeSubDomains = %s\n", c_max_age, (is ? "true" : "false")));

      xfree(c_max_age);
      success = true;
    }
    else {
      logprintf(LOG_VERBOSE, "Could not parse Strict-Transport-Security header\n");
      success = false;
    }
  }

  return success;
}
#endif

void ensure_extension(struct http_stat* hs, const char* ext, int* dt) {
  char* last_period_in_local_filename = strrchr(hs->local_file, '.');
  char shortext[8];
  int len;
  shortext[0] = '\0';
  len = strlen(ext);
  if (len == 5) {
    memcpy(shortext, ext, len - 1);
    shortext[len - 1] = '\0';
  }

  if (last_period_in_local_filename == NULL || !(0 == strcasecmp(last_period_in_local_filename, shortext) || 0 == strcasecmp(last_period_in_local_filename, ext))) {
    int local_filename_len = strlen(hs->local_file);
    /* Resize the local file, allowing for ".html" preceded by
       optional ".NUMBER".  */
    hs->local_file = xrealloc(hs->local_file, local_filename_len + 24 + len);
    strcpy(hs->local_file + local_filename_len, ext);
    /* If clobbering is not allowed and the file, as named,
       exists, tack on ".NUMBER.html" instead. */
    if (!ALLOW_CLOBBER && file_exists_p(hs->local_file, NULL)) {
      int ext_num = 1;
      do
        sprintf(hs->local_file + local_filename_len, ".%d%s", ext_num++, ext);
      while (file_exists_p(hs->local_file, NULL));
    }
    *dt |= ADDED_HTML_EXTENSION;
  }
}

#ifdef TESTING

const char* test_parse_range_header(void) {
  unsigned i;
  static const struct {
    const char* rangehdr;
    const wgint firstbyte;
    const wgint lastbyte;
    const wgint length;
    const bool shouldPass;
  } test_array[] = {
      {"bytes 0-1000/1000", 0, 1000, 1000, false},
      {"bytes 0-999/1000", 0, 999, 1000, true},
      {"bytes 100-99/1000", 100, 99, 1000, false},
      {"bytes 100-100/1000", 100, 100, 1000, true},
      {"bytes 0-1000/100000000", 0, 1000, 100000000, true},
      {"bytes 1-999/1000", 1, 999, 1000, true},
      {"bytes 42-1233/1234", 42, 1233, 1234, true},
      {"bytes 42-1233/*", 42, 1233, -1, true},
      {"bytes 0-2147483648/2147483649", 0, 2147483648U, 2147483649U, true},
      {"bytes 2147483648-4294967296/4294967297", 2147483648U, 4294967296ULL, 4294967297ULL, true},
  };

  wgint firstbyteptr[sizeof(wgint)];
  wgint lastbyteptr[sizeof(wgint)];
  wgint lengthptr[sizeof(wgint)];
  bool result;
  for (i = 0; i < countof(test_array); i++) {
    result = parse_content_range(test_array[i].rangehdr, firstbyteptr, lastbyteptr, lengthptr);
#if 0
      printf ("%ld %ld\n", test_array[i].firstbyte, *firstbyteptr);
      printf ("%ld %ld\n", test_array[i].lastbyte, *lastbyteptr);
      printf ("%ld %ld\n", test_array[i].length, *lengthptr);
      printf ("\n");
#endif
    mu_assert("test_parse_range_header: False Negative", result == test_array[i].shouldPass);
    mu_assert("test_parse_range_header: Bad parse", test_array[i].firstbyte == *firstbyteptr && test_array[i].lastbyte == *lastbyteptr && test_array[i].length == *lengthptr);
  }

  return NULL;
}

const char* test_parse_content_disposition(void) {
  unsigned i;
  static const struct {
    const char* hdrval;
    const char* filename;
    bool result;
  } test_array[] = {
      {"filename=\"file.ext\"", "file.ext", true},
      {"attachment; filename=\"file.ext\"", "file.ext", true},
      {"attachment; filename=\"file.ext\"; dummy", "file.ext", true},
      {"attachment", NULL, false},
      {"attachment; filename*=UTF-8'en-US'hello.txt", "hello.txt", true},
      {"attachment; filename*0=\"hello\"; filename*1=\"world.txt\"", "helloworld.txt", true},
      {"attachment; filename=\"A.ext\"; filename*=\"B.ext\"", "B.ext", true},
      {"attachment; filename*=\"A.ext\"; filename*0=\"B\"; filename*1=\"B.ext\"", "A.ext", true},
      {"filename**0=\"A\"; filename**1=\"A.ext\"; filename*0=\"B\";\
filename*1=\"B\"",
       "AA.ext", true},
  };

  for (i = 0; i < countof(test_array); ++i) {
    char* filename;
    bool res;

    res = parse_content_disposition(test_array[i].hdrval, &filename);

    mu_assert("test_parse_content_disposition: wrong result", res == test_array[i].result && (res == false || 0 == strcmp(test_array[i].filename, filename)));
    xfree(filename);
  }

  return NULL;
}

#endif /* TESTING */

/*
 * vim: et sts=2 sw=2 cino+={s
 */
