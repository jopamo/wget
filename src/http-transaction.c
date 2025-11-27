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
#include "http.h"
#include "evloop.h"
#include "net_conn.h"

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

extern struct cookie_jar* wget_cookie_jar;

/* --- Reused Helpers (Simplified copies from original) --- */
/* We include them to support the logic (auth, filename parsing, etc.) */

#define TEXTHTML_S "text/html"
#define TEXTXHTML_S "application/xhtml+xml"
#define TEXTCSS_S "text/css"

#define HTTP_STATUS_OK 200
#define HTTP_STATUS_MOVED_PERMANENTLY 301
#define HTTP_STATUS_MOVED_TEMPORARILY 302
#define HTTP_STATUS_SEE_OTHER 303
#define HTTP_STATUS_TEMPORARY_REDIRECT 307
#define HTTP_STATUS_PERMANENT_REDIRECT 308
#define HTTP_STATUS_UNAUTHORIZED 401
#define HTTP_STATUS_PARTIAL_CONTENTS 206

#define H_10X(x) (((x) >= 100) && ((x) < 200))
#define H_20X(x) (((x) >= 200) && ((x) < 300))
#define H_REDIRECTED(x) ((x) == HTTP_STATUS_MOVED_PERMANENTLY || (x) == HTTP_STATUS_MOVED_TEMPORARILY || (x) == HTTP_STATUS_SEE_OTHER || (x) == HTTP_STATUS_TEMPORARY_REDIRECT || (x) == HTTP_STATUS_PERMANENT_REDIRECT)

/* Helper to set error */
static void txn_set_error(struct http_transaction *txn, uerr_t err, const char *msg);

/* --- Async State Machine --- */

enum http_txn_state {
  H_INIT,
  H_RESOLVE_CONNECT,
  H_CONNECTING,
  H_SEND_REQUEST,
  H_SEND_BODY,
  H_READ_STATUS,
  H_READ_HEADERS,
  H_CHECK_AUTH, /* Decide if we need to retry with auth */
  H_READ_BODY,
  H_DONE,
  H_ERR
};

struct http_transaction {
  struct ev_loop *loop;
  enum http_txn_state state;
  
  /* Input Params */
  const struct url *u;
  struct url *original_url;
  struct http_stat *hs;
  int *dt;
  struct url *proxy;
  struct iri *iri;
  int count;
  
  http_txn_cb on_complete;
  void *cb_arg;
  
  /* Internal State */
  struct net_conn *conn;
  struct request *req;
  struct response *resp;
  char *resp_data;  /* Backing store for resp */
  
  /* Buffers */
  char *req_str;    /* Serialized request */
  size_t req_len;
  size_t req_sent;
  size_t body_sent;
  
  char *recv_buf;   /* Buffer for status/headers */
  size_t recv_cap;
  size_t recv_used;
  
  /* Body State */
  FILE *fp;         /* Output file */
  bool output_opened;
  wgint contlen;
  wgint contrange;
  bool parsed_content_range;
  bool chunked;
  wgint chunk_size; /* For chunked decoding */
  int chunk_state;  /* 0=size, 1=data, 2=CRLF */
  
  /* Auth State */
  bool auth_finished;
  bool basic_auth_finished;
  bool ntlm_seen;
  char *user;
  char *passwd;
  
  /* Result */
  uerr_t err_code;
};

/* Forward decls for helpers that we need to reimplement or link */
/* We assume these are available or copied from original. 
   For brevity in this replacement, I will assume some exist or stub them if simple.
   Actually, I need to COPY the critical ones or this won't compile!
*/

/* COPY: time_to_rfc1123 */
static uerr_t time_to_rfc1123(time_t time_val, char* buf, size_t bufsize) {
  static const char* wkday[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
  static const char* month[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  struct tm* gtm = gmtime(&time_val);
  if (!gtm) return TIMECONV_ERR;
  snprintf(buf, bufsize, "%s, %02d %s %04d %02d:%02d:%02d GMT", wkday[gtm->tm_wday], gtm->tm_mday, month[gtm->tm_mon], gtm->tm_year + 1900, gtm->tm_hour, gtm->tm_min, gtm->tm_sec);
  return RETROK;
}

/* COPY: set_file_timestamp (simplified) */
static uerr_t set_file_timestamp(struct http_stat* hs) {
    /* Simplified implementation to avoid complex backup logic for now */
    struct stat st;
    if (stat(hs->local_file, &st) == 0) {
        hs->orig_file_name = xstrdup(hs->local_file);
        hs->orig_file_size = st.st_size;
        hs->orig_file_tstamp = st.st_mtime;
        hs->timestamp_checked = true;
    }
    return RETROK;
}

/* COPY: initialize_request (Must include) */
static struct request* initialize_request(const struct url* u, struct http_stat* hs, int* dt, struct url* proxy, bool inhibit_keep_alive, bool* basic_auth_finished, wgint* body_data_size, char** user, char** passwd, uerr_t* ret) {
    /* ... (Simplified version of the original) ... */
    /* We really need the full logic for headers. I'll try to be concise but complete. */
    
    struct request* req;
    const char* meth = (*dt & HEAD_ONLY) ? "HEAD" : (opt.method ? opt.method : "GET");
    char* meth_arg = (proxy && u->scheme != SCHEME_HTTPS) ? xstrdup(u->url) : url_full_path(u);
    
    req = request_new(meth, meth_arg);
    
    /* Host header */
    int add_squares = (strchr(u->host, ':') != NULL);
    char* host_header = aprintf(add_squares ? "[%s]:%d" : "%s:%d", u->host, u->port); /* port is always set in url struct */
    request_set_header(req, "Host", host_header, rel_value);

    if (hs->referer) request_set_header(req, "Referer", hs->referer, rel_none);
    request_set_user_agent(req);
    request_set_header(req, "Accept", "*/*", rel_none);
    request_set_header(req, "Connection", "Close", rel_none); /* Default to close for now for safety in Phase 4 */

    /* Range */
    if (hs->restval)
         request_set_header(req, "Range", aprintf("bytes=%s-", number_to_static_string(hs->restval)), rel_value);
         
    /* Auth setup (simplified) */
    if (u->user) *user = u->user;
    else if (opt.user) *user = opt.user;
    else *user = NULL;
    
    if (u->passwd) *passwd = u->passwd;
    else if (opt.passwd) *passwd = opt.passwd;
    else *passwd = NULL;

    if (opt.netrc && (!*user || !*passwd))
        search_netrc(u->host, (const char**)user, (const char**)passwd, 0, NULL);

    if (*user && *passwd && (!u->user || opt.auth_without_challenge)) {
        *basic_auth_finished = maybe_send_basic_creds(u->host, *user, *passwd, req);
    }
    
    if (opt.body_data) {
        *body_data_size = strlen(opt.body_data);
        request_set_header(req, "Content-Length", xstrdup(number_to_static_string(*body_data_size)), rel_value);
    } else {
        *body_data_size = 0;
    }
    
    *ret = RETROK;
    return req;
}

/* State Machine Functions */

static void txn_step(struct http_transaction *txn);
static void on_conn_ready(struct net_conn *c, void *arg);
static void on_conn_error(struct net_conn *c, void *arg);
static void on_readable(struct net_conn *c, void *arg);
static void on_writable(struct net_conn *c, void *arg);

struct http_transaction* http_txn_new(struct ev_loop* loop,
                                      const struct url* u, 
                                      struct url* original_url, 
                                      struct http_stat* hs, 
                                      int* dt, 
                                      struct url* proxy, 
                                      struct iri* iri, 
                                      int count,
                                      http_txn_cb on_complete,
                                      void* cb_arg)
{
    struct http_transaction *txn = xnew0(struct http_transaction);
    txn->loop = loop;
    txn->u = u;
    txn->original_url = original_url;
    txn->hs = hs;
    txn->dt = dt;
    txn->proxy = proxy;
    txn->iri = iri;
    txn->count = count;
    txn->on_complete = on_complete;
    txn->cb_arg = cb_arg;
    txn->state = H_INIT;
    
    /* Init buffers */
    txn->recv_cap = 4096;
    txn->recv_buf = xmalloc(txn->recv_cap);
    
    return txn;
}

void http_txn_free(struct http_transaction* txn) {
    if (!txn) return;
    
    if (txn->conn) {
        /* If we owned the connection, close it. 
           In future PCONN, we might release it. */
        conn_close(txn->conn);
    }
    
    if (txn->req) request_free(&txn->req);
    if (txn->resp) resp_free(&txn->resp);
    xfree(txn->resp_data);
    if (txn->fp && txn->output_opened && txn->fp != stdout) fclose(txn->fp);
    
    xfree(txn->req_str);
    xfree(txn->recv_buf);
    /* User/Passwd are usually pointers to u->user or opt.user, not owned, unless strdup'd. 
       initialize_request logic handles this. */
    
    xfree(txn);
}

uerr_t http_txn_get_error(struct http_transaction* txn) {
    return txn ? txn->err_code : RETROK;
}

void http_txn_start(struct http_transaction* txn) {
    txn_step(txn);
}

void http_txn_stop(struct http_transaction* txn) {
    txn->state = H_DONE; /* Or H_CANCELLED */
    /* cleanup will happen on free */
}

static void txn_finish(struct http_transaction *txn, uerr_t err) {
    txn->err_code = err;
    txn->state = (err == RETROK || err == RETRFINISHED) ? H_DONE : H_ERR;
    if (txn->on_complete)
        txn->on_complete(txn, txn->cb_arg);
}

static void txn_set_error(struct http_transaction *txn, uerr_t err, const char *msg) {
    if (msg) {
        xfree(txn->hs->error);
        txn->hs->error = xstrdup(msg);
    }
    txn_finish(txn, err);
}

/* Helper for Content-Type */
static void set_content_type_from_header(int* dt, const char* type) {
  if (!dt) return;
  if (!type || 0 == c_strcasecmp(type, TEXTHTML_S) || 0 == c_strcasecmp(type, TEXTXHTML_S))
    *dt |= TEXTHTML;
  else
    *dt &= ~TEXTHTML;

  if (type && 0 == c_strcasecmp(type, TEXTCSS_S))
    *dt |= TEXTCSS;
  else
    *dt &= ~TEXTCSS;
}

static void txn_update_content_type(struct http_transaction *txn) {
    if (!txn || !txn->dt) return;
    char *type = resp_header_strdup(txn->resp, "Content-Type");
    set_content_type_from_header(txn->dt, type);
    xfree(type);
}

/* Step Logic */
static void txn_step(struct http_transaction *txn) {
    switch (txn->state) {
        case H_INIT: {
            /* Initialize Request */
            wgint body_size = 0;
            uerr_t ret;
            
            if (txn->req) request_free(&txn->req);
            
            txn->req = initialize_request(txn->u, txn->hs, txn->dt, txn->proxy, false, 
                                         &txn->basic_auth_finished, &body_size, 
                                         &txn->user, &txn->passwd, &ret);
            if (!txn->req) {
                txn_finish(txn, ret);
                return;
            }
            
            /* Move to Connect */
            txn->state = H_RESOLVE_CONNECT;
            txn_step(txn);
            break;
        }
        
        case H_RESOLVE_CONNECT: {
            /* Create net_conn */
            const char *host = txn->proxy ? txn->proxy->host : txn->u->host;
            int port = txn->proxy ? txn->proxy->port : txn->u->port;
            bool use_tls = (txn->u->scheme == SCHEME_HTTPS && !txn->proxy); /* Simplified proxy logic */
            
            logprintf(LOG_VERBOSE, _("Connecting to %s:%d... "), host, port);

            char port_str[16];
            snprintf(port_str, sizeof(port_str), "%d", port);
            
            txn->conn = conn_new(txn->loop, host, port_str, use_tls, on_conn_ready, on_conn_error, txn);
            
            txn->state = H_CONNECTING;
            break;
        }
        
        case H_SEND_REQUEST: {
            /* Serialize Request */
            if (!txn->req_str) {
                txn->req_str = request_string(txn->req, &txn->req_len);
                txn->req_sent = 0;
            }
            
            logprintf(LOG_VERBOSE, _("connected.\n"));
            logprintf(LOG_VERBOSE, _("%s request sent, awaiting response... "), txn->proxy ? "Proxy" : "HTTP");

            /* Register Writer */
            conn_set_writable_callback(txn->conn, on_writable, txn);
            break;
        }
        
        case H_SEND_BODY: {
             /* Register Writer */
             conn_set_writable_callback(txn->conn, on_writable, txn);
             break;
        }
        
        case H_READ_STATUS:
        case H_READ_HEADERS:
        case H_READ_BODY: {
             /* Just register reader */
             conn_set_readable_callback(txn->conn, on_readable, txn);
             break;
        }
        
        default:
            break;
    }
}

/* Callbacks */

static void on_conn_ready(struct net_conn *c, void *arg) {
    (void)c;
    struct http_transaction *txn = arg;
    if (txn->state == H_CONNECTING) {
        txn->state = H_SEND_REQUEST;
        txn_step(txn);
    }
}

static void on_conn_error(struct net_conn *c, void *arg) {
    struct http_transaction *txn = arg;
    const char *msg = conn_get_error_msg(c);
    logprintf(LOG_VERBOSE, _("failed: %s.\n"), msg ? msg : _("Unknown error"));
    txn_set_error(txn, CONERROR, msg);
}

static void on_writable(struct net_conn *c, void *arg) {
    struct http_transaction *txn = arg;
    
    if (txn->state == H_SEND_REQUEST) {
        ssize_t n = conn_try_write(c, txn->req_str + txn->req_sent, txn->req_len - txn->req_sent);
        if (n < 0) {
            if (errno == EAGAIN) return;
            txn_set_error(txn, WRITEFAILED, "Write failed");
            return;
        }
        txn->req_sent += n;
        if (txn->req_sent >= txn->req_len) {
            /* Done writing request headers */
            if (opt.body_data) {
                txn->state = H_SEND_BODY;
                txn->body_sent = 0;
                /* Fallthrough or return? If writable, we can try writing immediately. */
                on_writable(c, arg);
                return;
            } else {
                conn_set_writable_callback(c, NULL, NULL); /* Stop writing */
                txn->state = H_READ_STATUS;
                txn_step(txn);
            }
        }
    }
    else if (txn->state == H_SEND_BODY) {
        if (opt.body_data) {
             size_t len = strlen(opt.body_data);
             ssize_t n = conn_try_write(c, opt.body_data + txn->body_sent, len - txn->body_sent);
             if (n < 0) {
                 if (errno == EAGAIN) return;
                 txn_set_error(txn, WRITEFAILED, "Body write failed");
                 return;
             }
             txn->body_sent += n;
             if (txn->body_sent >= len) {
                 conn_set_writable_callback(c, NULL, NULL);
                 txn->state = H_READ_STATUS;
                 txn_step(txn);
             }
        }
    }
}


// Helper function to parse Content-Range header
// Expected format: "bytes START-END/TOTAL" or "bytes START-END/*"
// Returns TOTAL or -1 if TOTAL is not specified or parsing fails.
static wgint parse_content_range(const char* header_val) {
    if (!header_val || strncmp(header_val, "bytes ", 6) != 0) {
        return -1; // Not a bytes range or invalid format
    }
    const char* slash = strchr(header_val + 6, '/');
    if (!slash) {
        return -1; // Missing total length part
    }
    if (strcmp(slash + 1, "*") == 0) {
        return -1; // Total length is unknown
    }
    return str_to_wgint(slash + 1, NULL, 10);
}

static void on_readable(struct net_conn *c, void *arg) {
    struct http_transaction *txn = arg;
    
    if (txn->state == H_READ_STATUS || txn->state == H_READ_HEADERS) {
        /* Read into recv_buf until double CRLF */
        /* Simple implementation: read chunk, append, search for \r\n\r\n or \n\n */
        
        if (txn->recv_used >= txn->recv_cap - 1) {
            txn->recv_cap *= 2;
            txn->recv_buf = xrealloc(txn->recv_buf, txn->recv_cap);
        }
        
        ssize_t n = conn_try_read(c, txn->recv_buf + txn->recv_used, txn->recv_cap - txn->recv_used - 1);
        if (n < 0) {
            if (errno == EAGAIN) return;
            txn_set_error(txn, READERR, "Read error");
            return;
        }
        if (n == 0) {
            txn_set_error(txn, HEOF, "Connection closed prematurely");
            return;
        }
        txn->recv_used += n;
        txn->recv_buf[txn->recv_used] = '\0';
        
        if (txn->state == H_READ_STATUS) {
            /* Check for status line termination (first \n) */
             char *eol = strchr(txn->recv_buf, '\n');
             if (eol) {
                 *eol = '\0';
                 /* Parse Status */
                 /* Need to parse HTTP/1.x CODE MSG */
                 int code = -1;
                 char *p = txn->recv_buf;
                 if (strncmp(p, "HTTP", 4) == 0) {
                     p = strchr(p, ' ');
                     if (p) code = atoi(p+1);
                 }
                 
                 if (code < 0) {
                     txn_set_error(txn, HERR, "Malformed status line");
                     return;
                 }
                 txn->hs->statcode = code;
                 txn->state = H_READ_HEADERS;
                 DEBUGP(("[http-txn] H_READ_STATUS: statcode=%d\n", code));
                 
                 /* Log status */
                 logprintf(LOG_VERBOSE, "%2d %s\n", code, (p && strchr(p,' ')) ? strchr(p,' ')+1 : "");
                 
                 /* Shift buffer */
                 size_t line_len = (eol - txn->recv_buf) + 1;
                 memmove(txn->recv_buf, eol + 1, txn->recv_used - line_len);
                 txn->recv_used -= line_len;
                 txn->recv_buf[txn->recv_used] = '\0';
                 
                 /* Fallthrough to check headers in remaining buffer */
             }
        }
        
        if (txn->state == H_READ_HEADERS) {
            /* Check for \r\n\r\n */
            char *eoh = strstr(txn->recv_buf, "\r\n\r\n");
            if (!eoh) eoh = strstr(txn->recv_buf, "\n\n");
            
            if (eoh) {
                size_t head_len = (eoh - txn->recv_buf);
                /* Consume the full header terminator. Use 4 bytes for \r\n\r\n and 2 for \n\n. */
                size_t term_len = (eoh[0] == '\r' && eoh[1] == '\n') ? 4 : 2;
                
                txn->resp_data = xstrndup(txn->recv_buf, head_len);
                txn->resp = resp_new(txn->resp_data);
                
                /* Handle headers (Content-Length, Content-Range, etc.) */
                char val[1024];
                if (resp_header_copy(txn->resp, "Content-Length", val, sizeof(val))) {
                    txn->contlen = str_to_wgint(val, NULL, 10);
                } else {
                    txn->contlen = -1;
                }
                DEBUGP(("[http-txn] H_READ_HEADERS: Content-Length=%lld\n", (long long)txn->contlen));

                if (txn->hs->statcode == HTTP_STATUS_PARTIAL_CONTENTS) {
                    char *range_header_val = resp_header_strdup(txn->resp, "Content-Range");
                    if (range_header_val) {
                        txn->contrange = parse_content_range(range_header_val);
                        txn->parsed_content_range = true;
                        DEBUGP(("[http-txn] H_READ_HEADERS: Content-Range='%s', parsed_contrange=%lld\n", range_header_val, (long long)txn->contrange));
                        xfree(range_header_val);
                    } else {
                        DEBUGP(("[http-txn] H_READ_HEADERS: Content-Range header missing for 206 response!\n"));
                    }
                }
                
                /* Handle Content-Type */
                txn_update_content_type(txn);

                /* Check for Redirects */
                if (H_REDIRECTED(txn->hs->statcode)) {
                    char *loc = resp_header_strdup(txn->resp, "Location");
                    if (loc) {
                        xfree(txn->hs->newloc);
                        txn->hs->newloc = loc;
                        txn_set_error(txn, NEWLOCATION, NULL);
                        return;
                    }
                }
                
                /* Set RETROKF flag based on status code */
                if (H_20X(txn->hs->statcode)) {
                    if (txn->dt) *txn->dt |= RETROKF;
                } else {
                    if (txn->dt) *txn->dt &= ~RETROKF;
                }

                /* If error (not 2xx), stop here (unless redirect handled above) */
                /* Redirects returned above. */
                if (!H_20X(txn->hs->statcode)) {
                     char *msg = NULL;
                     resp_status(txn->resp, &msg);
                     if (msg) {
                         xfree(txn->hs->error);
                         txn->hs->error = msg;
                     }
                     txn_finish(txn, RETROK);
                     return;
                }

                txn->state = H_READ_BODY;
                
                /* Open Output File */
                if (!txn->hs->local_file) {
                    /* Fallback if not set */
                    txn->hs->local_file = url_file_name(txn->u, NULL);
                }
                
                const char *mode = "wb";
                if (txn->hs->restval > 0 && txn->hs->statcode == HTTP_STATUS_PARTIAL_CONTENTS) {
                    mode = "ab";
                }

                if (strcmp(txn->hs->local_file, "-") == 0) {
                    txn->fp = stdout;
                    /* Don't set output_opened for stdout to avoid closing it */
                } else {
                    mkalldirs(txn->hs->local_file);
                    txn->fp = fopen(txn->hs->local_file, mode); /* TODO: Respect clobber, etc. */
                    if (txn->fp) txn->output_opened = true;
                }

                if (!txn->fp) {
                     txn_set_error(txn, FOPENERR, "Cannot open output file");
                     return;
                }
                
                // Initialize txn->hs->len with the current file size if appending
                if (txn->hs->restval > 0 && txn->hs->statcode == HTTP_STATUS_PARTIAL_CONTENTS) {
                    txn->hs->len = txn->hs->restval;
                } else {
                    txn->hs->len = 0; // Ensure it's reset for new downloads
                }
                DEBUGP(("[http-txn] H_READ_HEADERS: Initial txn->hs->len=%lld (from restval=%lld)\n", (long long)txn->hs->len, (long long)txn->hs->restval));

                logprintf(LOG_VERBOSE, _("Saving to: %s\n"), quote(txn->hs->local_file));
                
                /* Shift remaining body data */
                size_t consumed = head_len + term_len;
                size_t body_rem = txn->recv_used - consumed;
                if (body_rem > 0) {
                    fwrite(txn->recv_buf + consumed, 1, body_rem, txn->fp);
                    txn->hs->len += body_rem;
                }
                txn->recv_used = 0;
            }
        }
    }
    else if (txn->state == H_READ_BODY) {
        /* Stream Body */
        if (txn->recv_used >= txn->recv_cap) txn->recv_used = 0;
        
        ssize_t n = conn_try_read(c, txn->recv_buf, txn->recv_cap);
        if (n < 0) {
             if (errno == EAGAIN) return;
             txn_set_error(txn, READERR, "Body read error");
             return;
        }
        if (n == 0) {
             /* EOF */
             if (txn->hs->statcode == HTTP_STATUS_PARTIAL_CONTENTS && txn->parsed_content_range) {
                 if (txn->contrange != -1 && txn->hs->len < txn->contrange) {
                     txn_set_error(txn, RETRFINISHED, "Connection closed before full length (partial content)"); /* Warning */
                 } else {
                     txn_finish(txn, RETRFINISHED);
                 }
             } else if (txn->contlen != -1 && txn->hs->len < txn->contlen) {
                 txn_set_error(txn, RETRFINISHED, "Connection closed before full length"); /* Warning */
             } else {
                 txn_finish(txn, RETRFINISHED);
             }
             return;
        }
        
        fwrite(txn->recv_buf, 1, n, txn->fp);
        txn->hs->len += n;
        DEBUGP(("[http-txn] H_READ_BODY: Read %zd bytes, total_len=%lld, contlen=%lld, contrange=%lld\n", n, (long long)txn->hs->len, (long long)txn->contlen, (long long)txn->contrange));
        
        if (txn->hs->statcode == HTTP_STATUS_PARTIAL_CONTENTS && txn->parsed_content_range) {
            if (txn->contrange != -1 && txn->hs->len >= txn->contrange) {
                DEBUGP(("[http-txn] H_READ_BODY: Finishing due to full contrange (%lld >= %lld)\n", (long long)txn->hs->len, (long long)txn->contrange));
                txn_finish(txn, RETRFINISHED);
            }
        } else if (txn->contlen != -1 && txn->hs->len >= txn->contlen) {
            DEBUGP(("[http-txn] H_READ_BODY: Finishing due to full contlen (%lld >= %lld)\n", (long long)txn->hs->len, (long long)txn->contlen));
            txn_finish(txn, RETRFINISHED);
        }
    }
}



/* --- Wrapper Implementation --- */

struct run_ctx {
    struct ev_loop *loop;
    bool done;
};

static void on_run_complete(struct http_transaction *txn, void *arg) {
    (void)txn;
    struct run_ctx *ctx = arg;
    ctx->done = true;
    evloop_break(ctx->loop);
}

uerr_t http_transaction_run(const struct url* u, struct url* original_url, struct http_stat* hs, int* dt, struct url* proxy, struct iri* iri, int count)
{
    struct ev_loop *loop = evloop_get_default();
    struct run_ctx ctx = { loop, false };
    
    struct http_transaction *txn = http_txn_new(loop, u, original_url, hs, dt, proxy, iri, count, on_run_complete, &ctx);
    
    http_txn_start(txn);
    
    /* Run Loop until done */
    /* evloop_run might block forever if no events. 
       But txn start adds resolve/connect watchers. */
    evloop_run(loop);
    
    uerr_t err = http_txn_get_error(txn);
    
    http_txn_free(txn);
    
    return err;
}
