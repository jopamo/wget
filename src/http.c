/* HTTP support
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
#include "http-request.h"
#include "http-response.h"
#include "http-auth.h"
#include "http-pconn.h"
#include "http-proxy.h"
#include "http-stat.h"
#include "http-transaction.h"
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
#include "cookies.h"
#include "md5.h"
#include "convert.h"
#include "spider.h"
#include "warc.h"
#include "c-strcase.h"
#include "version.h"
#include "xstrndup.h"
#ifdef ENABLE_XATTR
#include "xattr.h"
#endif

static void load_cookies(void);

static bool cookies_loaded_p;
struct cookie_jar* wget_cookie_jar;

#define TEXTHTML_S "text/html"
#define TEXTXHTML_S "application/xhtml+xml"
#define TEXTCSS_S "text/css"

/* ------------------------------------------------------------------------- */
/* Local helpers */
/* ------------------------------------------------------------------------- */

void get_file_flags(const char* filename, int* dt) {
  logprintf(LOG_VERBOSE, _("\nFile %s already there; not retrieving\n\n"), quote(filename));

  *dt |= RETROKF;

  if (has_html_suffix_p(filename))
    *dt |= TEXTHTML;
}

/* Check whether the supplied HTTP status code is among those
   listed for the --retry-on-http-error option */
static bool check_retry_on_http_error(const int statcode) {
  const char* tok = opt.retry_on_http_error;
  while (tok && *tok) {
    if (atoi(tok) == statcode)
      return true;
    if ((tok = strchr(tok, ',')))
      ++tok;
  }
  return false;
}

/* Verify that p is a valid pointer to the end of the string */
static bool check_end(const char* p) {
  return p && !*p;
}

/* Parameter extraction helper used for header and cookie parsing paths
 * name and value are slices into the input string, not owning buffers */
bool extract_param(const char** input, param_token* name, param_token* value, char separator, bool* is_url_encoded) {
  const char* p = *input;

  /* skip leading whitespace and any stray separators */
  while (*p && (c_isspace(*p) || *p == separator))
    p++;

  if (!*p) {
    *input = p;
    if (is_url_encoded)
      *is_url_encoded = false;
    return false;
  }

  /* parse name */
  name->b = p;
  while (*p && *p != '=' && *p != separator && !c_isspace(*p))
    p++;
  name->e = p;

  /* skip whitespace after name */
  while (*p && c_isspace(*p))
    p++;

  /* name-only parameter: no '=' present */
  if (*p != '=') {
    value->b = NULL;
    value->e = NULL;

    /* consume until next separator so caller can make progress */
    while (*p && *p != separator)
      p++;

    if (*p == separator)
      p++;

    *input = p;

    if (is_url_encoded)
      *is_url_encoded = false;

    return true;
  }

  /* value follows '=' */
  p++;

  while (*p && c_isspace(*p))
    p++;

  value->b = p;

  if (*p == '"') {
    p++;
    value->b = p;
    while (*p && *p != '"')
      p++;
    value->e = p;
    if (*p == '"')
      p++;
  }
  else {
    while (*p && *p != separator && !c_isspace(*p))
      p++;
    value->e = p;
  }

  /* consume up to and including next separator */
  while (*p && *p != separator)
    p++;

  if (*p == separator)
    p++;

  *input = p;

  if (is_url_encoded)
    *is_url_encoded = false;

  return true;
}

/* ------------------------------------------------------------------------- */
/* RFC time parsing */
/* ------------------------------------------------------------------------- */

time_t http_atotm(const char* time_string) {
  static const char* time_formats[] = {
      "%a, %d %b %Y %T", /* rfc1123: Thu, 29 Jan 1998 22:12:57 */
      "%A, %d-%b-%y %T", /* rfc850:  Thursday, 29-Jan-98 22:12:57 */
      "%a %b %d %T %Y",  /* asctime: Thu Jan 29 22:12:57 1998 */
      "%a, %d-%b-%Y %T"  /* cookies: Thu, 29-Jan-1998 22:12:57 */
  };

  const char* oldlocale;
  char savedlocale[256];
  size_t i;
  time_t ret = (time_t)-1;

  oldlocale = setlocale(LC_TIME, NULL);
  if (oldlocale) {
    size_t l = strlen(oldlocale) + 1;
    if (l < sizeof savedlocale)
      memcpy(savedlocale, oldlocale, l);
    else
      savedlocale[0] = '\0';
  }
  else {
    savedlocale[0] = '\0';
  }

  setlocale(LC_TIME, "C");

  for (i = 0; i < countof(time_formats); i++) {
    struct tm t;
    xzero(t);

    if (check_end(strptime(time_string, time_formats[i], &t))) {
      ret = timegm(&t);
      break;
    }
  }

  if (savedlocale[0])
    setlocale(LC_TIME, savedlocale);

  return ret;
}

/* ------------------------------------------------------------------------- */
/* Cookies */
/* ------------------------------------------------------------------------- */

static void load_cookies(void) {
  if (!wget_cookie_jar)
    wget_cookie_jar = cookie_jar_new();

  if (opt.cookies_input && !cookies_loaded_p) {
    cookie_jar_load(wget_cookie_jar, opt.cookies_input);
    cookies_loaded_p = true;
  }
}

void save_cookies(void) {
  if (wget_cookie_jar)
    cookie_jar_save(wget_cookie_jar, opt.cookies_output);
}

/* ------------------------------------------------------------------------- */
/* Cleanup */
/* ------------------------------------------------------------------------- */

#if defined DEBUG_MALLOC || defined TESTING
void http_cleanup(void) {
  /* legacy persistent connection cleanup is handled by http-pconn in the new design */

  if (wget_cookie_jar) {
    cookie_jar_delete(wget_cookie_jar);
    wget_cookie_jar = NULL;
  }

  http_auth_cleanup();
}
#endif

/* ------------------------------------------------------------------------- */
/* Timestamp and local file metadata */
/* ------------------------------------------------------------------------- */

static uerr_t set_file_timestamp(struct http_stat* hs) {
  struct stat st;
  char buf[1024];
  char* heap_tmp = NULL;
  const char* candidate = NULL;

  if (!hs || !hs->local_file)
    return RETROK;

  if (opt.backup_converted) {
    size_t filename_len = strlen(hs->local_file);
    size_t needed = filename_len + sizeof(ORIG_SFX);

    if (needed > sizeof(buf)) {
      heap_tmp = xmalloc(needed);
      memcpy(heap_tmp, hs->local_file, filename_len);
      memcpy(heap_tmp + filename_len, ORIG_SFX, sizeof(ORIG_SFX));
      if (stat(heap_tmp, &st) == 0)
        candidate = heap_tmp;
    }
    else {
      memcpy(buf, hs->local_file, filename_len);
      memcpy(buf + filename_len, ORIG_SFX, sizeof(ORIG_SFX));
      if (stat(buf, &st) == 0)
        candidate = buf;
    }
  }

  if (!candidate) {
    if (stat(hs->local_file, &st) != 0) {
      if (heap_tmp)
        xfree(heap_tmp);
      return RETROK;
    }
    candidate = hs->local_file;
  }

  hs->orig_file_name = xstrdup(candidate);
  hs->orig_file_size = st.st_size;
  hs->orig_file_tstamp = st.st_mtime;
  hs->timestamp_checked = true;

  if (heap_tmp)
    xfree(heap_tmp);

  return RETROK;
}

/* ------------------------------------------------------------------------- */
/* Legacy synchronous HTTP loop
 * This will eventually be replaced by async http_job + scheduler
 * For now it remains as a policy wrapper over http_transaction_run
 * ------------------------------------------------------------------------- */

uerr_t http_loop(const struct url* u, struct url* original_url, char** newloc, char** local_file, const char* referer, int* dt, struct url* proxy, struct iri* iri, struct transfer_context* tctx) {
  int count;
  bool got_head = false;
  bool got_name = false;
  char* tms = NULL;
  const char* tmrate = NULL;
  uerr_t err;
  uerr_t ret = TRYLIMEXC;
  time_t tmr = (time_t)-1;
  struct http_stat hstat;
  struct stat st;
  bool send_head_first = true;
  bool force_full_retrieve = false;

  (void)tctx;

  if (opt.warc_filename != NULL)
    force_full_retrieve = true;

  assert(local_file == NULL || *local_file == NULL);

  if (newloc)
    *newloc = NULL;

  if (opt.cookies)
    load_cookies();

  if (opt.ftp_glob && has_wildcards_p(u->path))
    logputs(LOG_VERBOSE, _("Warning: wildcards not supported in HTTP\n"));

  xzero(hstat);
  hstat.referer = referer;

  if (opt.output_document) {
    hstat.local_file = xstrdup(opt.output_document);
    got_name = true;
  }
  else if (!opt.content_disposition) {
    hstat.local_file = url_file_name(opt.trustservernames ? u : original_url, NULL);
    got_name = true;
  }

  if (got_name && file_exists_p(hstat.local_file, NULL) && opt.noclobber && !opt.output_document) {
    get_file_flags(hstat.local_file, dt);
    ret = RETROK;
    goto exit;
  }

  count = 0;
  *dt = 0;

  if (!opt.spider)
    send_head_first = false;

  if (opt.content_disposition && opt.always_rest)
    send_head_first = true;

  if (opt.timestamping) {
    if (opt.if_modified_since && !send_head_first && got_name && file_exists_p(hstat.local_file, NULL)) {
      *dt |= IF_MODIFIED_SINCE;
      uerr_t timestamp_err = set_file_timestamp(&hstat);
      if (timestamp_err != RETROK) {
        ret = timestamp_err;
        goto exit;
      }
    }
    else if (opt.content_disposition || file_exists_p(hstat.local_file, NULL)) {
      send_head_first = true;
    }
  }

  do {
    ++count;
    sleep_between_retrievals(count);

    tms = datetime_str(time(NULL));

    if (opt.spider && !got_head)
      logprintf(LOG_VERBOSE, _("Spider mode enabled. Check if remote file exists\n"));

    if (opt.verbose) {
      char* hurl = url_string(u, URL_AUTH_HIDE_PASSWD);

      if (count > 1) {
        char tmp[256];
        sprintf(tmp, _("(try:%2d)"), count);
        logprintf(LOG_NOTQUIET, "--%s--  %s  %s\n", tms, tmp, hurl);
      }
      else {
        logprintf(LOG_NOTQUIET, "--%s--  %s\n", tms, hurl);
      }

      xfree(hurl);
    }

    if (send_head_first && !got_head)
      *dt |= HEAD_ONLY;
    else
      *dt &= ~HEAD_ONLY;

    if (force_full_retrieve)
      hstat.restval = hstat.len;
    else if (opt.start_pos >= 0)
      hstat.restval = opt.start_pos;
    else if (opt.always_rest && got_name && stat(hstat.local_file, &st) == 0 && S_ISREG(st.st_mode))
      hstat.restval = st.st_size;
    else if (count > 1) {
      if (hstat.len < hstat.restval)
        hstat.restval -= hstat.len;
      else
        hstat.restval = hstat.len;
    }
    else {
      hstat.restval = 0;
    }

    if ((proxy && count > 1) || !opt.allow_cache)
      *dt |= SEND_NOCACHE;
    else
      *dt &= ~SEND_NOCACHE;

    err = http_transaction_run(u, original_url, &hstat, dt, proxy, iri, count);

    tms = datetime_str(time(NULL));

    if (hstat.newloc && newloc)
      *newloc = xstrdup(hstat.newloc);

    switch (err) {
      case HERR:
      case HEOF:
      case CONSOCKERR:
      case READERR:
      case WRITEFAILED:
      case RANGEERR:
      case FOPEN_EXCL_ERR:
      case GATEWAYTIMEOUT:
        printwhat(count, opt.ntry);
        continue;
      case CONERROR:
        if (opt.retry_connrefused) {
          printwhat(count, opt.ntry);
          continue;
        }
        ret = err;
        goto exit;
      case FWRITEERR:
      case FOPENERR:
        logputs(LOG_VERBOSE, "\n");
        logprintf(LOG_NOTQUIET, _("Cannot write to %s (%s)\n"), quote(hstat.local_file), strerror(errno));
        ret = err;
        goto exit;
      case HOSTERR:
        if (opt.retry_on_host_error) {
          printwhat(count, opt.ntry);
          continue;
        }
        ret = err;
        goto exit;
      case CONIMPOSSIBLE:
      case PROXERR:
      case SSLINITFAILED:
      case CONTNOTSUPPORTED:
      case VERIFCERTERR:
      case FILEBADFILE:
      case UNKNOWNATTR:
        ret = err;
        goto exit;
      case ATTRMISSING:
        logputs(LOG_VERBOSE, "\n");
        logprintf(LOG_NOTQUIET, _("Required attribute missing from Header received\n"));
        ret = err;
        goto exit;
      case AUTHFAILED:
        logputs(LOG_VERBOSE, "\n");
        logprintf(LOG_NOTQUIET, _("Username/Password Authentication Failed\n"));
        ret = err;
        goto exit;
      case WARC_ERR:
        logputs(LOG_VERBOSE, "\n");
        logprintf(LOG_NOTQUIET, _("Cannot write to WARC file\n"));
        ret = err;
        goto exit;
      case WARC_TMP_FOPENERR:
      case WARC_TMP_FWRITEERR:
        logputs(LOG_VERBOSE, "\n");
        logprintf(LOG_NOTQUIET, _("Cannot write to temporary WARC file\n"));
        ret = err;
        goto exit;
      case CONSSLERR:
        logprintf(LOG_NOTQUIET, _("Unable to establish SSL connection\n"));
        ret = err;
        goto exit;
      case UNLINKERR:
        logputs(LOG_VERBOSE, "\n");
        logprintf(LOG_NOTQUIET, _("Cannot unlink %s (%s)\n"), quote(hstat.local_file), strerror(errno));
        ret = err;
        goto exit;
      case NEWLOCATION:
      case NEWLOCATION_KEEP_POST:
        if (!newloc || !*newloc) {
          logprintf(LOG_NOTQUIET, _("ERROR: Redirection (%d) without location\n"), hstat.statcode);
          ret = WRONGCODE;
        }
        else {
          ret = err;
        }
        goto exit;
      case RETRUNNEEDED:
        ret = RETROK;
        goto exit;
      case RETROK:
        ret = RETROK;
        goto exit;
      case RETRFINISHED:
        /* treat a finished retrieval as success and exit loop */
        *dt |= RETROKF;
        ret = RETROK;
        goto exit;
      default:
        abort();
    }

    if (!(*dt & RETROKF)) {
      char* hurl = NULL;
      if (!opt.verbose) {
        hurl = url_string(u, URL_AUTH_HIDE_PASSWD);
        logprintf(LOG_NONVERBOSE, "%s:\n", hurl);
      }

      if (*dt & HEAD_ONLY && (hstat.statcode == 500 || hstat.statcode == 501)) {
        got_head = true;
        xfree(hurl);
        continue;
      }
      else if (opt.spider && !iri->utf8_encode) {
        if (!hurl)
          hurl = url_string(u, URL_AUTH_HIDE_PASSWD);
        nonexisting_url(hurl);
        logprintf(LOG_NOTQUIET, _("\nRemote file does not exist -- broken link!!!\n"));
      }
      else if (check_retry_on_http_error(hstat.statcode)) {
        printwhat(count, opt.ntry);
        xfree(hurl);
        continue;
      }
      else {
        logprintf(LOG_NOTQUIET, _("%s ERROR %d: %s\n"), tms, hstat.statcode, quotearg_style(escape_quoting_style, hstat.error));
      }
      logputs(LOG_VERBOSE, "\n");
      ret = WRONGCODE;
      xfree(hurl);
      goto exit;
    }

    if (!got_head || (opt.spider && !opt.recursive)) {
      got_head = true;

      if (opt.timestamping && !hstat.remote_time) {
        logputs(LOG_NOTQUIET, _("\nLast-modified header missing -- time-stamps turned off\n"));
      }
      else if (hstat.remote_time) {
        tmr = http_atotm(hstat.remote_time);
        if (tmr == (time_t)(-1))
          logputs(LOG_VERBOSE, _("\nLast-modified header invalid -- time-stamp ignored\n"));
      }

      if (send_head_first && opt.timestamping && hstat.orig_file_name) {
        if (hstat.remote_time && tmr != (time_t)(-1)) {
          if (hstat.orig_file_tstamp >= tmr) {
            if (hstat.contlen == -1 || hstat.orig_file_size == hstat.contlen) {
              logprintf(LOG_VERBOSE, _("\nServer file no newer than local file %s -- not retrieving\n\n"), quote(hstat.orig_file_name));
              ret = RETROK;
              goto exit;
            }
            else {
              logprintf(LOG_VERBOSE, _("\nThe sizes do not match (local %s) -- retrieving\n"), number_to_static_string(hstat.orig_file_size));
            }
          }
          else {
            force_full_retrieve = true;
            logputs(LOG_VERBOSE, _("Remote file is newer, retrieving\n"));
          }

          logputs(LOG_VERBOSE, "\n");
        }

        hstat.timestamp_checked = true;
      }
    }
  } while (!opt.ntry || (count < opt.ntry));

  if (count >= opt.ntry)
    ret = TRYLIMEXC;

exit:
  if (ret == RETROK && opt.verbose && !opt.spider && !(*dt & RETROKF)) {
    if (!tmrate)
      tmrate = "";
    logprintf(LOG_VERBOSE, _("%s (%s) - %s saved [%s/%s]\n\n"), tms, tmrate, quote(hstat.local_file), number_to_static_string(hstat.len), number_to_static_string(hstat.len));
  }

  {
    char* lf = hstat.local_file;
    hstat.local_file = NULL;
    free_hstat(&hstat);

    if (local_file)
      *local_file = lf;
    else
      xfree(lf);
  }

  return ret;
}
