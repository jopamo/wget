/* Handling of recursive HTTP retrieving
 * src/recur.c
 */

#include "wget.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "convert.h"
#include "css-url.h"
#include "exits.h"
#include "ftp.h"
#include "hash.h"
#include "host.h"
#include "html-url.h"
#include "recur.h"
#include "res.h"
#include "retr.h"
#include "spider.h"
#include "url.h"
#include "utils.h"

/* Functions for maintaining the URL queue */

struct queue_element {
  const char* url;            /* URL to download */
  const char* referer;        /* referring document */
  int depth;                  /* recursion depth */
  bool html_allowed;          /* allowed to treat document as HTML */
  struct iri* iri;            /* IRI context */
  bool css_allowed;           /* allowed to treat document as CSS */
  struct queue_element* next; /* next element in queue */
};

struct url_queue {
  struct queue_element* head;
  struct queue_element* tail;
  int count;
  int maxcount;
};

static struct url_queue* url_queue_new(void) {
  struct url_queue* queue = xnew0(struct url_queue);
  return queue;
}

static void url_queue_delete(struct url_queue* queue) {
  xfree(queue);
}

/* Enqueue a URL in FIFO order */

static void url_enqueue(struct url_queue* queue, struct iri* i, const char* url, const char* referer, int depth, bool html_allowed, bool css_allowed) {
  struct queue_element* qel = xnew(struct queue_element);
  qel->iri = i;
  qel->url = url;
  qel->referer = referer;
  qel->depth = depth;
  qel->html_allowed = html_allowed;
  qel->css_allowed = css_allowed;
  qel->next = NULL;

  ++queue->count;
  if (queue->count > queue->maxcount)
    queue->maxcount = queue->count;

  DEBUGP(("Enqueuing %s at depth %d\n", quotearg_n_style(0, escape_quoting_style, url), depth));
  DEBUGP(("Queue count %d, maxcount %d\n", queue->count, queue->maxcount));

  if (i)
    DEBUGP(("[IRI Enqueuing %s with %s\n", quote_n(0, url), i->uri_encoding ? quote_n(1, i->uri_encoding) : "None"));

  if (queue->tail)
    queue->tail->next = qel;
  queue->tail = qel;

  if (!queue->head)
    queue->head = queue->tail;
}

/* Dequeue the next URL
   Returns true if an element was dequeued, false if the queue is empty
 */

static bool url_dequeue(struct url_queue* queue, struct iri** i, const char** url, const char** referer, int* depth, bool* html_allowed, bool* css_allowed) {
  struct queue_element* qel = queue->head;

  if (!qel)
    return false;

  queue->head = queue->head->next;
  if (!queue->head)
    queue->tail = NULL;

  *i = qel->iri;
  *url = qel->url;
  *referer = qel->referer;
  *depth = qel->depth;
  *html_allowed = qel->html_allowed;
  *css_allowed = qel->css_allowed;

  --queue->count;

  DEBUGP(("Dequeuing %s at depth %d\n", quotearg_n_style(0, escape_quoting_style, qel->url), qel->depth));
  DEBUGP(("Queue count %d, maxcount %d\n", queue->count, queue->maxcount));

  xfree(qel);
  return true;
}

static void blacklist_add(struct hash_table* blacklist, const char* url) {
  char* url_unescaped = xstrdup(url);

  url_unescape(url_unescaped);
  string_set_add(blacklist, url_unescaped);
  xfree(url_unescaped);
}

static bool blacklist_contains(struct hash_table* blacklist, const char* url) {
  char* url_unescaped = xstrdup(url);
  bool present;

  url_unescape(url_unescaped);
  present = string_set_contains(blacklist, url_unescaped) != 0;
  xfree(url_unescaped);

  return present;
}

typedef enum {
  WG_RR_SUCCESS,
  WG_RR_BLACKLIST,
  WG_RR_NOTHTTPS,
  WG_RR_NONHTTP,
  WG_RR_ABSOLUTE,
  WG_RR_DOMAIN,
  WG_RR_PARENT,
  WG_RR_LIST,
  WG_RR_REGEX,
  WG_RR_RULES,
  WG_RR_SPANNEDHOST,
  WG_RR_ROBOTS
} reject_reason;

static reject_reason download_child(const struct urlpos*, struct url*, int, struct url*, struct hash_table*, struct iri*);
static reject_reason descend_redirect(const char*, struct url*, int, struct url*, struct hash_table*, struct iri*);
static void write_reject_log_header(FILE*);
static void write_reject_log_reason(FILE*, reject_reason, const struct url*, const struct url*);

/* Breadth-first recursive retrieval starting from START_URL_PARSED */

uerr_t retrieve_tree(struct url* start_url_parsed, struct iri* pi) {
  uerr_t status = RETROK;

  struct url_queue* queue;
  struct hash_table* blacklist;

  struct iri* i = iri_new();

  FILE* rejectedlog = NULL;

  if (pi) {
#define COPYSTR(x) (x) ? xstrdup(x) : NULL;
    i->uri_encoding = COPYSTR(pi->uri_encoding);
    i->content_encoding = COPYSTR(pi->content_encoding);
    i->utf8_encode = pi->utf8_encode;
#undef COPYSTR
  }
#ifdef ENABLE_IRI
  else
    set_uri_encoding(i, opt.locale, true);
#endif

  queue = url_queue_new();
  blacklist = make_string_hash_table(0);

  /* Enqueue the starting URL using its canonical form */
  url_enqueue(queue, i, xstrdup(start_url_parsed->url), NULL, 0, true, false);
  blacklist_add(blacklist, start_url_parsed->url);

  if (opt.rejected_log) {
    rejectedlog = fopen(opt.rejected_log, "w");
    write_reject_log_header(rejectedlog);
    if (!rejectedlog)
      logprintf(LOG_NOTQUIET, "%s: %s\n", opt.rejected_log, strerror(errno));
  }

  while (1) {
    bool descend = false;
    char *url, *referer, *file = NULL;
    int depth;
    bool html_allowed;
    bool css_allowed;
    bool is_css = false;
    bool dash_p_leaf_HTML = false;

    if (opt.quota && total_downloaded_bytes > opt.quota)
      break;
    if (status == FWRITEERR)
      break;

    if (!url_dequeue(queue, (struct iri**)&i, (const char**)&url, (const char**)&referer, &depth, &html_allowed, &css_allowed))
      break;

    /* Avoid downloading the same URL twice
       Still allow revisiting it from a different root to process children again
     */
    if (dl_url_file_map && hash_table_contains(dl_url_file_map, url)) {
      bool is_css_bool;

      file = xstrdup(hash_table_get(dl_url_file_map, url));

      DEBUGP(("Already downloaded \"%s\", reusing it from \"%s\"\n", url, file));

      if ((is_css_bool = (css_allowed && downloaded_css_set && string_set_contains(downloaded_css_set, file))) ||
          (html_allowed && downloaded_html_set && string_set_contains(downloaded_html_set, file))) {
        descend = true;
        is_css = is_css_bool;
      }
    }
    else {
      int dt = 0;
      int url_err;
      char* redirected = NULL;
      struct url* url_parsed = url_parse(url, &url_err, i, true);

      if (!url_parsed) {
        logprintf(LOG_NOTQUIET, "%s: %s.\n", url, url_error(url_err));
        inform_exit_status(URLERROR);
      }
      else {
        struct transfer_context tctx;
        transfer_context_prepare(&tctx, &opt, url);
        status = retrieve_url(url_parsed, url, &file, &redirected, referer, &dt, false, i, true, &tctx);
        transfer_context_free(&tctx);

        if (html_allowed && file && status == RETROK && (dt & RETROKF) && (dt & TEXTHTML)) {
          descend = true;
          is_css = false;
        }

        /* css_allowed can override content type because many servers mislabel CSS */
        if (file && status == RETROK && (dt & RETROKF) && ((dt & TEXTCSS) || css_allowed)) {
          descend = true;
          is_css = true;
        }

        if (redirected) {
          if (descend) {
            reject_reason r = descend_redirect(redirected, url_parsed, depth, start_url_parsed, blacklist, i);
            if (r == WG_RR_SUCCESS) {
              blacklist_add(blacklist, url);
            }
            else {
              write_reject_log_reason(rejectedlog, r, url_parsed, start_url_parsed);
              descend = false;
            }
          }

          xfree(url);
          url = redirected;
        }
        else {
          xfree(url);
          url = xstrdup(url_parsed->url);
        }
        url_free(url_parsed);
      }
    }

    if (opt.spider)
      visited_url(url, referer);

    if (descend && depth >= opt.reclevel && opt.reclevel != INFINITE_RECURSION) {
      if (opt.page_requisites && (depth == opt.reclevel || depth == opt.reclevel + 1)) {
        /* With -p we can exceed the depth for inline requisites
           Allow one extra pseudo level for frame containers */
        dash_p_leaf_HTML = true;
      }
      else {
        DEBUGP(("Not descending further; at depth %d, max. %d\n", depth, opt.reclevel));
        descend = false;
      }
    }

    /* For HTML and CSS, parse and enqueue embedded links */

    if (descend) {
      bool meta_disallow_follow = false;
      struct urlpos* children = is_css ? get_urls_css_file(file, url) : get_urls_html(file, url, &meta_disallow_follow, i);

      if (opt.use_robots && meta_disallow_follow) {
        logprintf(LOG_VERBOSE, _("nofollow attribute found in %s. Will not follow any links on this page\n"), file);
        free_urlpos(children);
        children = NULL;
      }

      if (children) {
        struct urlpos* child = children;
        struct url* url_parsed = url_parse(url, NULL, i, true);
        struct iri* ci;
        char* referer_url = url;
        bool strip_auth;

        assert(url_parsed != NULL);

        if (!url_parsed)
          continue;

        strip_auth = (url_parsed && url_parsed->user);

        if (strip_auth)
          referer_url = url_string(url_parsed, URL_AUTH_HIDE);

        for (; child; child = child->next) {
          reject_reason r;

          if (child->ignore_when_downloading) {
            DEBUGP(("Not following due to 'ignore' flag: %s\n", child->url->url));
            continue;
          }

          if (dash_p_leaf_HTML && !child->link_inline_p) {
            DEBUGP(("Not following due to 'link inline' flag: %s\n", child->url->url));
            continue;
          }

          r = download_child(child, url_parsed, depth, start_url_parsed, blacklist, i);
          if (r == WG_RR_SUCCESS) {
            ci = iri_new();
            set_uri_encoding(ci, i->content_encoding, false);
            url_enqueue(queue, ci, xstrdup(child->url->url), xstrdup(referer_url), depth + 1, child->link_expect_html, child->link_expect_css);
            blacklist_add(blacklist, child->url->url);
          }
          else {
            write_reject_log_reason(rejectedlog, r, child->url, url_parsed);
          }
        }

        if (strip_auth)
          xfree(referer_url);
        url_free(url_parsed);
        free_urlpos(children);
      }
    }

    if (file && (opt.delete_after || opt.spider || !acceptable(file))) {
      DEBUGP(("Removing file due to %s in recursive_retrieve():\n", opt.delete_after ? "--delete-after" : (opt.spider ? "--spider" : "recursive rejection criteria")));
      logprintf(LOG_VERBOSE, (opt.delete_after || opt.spider ? _("Removing %s.\n") : _("Removing %s since it should be rejected.\n")), file);
      if (unlink(file))
        logprintf(LOG_NOTQUIET, "unlink: %s\n", strerror(errno));
      logputs(LOG_VERBOSE, "\n");
      register_delete_file(file);
    }

    xfree(url);
    xfree(referer);
    xfree(file);
    iri_free(i);
  }

  if (rejectedlog) {
    fclose(rejectedlog);
    rejectedlog = NULL;
  }

  /* Drain and free any queued entries on premature exit */
  {
    char *d1, *d2;
    int d3;
    bool d4;
    bool d5;
    struct iri* d6;
    while (url_dequeue(queue, (struct iri**)&d6, (const char**)&d1, (const char**)&d2, &d3, &d4, &d5)) {
      iri_free(d6);
      xfree(d1);
      xfree(d2);
    }
  }
  url_queue_delete(queue);

  string_set_free(blacklist);

  if (opt.quota && total_downloaded_bytes > opt.quota)
    return QUOTEXC;
  if (status == FWRITEERR)
    return FWRITEERR;
  return RETROK;
}

/* Decide whether a discovered URL should be enqueued for download */

static reject_reason download_child(const struct urlpos* upos, struct url* parent, int depth, struct url* start_url_parsed, struct hash_table* blacklist, struct iri* iri) {
  struct url* u = upos->url;
  const char* url = u->url;
  bool u_scheme_like_http;
  reject_reason reason = WG_RR_SUCCESS;

  DEBUGP(("Deciding whether to enqueue \"%s\"\n", url));

  if (blacklist_contains(blacklist, url)) {
    if (opt.spider) {
      char* referrer = url_string(parent, URL_AUTH_HIDE_PASSWD);
      DEBUGP(("download_child: parent->url is: %s\n", quote(parent->url)));
      visited_url(url, referrer);
      xfree(referrer);
    }
    DEBUGP(("Already on the black list\n"));
    reason = WG_RR_BLACKLIST;
    goto out;
  }

#ifdef HAVE_SSL
  if (opt.https_only && u->scheme != SCHEME_HTTPS) {
    DEBUGP(("Not following non-HTTPS links\n"));
    reason = WG_RR_NOTHTTPS;
    goto out;
  }
#endif

  u_scheme_like_http = schemes_are_similar_p(u->scheme, SCHEME_HTTP);

  if (!u_scheme_like_http && !((u->scheme == SCHEME_FTP
#ifdef HAVE_SSL
                                || u->scheme == SCHEME_FTPS
#endif
                                ) &&
                               opt.follow_ftp)) {
    DEBUGP(("Not following non-HTTP schemes\n"));
    reason = WG_RR_NONHTTP;
    goto out;
  }

  if (u_scheme_like_http && opt.relative_only && !upos->link_relative_p) {
    DEBUGP(("It doesn't really look like a relative link\n"));
    reason = WG_RR_ABSOLUTE;
    goto out;
  }

  if (!accept_domain(u)) {
    DEBUGP(("The domain was not accepted\n"));
    reason = WG_RR_DOMAIN;
    goto out;
  }

  if (opt.no_parent && schemes_are_similar_p(u->scheme, start_url_parsed->scheme) && 0 == strcasecmp(u->host, start_url_parsed->host) &&
      (u->scheme != start_url_parsed->scheme || u->port == start_url_parsed->port) && !(opt.page_requisites && upos->link_inline_p)) {
    if (!subdir_p(start_url_parsed->dir, u->dir)) {
      DEBUGP(("Going to \"%s\" would escape \"%s\" with no_parent on\n", u->dir, start_url_parsed->dir));
      reason = WG_RR_PARENT;
      goto out;
    }
  }

  if (opt.includes || opt.excludes) {
    if (!accdir(u->dir)) {
      DEBUGP(("%s (%s) is excluded/not-included\n", url, u->dir));
      reason = WG_RR_LIST;
      goto out;
    }
  }
  if (!accept_url(url)) {
    DEBUGP(("%s is excluded/not-included through regex\n", url));
    reason = WG_RR_REGEX;
    goto out;
  }

  if (u->file[0] != '\0' && !(has_html_suffix_p(u->file) && (opt.reclevel == INFINITE_RECURSION || depth < opt.reclevel - 1 || opt.page_requisites))) {
    if (!acceptable(u->file)) {
      DEBUGP(("%s (%s) does not match acc/rej rules\n", url, u->file));
      reason = WG_RR_RULES;
      goto out;
    }
  }

  if (schemes_are_similar_p(u->scheme, parent->scheme) && !opt.spanhost && 0 != strcasecmp(parent->host, u->host)) {
    DEBUGP(("This is not the same hostname as the parent's (%s and %s)\n", u->host, parent->host));
    reason = WG_RR_SPANNEDHOST;
    goto out;
  }

  if (opt.use_robots && u_scheme_like_http) {
    struct robot_specs* specs = res_get_specs(u->host, u->port);
    if (!specs) {
      char* rfile;
      if (res_retrieve_file(url, &rfile, iri)) {
        specs = res_parse_from_file(rfile);

        if (opt.delete_after || opt.spider || match_tail(rfile, ".tmp", false)) {
          logprintf(LOG_VERBOSE, _("Removing %s.\n"), rfile);
          if (unlink(rfile))
            logprintf(LOG_NOTQUIET, "unlink: %s\n", strerror(errno));
        }

        xfree(rfile);
      }
      else {
        specs = res_parse("", 0);
      }
      res_register_specs(u->host, u->port, specs);
    }

    if (!res_match_path(specs, u->path)) {
      DEBUGP(("Not following %s because robots.txt forbids it\n", url));
      blacklist_add(blacklist, url);
      reason = WG_RR_ROBOTS;
      goto out;
    }
  }

out:

  if (reason == WG_RR_SUCCESS)
    DEBUGP(("Decided to load it\n"));
  else
    DEBUGP(("Decided NOT to load it\n"));

  return reason;
}

/* Determine whether to descend into a URL reached via redirect */

static reject_reason descend_redirect(const char* redirected, struct url* orig_parsed, int depth, struct url* start_url_parsed, struct hash_table* blacklist, struct iri* iri) {
  struct url* new_parsed;
  struct urlpos* upos;
  reject_reason reason;

  assert(orig_parsed != NULL);

  new_parsed = url_parse(redirected, NULL, NULL, false);
  assert(new_parsed != NULL);

  upos = xnew0(struct urlpos);
  upos->url = new_parsed;

  reason = download_child(upos, orig_parsed, depth, start_url_parsed, blacklist, iri);

  if (reason == WG_RR_SUCCESS) {
    blacklist_add(blacklist, upos->url->url);
  }
  else if (reason == WG_RR_LIST || reason == WG_RR_REGEX) {
    DEBUGP(("Ignoring decision for redirects, decided to load it\n"));
    blacklist_add(blacklist, upos->url->url);
    reason = WG_RR_SUCCESS;
  }
  else {
    DEBUGP(("Redirection \"%s\" failed the test\n", redirected));
  }

  url_free(new_parsed);
  xfree(upos);

  return reason;
}

static void write_reject_log_header(FILE* f) {
  if (!f)
    return;

  fprintf(f,
          "REASON\t"
          "U_URL\tU_SCHEME\tU_HOST\tU_PORT\tU_PATH\tU_PARAMS\tU_QUERY\tU_FRAGMENT\t"
          "P_URL\tP_SCHEME\tP_HOST\tP_PORT\tP_PATH\tP_PARAMS\tP_QUERY\tP_FRAGMENT\n");
}

static void write_reject_log_url(FILE* fp, const struct url* url) {
  const char* escaped_str;
  const char* scheme_str;

  if (!fp)
    return;

  escaped_str = url_escape(url->url);

  switch (url->scheme) {
    case SCHEME_HTTP:
      scheme_str = "SCHEME_HTTP";
      break;
#ifdef HAVE_SSL
    case SCHEME_HTTPS:
      scheme_str = "SCHEME_HTTPS";
      break;
    case SCHEME_FTPS:
      scheme_str = "SCHEME_FTPS";
      break;
#endif
    case SCHEME_FTP:
      scheme_str = "SCHEME_FTP";
      break;
    default:
      scheme_str = "SCHEME_INVALID";
      break;
  }

  fprintf(fp, "%s\t%s\t%s\t%i\t%s\t%s\t%s\t%s", escaped_str, scheme_str, url->host, url->port, url->path, url->params ? url->params : "", url->query ? url->query : "",
          url->fragment ? url->fragment : "");

  xfree(escaped_str);
}

/* Log why a URL was rejected along with its parent context */

static void write_reject_log_reason(FILE* fp, reject_reason reason, const struct url* url, const struct url* parent) {
  const char* reason_str;

  if (!fp)
    return;

  switch (reason) {
    case WG_RR_SUCCESS:
      reason_str = "SUCCESS";
      break;
    case WG_RR_BLACKLIST:
      reason_str = "BLACKLIST";
      break;
    case WG_RR_NOTHTTPS:
      reason_str = "NOTHTTPS";
      break;
    case WG_RR_NONHTTP:
      reason_str = "NONHTTP";
      break;
    case WG_RR_ABSOLUTE:
      reason_str = "ABSOLUTE";
      break;
    case WG_RR_DOMAIN:
      reason_str = "DOMAIN";
      break;
    case WG_RR_PARENT:
      reason_str = "PARENT";
      break;
    case WG_RR_LIST:
      reason_str = "LIST";
      break;
    case WG_RR_REGEX:
      reason_str = "REGEX";
      break;
    case WG_RR_RULES:
      reason_str = "RULES";
      break;
    case WG_RR_SPANNEDHOST:
      reason_str = "SPANNEDHOST";
      break;
    case WG_RR_ROBOTS:
      reason_str = "ROBOTS";
      break;
    default:
      reason_str = "UNKNOWN";
      break;
  }

  fprintf(fp, "%s\t", reason_str);
  write_reject_log_url(fp, url);
  fprintf(fp, "\t");
  write_reject_log_url(fp, parent);
  fprintf(fp, "\n");
}
