/* URL handling.
 * src/url.c
 */

#include "wget.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "utils.h"
#include "url.h"
#include "host.h"
#include "c-strcase.h"
#include "c-ctype.h"

#ifdef HAVE_ICONV
#include <iconv.h>
#endif
#include <langinfo.h>

#ifdef TESTING
#include "../tests/unit-tests.h"
#endif

enum { scm_disabled = 1, scm_has_params = 2, scm_has_query = 4, scm_has_fragment = 8 };

struct scheme_data {
  const char* name;
  const char* leading_string;
  int default_port;
  int flags;
};

static struct scheme_data supported_schemes[] = {{"http", "http://", DEFAULT_HTTP_PORT, scm_has_query | scm_has_fragment},
#ifdef HAVE_SSL
                                                 {"https", "https://", DEFAULT_HTTPS_PORT, scm_has_query | scm_has_fragment},
#endif
                                                 {"ftp", "ftp://", DEFAULT_FTP_PORT, scm_has_params | scm_has_fragment},
#ifdef HAVE_SSL
                                                 {"ftps", "ftps://", DEFAULT_FTP_PORT, scm_has_params | scm_has_fragment},
#endif
                                                 {NULL, NULL, -1, 0}};

static bool path_simplify(enum url_scheme, char*);

enum { urlchr_reserved = 1, urlchr_unsafe = 2 };

#define urlchr_test(c, mask) (urlchr_table[(unsigned char)(c)] & (mask))
#define URL_RESERVED_CHAR(c) urlchr_test(c, urlchr_reserved)
#define URL_UNSAFE_CHAR(c) urlchr_test(c, urlchr_unsafe)

#define R urlchr_reserved
#define U urlchr_unsafe
#define RU (R | U)

static const unsigned char urlchr_table[256] = {
    U,  U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U,  U, U,  U, U, U, 0, U, RU, R, U, R, 0, 0, 0, 0, R, R, 0, 0, R, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, RU, R, U, R, U, R,
    RU, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, RU, U, RU, U, 0, U, 0, 0, 0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  U, U, U, 0, U,

    U,  U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U,  U, U,  U, U, U, U, U, U,  U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U,  U, U, U,

    U,  U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U,  U, U,  U, U, U, U, U, U,  U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U, U,  U, U, U};
#undef R
#undef U
#undef RU

static void url_unescape_1(char* s, unsigned char mask) {
  unsigned char* t = (unsigned char*)s;
  unsigned char* h = (unsigned char*)s;

  for (; *h; h++, t++) {
    if (*h != '%') {
    copychar:
      *t = *h;
    }
    else {
      unsigned char c;

      if (!h[1] || !h[2] || !(c_isxdigit(h[1]) && c_isxdigit(h[2])))
        goto copychar;
      c = X2DIGITS_TO_NUM(h[1], h[2]);
      if (urlchr_test(c, mask))
        goto copychar;

      if (c == '\0')
        goto copychar;
      *t = c;
      h += 2;
    }
  }
  *t = '\0';
}

void url_unescape(char* s) {
  url_unescape_1(s, 0);
}

void url_unescape_except_reserved(char* s) {
  url_unescape_1(s, urlchr_reserved);
}

static char* url_escape_1(const char* s, unsigned char mask, bool allow_passthrough) {
  const char* p1;
  char *p2, *newstr;
  int newlen;
  int addition = 0;

  for (p1 = s; *p1; p1++)
    if (urlchr_test(*p1, mask))
      addition += 2;

  if (!addition)
    return allow_passthrough ? (char*)s : xstrdup(s);

  newlen = (int)(p1 - s) + addition;
  newstr = xmalloc((size_t)newlen + 1);

  p1 = s;
  p2 = newstr;
  while (*p1) {
    if (urlchr_test(*p1, mask)) {
      unsigned char c = (unsigned char)*p1++;
      *p2++ = '%';
      *p2++ = XNUM_TO_DIGIT(c >> 4);
      *p2++ = XNUM_TO_DIGIT(c & 0xf);
    }
    else {
      *p2++ = *p1++;
    }
  }
  assert(p2 - newstr == newlen);
  *p2 = '\0';

  return newstr;
}

char* url_escape(const char* s) {
  return url_escape_1(s, urlchr_unsafe, false);
}

char* url_escape_unsafe_and_reserved(const char* s) {
  return url_escape_1(s, urlchr_unsafe | urlchr_reserved, false);
}

static char* url_escape_allow_passthrough(const char* s) {
  return url_escape_1(s, urlchr_unsafe, true);
}

static inline bool char_needs_escaping(const char* p) {
  if (*p == '%') {
    if (c_isxdigit(*(p + 1)) && c_isxdigit(*(p + 2)))
      return false;
    return true;
  }
  else if (URL_UNSAFE_CHAR(*p) && !URL_RESERVED_CHAR(*p)) {
    return true;
  }
  return false;
}

static char* reencode_escapes(const char* s) {
  const char* p1;
  char *newstr, *p2;
  int oldlen, newlen;
  int encode_count = 0;

  for (p1 = s; *p1; p1++)
    if (char_needs_escaping(p1))
      ++encode_count;

  if (!encode_count)
    return (char*)s;

  oldlen = (int)(p1 - s);

  newlen = oldlen + 2 * encode_count;
  newstr = xmalloc((size_t)newlen + 1);

  p1 = s;
  p2 = newstr;

  while (*p1) {
    if (char_needs_escaping(p1)) {
      unsigned char c = (unsigned char)*p1++;
      *p2++ = '%';
      *p2++ = XNUM_TO_DIGIT(c >> 4);
      *p2++ = XNUM_TO_DIGIT(c & 0xf);
    }
    else {
      *p2++ = *p1++;
    }
  }

  *p2 = '\0';
  assert(p2 - newstr == newlen);
  return newstr;
}

enum url_scheme url_scheme(const char* url) {
  if (!url)
    return SCHEME_INVALID;

  for (int i = 0; supported_schemes[i].leading_string; i++) {
    const char* lead = supported_schemes[i].leading_string;
    size_t lead_len = strlen(lead);
    if (c_strncasecmp(url, lead, lead_len) == 0) {
      if (!(supported_schemes[i].flags & scm_disabled))
        return (enum url_scheme)i;
      return SCHEME_INVALID;
    }
  }

  return SCHEME_INVALID;
}

#define SCHEME_CHAR(ch) (c_isalnum(ch) || (ch) == '-' || (ch) == '+')

bool url_has_scheme(const char* url) {
  const char* p = url;

  if (!p || !*p || !SCHEME_CHAR(*p))
    return false;
  ++p;

  while (*p && SCHEME_CHAR(*p))
    ++p;

  return *p == ':';
}

bool url_valid_scheme(const char* url) {
  enum url_scheme scheme = url_scheme(url);
  return scheme != SCHEME_INVALID;
}

int scheme_default_port(enum url_scheme scheme) {
  return supported_schemes[scheme].default_port;
}

void scheme_disable(enum url_scheme scheme) {
  supported_schemes[scheme].flags |= scm_disabled;
}

const char* scheme_leading_string(enum url_scheme scheme) {
  return supported_schemes[scheme].leading_string;
}

static const char* url_skip_credentials(const char* url) {
  static const char* allowed = "-_.!~*'();:&=+$,";

  for (const char* p = url; *p; p++) {
    if (c_isalnum(*p))
      continue;

    if (strchr(allowed, *p))
      continue;

    if (*p == '%' && c_isxdigit(p[1]) && c_isxdigit(p[2])) {
      p += 2;
      continue;
    }

    if (*p == '@')
      return p + 1;

    break;
  }

  return url;
}

static bool parse_credentials(const char* beg, const char* end, char** user, char** passwd) {
  char* colon;
  const char* userend;

  if (beg == end)
    return false;

  colon = memchr(beg, ':', (size_t)(end - beg));
  if (colon == beg)
    return false;

  if (colon) {
    *passwd = strdupdelim(colon + 1, end);
    userend = colon;
    url_unescape(*passwd);
  }
  else {
    *passwd = NULL;
    userend = end;
  }
  *user = strdupdelim(beg, userend);
  url_unescape(*user);
  return true;
}

static bool is_valid_port(const char* p) {
  unsigned port = (unsigned)atoi(p);
  if (port == 0 || port > 65535)
    return false;

  int digits = (int)strspn(p, "0123456789");
  return digits && (p[digits] == '/' || p[digits] == '\0');
}

char* maybe_prepend_scheme(const char* url) {
  if (!url)
    return NULL;

  if (url_scheme(url) != SCHEME_INVALID)
    return NULL;

  const char* p = strchr(url, ':');
  if (p == url)
    return NULL;

  if (p && p[0] == ':' && p[1] == '/' && p[2] == '/')
    return NULL;

  if (p && p[0] == ':' && !is_valid_port(p + 1))
    return NULL;

  logprintf(LOG_VERBOSE, _("Prepended http:// to '%s'\n"), url);
  return aprintf("http://%s", url);
}

static void split_path(const char*, char**, char**);

static inline char* strpbrk_or_eos(const char* s, const char* accept) {
  char* p = strpbrk(s, accept);
  if (!p)
    p = strchr(s, '\0');
  return p;
}

static bool lowercase_str(char* str) {
  bool changed = false;
  for (; *str; str++)
    if (c_isupper(*str)) {
      changed = true;
      *str = c_tolower(*str);
    }
  return changed;
}

static const char* init_seps(enum url_scheme scheme) {
  static char seps[8] = ":/";
  char* p = seps + 2;
  int flags = supported_schemes[scheme].flags;

  if (flags & scm_has_params)
    *p++ = ';';
  if (flags & scm_has_query)
    *p++ = '?';
  if (flags & scm_has_fragment)
    *p++ = '#';
  *p = '\0';
  return seps;
}

enum {
  PE_NO_ERROR = 0,
  PE_UNSUPPORTED_SCHEME,
  PE_UNSUPPORTED_SCHEME_HTTPS,
  PE_UNSUPPORTED_SCHEME_FTPS,
  PE_MISSING_SCHEME,
  PE_INVALID_HOST_NAME,
  PE_BAD_PORT_NUMBER,
  PE_INVALID_USER_NAME,
  PE_UNTERMINATED_IPV6_ADDRESS,
  PE_IPV6_NOT_SUPPORTED,
  PE_INVALID_IPV6_ADDRESS
};

static const char* parse_errors[] = {[PE_NO_ERROR] = N_("No error"),
                                     [PE_UNSUPPORTED_SCHEME] = N_("Unsupported scheme"),
                                     [PE_UNSUPPORTED_SCHEME_HTTPS] = N_("HTTPS support not compiled in"),
                                     [PE_UNSUPPORTED_SCHEME_FTPS] = N_("FTPS support not compiled in"),
                                     [PE_MISSING_SCHEME] = N_("Scheme missing"),
                                     [PE_INVALID_HOST_NAME] = N_("Invalid host name"),
                                     [PE_BAD_PORT_NUMBER] = N_("Bad port number"),
                                     [PE_INVALID_USER_NAME] = N_("Invalid user name"),
                                     [PE_UNTERMINATED_IPV6_ADDRESS] = N_("Unterminated IPv6 numeric address"),
                                     [PE_IPV6_NOT_SUPPORTED] = N_("IPv6 addresses not supported"),
                                     [PE_INVALID_IPV6_ADDRESS] = N_("Invalid IPv6 numeric address")};

struct url* url_parse(const char* url, int* error, struct iri* iri, bool percent_encode) {
  struct url* u;
  const char* p;
  bool path_modified, host_modified;

  enum url_scheme scheme;
  const char* seps;

  const char *uname_b, *uname_e;
  const char *host_b, *host_e;
  const char *path_b, *path_e;
  const char *params_b, *params_e;
  const char *query_b, *query_e;
  const char *fragment_b, *fragment_e;

  int port;
  char *user = NULL, *passwd = NULL;

  const char* url_encoded = NULL;

  int error_code;

  if (!url) {
    if (error)
      *error = PE_MISSING_SCHEME;
    return NULL;
  }

  scheme = url_scheme(url);
  if (scheme == SCHEME_INVALID) {
    if (!url_has_scheme(url))
      error_code = PE_MISSING_SCHEME;
    else if (!c_strncasecmp(url, "https:", 6))
      error_code = PE_UNSUPPORTED_SCHEME_HTTPS;
    else if (!c_strncasecmp(url, "ftps:", 5))
      error_code = PE_UNSUPPORTED_SCHEME_FTPS;
    else
      error_code = PE_UNSUPPORTED_SCHEME;
    goto error;
  }

  url_encoded = url;

  if (iri && iri->utf8_encode) {
    char* new_url = NULL;

    iri->utf8_encode = remote_to_utf8(iri, iri->orig_url ? iri->orig_url : url, &new_url);
    if (!iri->utf8_encode)
      new_url = NULL;
    else {
      xfree(iri->orig_url);
      iri->orig_url = xstrdup(url);
      url_encoded = reencode_escapes(new_url);
      if (url_encoded != new_url)
        xfree(new_url);
      percent_encode = false;
    }
  }

  if (percent_encode)
    url_encoded = reencode_escapes(url);

  p = url_encoded;
  p += strlen(supported_schemes[scheme].leading_string);
  uname_b = p;
  p = url_skip_credentials(p);
  uname_e = p;

  path_b = path_e = NULL;
  params_b = params_e = NULL;
  query_b = query_e = NULL;
  fragment_b = fragment_e = NULL;

  seps = init_seps(scheme);

  host_b = p;

  if (*p == '[') {
    host_b = p + 1;
    host_e = strchr(host_b, ']');

    if (!host_e) {
      error_code = PE_UNTERMINATED_IPV6_ADDRESS;
      goto error;
    }

#ifdef ENABLE_IPV6
    if (!is_valid_ipv6_address(host_b, host_e)) {
      error_code = PE_INVALID_IPV6_ADDRESS;
      goto error;
    }

    p = host_e + 1;
#else
    error_code = PE_IPV6_NOT_SUPPORTED;
    goto error;
#endif

    if (!strchr(seps, *p)) {
      error_code = PE_INVALID_HOST_NAME;
      goto error;
    }
  }
  else {
    p = strpbrk_or_eos(p, seps);
    host_e = p;
  }
  ++seps;

  if (host_b == host_e) {
    error_code = PE_INVALID_HOST_NAME;
    goto error;
  }

  port = scheme_default_port(scheme);
  if (*p == ':') {
    const char *port_b, *port_e, *pp;

    ++p;
    port_b = p;
    p = strpbrk_or_eos(p, seps);
    port_e = p;

    if (port_b != port_e) {
      port = 0;
      for (pp = port_b; pp < port_e; pp++) {
        if (!c_isdigit(*pp)) {
          error_code = PE_BAD_PORT_NUMBER;
          goto error;
        }
        port = 10 * port + (*pp - '0');
        if (port > 0xffff) {
          error_code = PE_BAD_PORT_NUMBER;
          goto error;
        }
      }
    }
  }
  ++seps;

#define GET_URL_PART(sepchar, var)                          \
  do {                                                      \
    if (*p == (sepchar))                                    \
      var##_b = ++p, var##_e = p = strpbrk_or_eos(p, seps); \
    ++seps;                                                 \
  } while (0)

  GET_URL_PART('/', path);
  if (supported_schemes[scheme].flags & scm_has_params)
    GET_URL_PART(';', params);
  if (supported_schemes[scheme].flags & scm_has_query)
    GET_URL_PART('?', query);
  if (supported_schemes[scheme].flags & scm_has_fragment)
    GET_URL_PART('#', fragment);

#undef GET_URL_PART
  assert(*p == 0);

  if (uname_b != uname_e) {
    if (!parse_credentials(uname_b, uname_e - 1, &user, &passwd)) {
      error_code = PE_INVALID_USER_NAME;
      goto error;
    }
  }

  u = xnew0(struct url);
  u->scheme = scheme;
  u->host = strdupdelim(host_b, host_e);
  u->port = port;
  u->user = user;
  u->passwd = passwd;

  u->path = strdupdelim(path_b, path_e);
  path_modified = path_simplify(scheme, u->path);
  split_path(u->path, &u->dir, &u->file);

  host_modified = lowercase_str(u->host);

  if (strchr(u->host, '%')) {
    url_unescape(u->host);
    host_modified = true;

    for (p = u->host; *p; p++) {
      if (c_iscntrl(*p)) {
        url_free(u);
        error_code = PE_INVALID_HOST_NAME;
        goto error;
      }
    }

    if (opt.enable_iri && iri) {
      char* new = idn_encode(iri, u->host);
      if (new) {
        xfree(u->host);
        u->host = new;
        host_modified = true;
      }
    }
  }

  if (params_b)
    u->params = strdupdelim(params_b, params_e);
  if (query_b)
    u->query = strdupdelim(query_b, query_e);
  if (fragment_b)
    u->fragment = strdupdelim(fragment_b, fragment_e);

  if (opt.enable_iri || path_modified || u->fragment || host_modified || path_b == path_e) {
    u->url = url_string(u, URL_AUTH_SHOW);

    if (url_encoded != url)
      xfree(url_encoded);
  }
  else {
    if (url_encoded == url)
      u->url = xstrdup(url);
    else
      u->url = (char*)url_encoded;
  }

  return u;

error:
  if (url_encoded && url_encoded != url)
    xfree(url_encoded);

  if (error)
    *error = error_code;
  return NULL;
}

const char* url_error(int error_code) {
  assert(error_code >= 0 && error_code < (int)countof(parse_errors));
  if (error_code < 0 || error_code >= (int)countof(parse_errors))
    return "";

  return _(parse_errors[error_code]);
}

static void split_path(const char* path, char** dir, char** file) {
  char* last_slash = strrchr(path, '/');
  if (!last_slash) {
    *dir = xstrdup("");
    *file = xstrdup(path);
  }
  else {
    *dir = strdupdelim(path, last_slash);
    *file = xstrdup(last_slash + 1);
  }
  url_unescape(*dir);
  url_unescape(*file);
}

static int full_path_length(const struct url* url) {
  int len = 0;

#define FROB(el) \
  if (url->el)   \
  len += 1 + (int)strlen(url->el)

  FROB(path);
  FROB(params);
  FROB(query);

#undef FROB

  return len;
}

static void full_path_write(const struct url* url, char* where) {
#define FROB(el, chr)                 \
  do {                                \
    char* f_el = url->el;             \
    if (f_el) {                       \
      int l = (int)strlen(f_el);      \
      *where++ = (chr);               \
      memcpy(where, f_el, (size_t)l); \
      where += l;                     \
    }                                 \
  } while (0)

  FROB(path, '/');
  FROB(params, ';');
  FROB(query, '?');

#undef FROB
}

char* url_full_path(const struct url* url) {
  int length = full_path_length(url);
  char* full_path = xmalloc((size_t)length + 1);

  full_path_write(url, full_path);
  full_path[length] = '\0';

  return full_path;
}

static void unescape_single_char(char* str, char chr) {
  const char c1 = XNUM_TO_DIGIT(((unsigned char)chr) >> 4);
  const char c2 = XNUM_TO_DIGIT(((unsigned char)chr) & 0xf);
  char* h = str;
  char* t = str;
  for (; *h; h++, t++) {
    if (h[0] == '%' && h[1] == c1 && h[2] == c2) {
      *t = chr;
      h += 2;
    }
    else {
      *t = *h;
    }
  }
  *t = '\0';
}

static char* url_escape_dir(const char* dir) {
  char* newdir = url_escape_1(dir, urlchr_unsafe | urlchr_reserved, true);
  if (newdir == dir)
    return (char*)dir;

  unescape_single_char(newdir, '/');
  return newdir;
}

static void sync_path(struct url* u) {
  char *newpath, *efile, *edir;

  xfree(u->path);

  edir = url_escape_dir(u->dir);
  efile = url_escape_1(u->file, urlchr_unsafe | urlchr_reserved, true);

  if (!*edir)
    newpath = xstrdup(efile);
  else {
    int dirlen = (int)strlen(edir);
    int filelen = (int)strlen(efile);

    char* p = newpath = xmalloc((size_t)dirlen + 1 + (size_t)filelen + 1);
    memcpy(p, edir, (size_t)dirlen);
    p += dirlen;
    *p++ = '/';
    memcpy(p, efile, (size_t)filelen);
    p += filelen;
    *p = '\0';
  }

  u->path = newpath;

  if (edir != u->dir)
    xfree(edir);
  if (efile != u->file)
    xfree(efile);

  xfree(u->url);
  u->url = url_string(u, URL_AUTH_SHOW);
}

void url_set_dir(struct url* url, const char* newdir) {
  xfree(url->dir);
  url->dir = xstrdup(newdir);
  sync_path(url);
}

void url_set_file(struct url* url, const char* newfile) {
  xfree(url->file);
  url->file = xstrdup(newfile);
  sync_path(url);
}

void url_free(struct url* url) {
  if (url) {
    xfree(url->host);

    xfree(url->path);
    xfree(url->url);

    xfree(url->params);
    xfree(url->query);
    xfree(url->fragment);
    xfree(url->user);
    xfree(url->passwd);

    xfree(url->dir);
    xfree(url->file);

    xfree(url);
  }
}

int mkalldirs(const char* path) {
  const char* p;
  char* t;
  struct stat st;
  int res;

  p = strrchr(path, '/');
  p = p == NULL ? path : p;

  if ((p == path) && (*p != '/'))
    return 0;
  t = strdupdelim(path, p);

  if ((stat(t, &st) == 0)) {
    if (S_ISDIR(st.st_mode)) {
      xfree(t);
      return 0;
    }
    else {
      DEBUGP(("Removing %s because of directory danger!\n", t));
      if (unlink(t))
        logprintf(LOG_NOTQUIET, "Failed to unlink %s (%d): %s\n", t, errno, strerror(errno));
    }
  }
  res = make_directory(t);
  if (res != 0)
    logprintf(LOG_NOTQUIET, "%s: %s\n", t, strerror(errno));
  xfree(t);
  return res;
}

struct growable {
  char* base;
  int size;
  int tail;
};

#define GROW(g, append_size)                                        \
  do {                                                              \
    struct growable* G_ = (g);                                      \
    DO_REALLOC(G_->base, G_->size, G_->tail + (append_size), char); \
  } while (0)

#define TAIL(r) ((r)->base + (r)->tail)
#define TAIL_INCR(r, append_count) ((r)->tail += (append_count))

static void append_null(struct growable* dest) {
  GROW(dest, 1);
  *TAIL(dest) = 0;
}

static void append_char(char ch, struct growable* dest) {
  if (ch) {
    GROW(dest, 1);
    *TAIL(dest) = ch;
    TAIL_INCR(dest, 1);
  }

  append_null(dest);
}

static void append_string(const char* str, struct growable* dest) {
  int l = (int)strlen(str);

  if (l) {
    GROW(dest, l);
    memcpy(TAIL(dest), str, (size_t)l);
    TAIL_INCR(dest, l);
  }

  append_null(dest);
}

/* Linux/Unix only filename character handling */

enum { filechr_not_unix = 1, filechr_control = 2 };

static bool file_char_needs_escape(unsigned char c, int mask) {
  if (opt.restrict_files_nonascii && !c_isascii(c))
    return true;

  if ((mask & filechr_control) && (c < 32 || c == 127))
    return true;

  if ((mask & filechr_not_unix) && (c == '/' || c == '\0'))
    return true;

  return false;
}

#define FILE_CHAR_TEST(c, mask) file_char_needs_escape((unsigned char)(c), (mask))

#define FN_PORT_SEP ':'
#define FN_QUERY_SEP '?'
#define FN_QUERY_SEP_STR "?"

static void append_uri_pathel(const char* b, const char* e, bool escaped, struct growable* dest) {
  const char* p;
  char buf[1024];
  char* unescaped = NULL;
  int quoted;
  int outlen;
  int mask;
  int max_length;

  if (!dest)
    return;

  mask = filechr_not_unix;
  if (opt.restrict_files_ctrl)
    mask |= filechr_control;

  if (escaped) {
    size_t len = (size_t)(e - b);
    if (len < sizeof(buf))
      unescaped = buf;
    else
      unescaped = xmalloc(len + 1);

    memcpy(unescaped, b, len);
    unescaped[len] = 0;

    url_unescape(unescaped);
    b = unescaped;
    e = unescaped + strlen(unescaped);
  }

  if (e - b == 2 && b[0] == '.' && b[1] == '.') {
    b = "%2E%2E";
    e = b + 6;
  }

  quoted = 0;
  for (p = b; p < e; p++)
    if (FILE_CHAR_TEST(*p, mask))
      ++quoted;

  outlen = (int)(e - b) + (2 * quoted);

  max_length = get_max_length(dest->base, dest->tail, _PC_NAME_MAX);

  max_length -= CHOMP_BUFFER;
  if (max_length > 0 && outlen > max_length) {
    logprintf(LOG_NOTQUIET, "The destination name is too long (%d), reducing to %d\n", outlen, max_length);
    outlen = max_length;
  }
  GROW(dest, outlen);

  if (!dest->base)
    return;

  if (!quoted) {
    memcpy(TAIL(dest), b, (size_t)outlen);
  }
  else {
    char* q = TAIL(dest);
    int i;

    for (i = 0, p = b; p < e; p++) {
      if (!FILE_CHAR_TEST(*p, mask)) {
        if (i == outlen)
          break;
        *q++ = *p;
        i++;
      }
      else if (i + 3 > outlen) {
        break;
      }
      else {
        unsigned char ch = (unsigned char)*p;
        *q++ = '%';
        *q++ = XNUM_TO_DIGIT(ch >> 4);
        *q++ = XNUM_TO_DIGIT(ch & 0xf);
        i += 3;
      }
    }
    assert(q - TAIL(dest) <= outlen);
  }

  if (opt.restrict_files_case == restrict_lowercase || opt.restrict_files_case == restrict_uppercase) {
    char* q;
    for (q = TAIL(dest); q < TAIL(dest) + outlen; ++q) {
      if (opt.restrict_files_case == restrict_lowercase)
        *q = c_tolower(*q);
      else
        *q = c_toupper(*q);
    }
  }

  TAIL_INCR(dest, outlen);
  append_null(dest);

  if (unescaped && unescaped != buf)
    free(unescaped);
}

#ifdef HAVE_ICONV
static char* convert_fname(char* fname) {
  char* converted_fname;
  const char* from_encoding = opt.encoding_remote;
  const char* to_encoding = opt.locale;
  iconv_t cd;
  size_t len, done, inlen, outlen;
  char* s;
  const char* orig_fname;

  if (!from_encoding)
    from_encoding = "UTF-8";
  if (!to_encoding)
    to_encoding = nl_langinfo(CODESET);

  cd = iconv_open(to_encoding, from_encoding);
  if (cd == (iconv_t)(-1)) {
    logprintf(LOG_VERBOSE, _("Conversion from %s to %s isn't supported\n"), quote_n(0, from_encoding), quote_n(1, to_encoding));
    return fname;
  }

  orig_fname = fname;
  inlen = strlen(fname);
  len = outlen = inlen * 2;
  converted_fname = s = xmalloc(outlen + 1);
  done = 0;

  for (;;) {
    errno = 0;
    if (iconv(cd, (ICONV_CONST char**)&fname, &inlen, &s, &outlen) == 0 && iconv(cd, NULL, NULL, &s, &outlen) == 0) {
      *(converted_fname + len - outlen - done) = '\0';
      iconv_close(cd);
      DEBUGP(("Converted file name '%s' (%s) -> '%s' (%s)\n", orig_fname, from_encoding, converted_fname, to_encoding));
      xfree(orig_fname);
      return converted_fname;
    }

    if (errno == EINVAL || errno == EILSEQ || errno == 0) {
      if (errno)
        logprintf(LOG_VERBOSE, _("Incomplete or invalid multibyte sequence encountered\n"));
      else
        logprintf(LOG_VERBOSE, _("Unconvertable multibyte sequence encountered\n"));
      xfree(converted_fname);
      converted_fname = (char*)orig_fname;
      break;
    }
    else if (errno == E2BIG) {
      done = len;
      len = outlen = done + inlen * 2;
      converted_fname = xrealloc(converted_fname, outlen + 1);
      s = converted_fname + done;
    }
    else {
      logprintf(LOG_VERBOSE, _("Unhandled errno %d\n"), errno);
      xfree(converted_fname);
      converted_fname = (char*)orig_fname;
      break;
    }
  }
  DEBUGP(("Failed to convert file name '%s' (%s) -> '?' (%s)\n", orig_fname, from_encoding, to_encoding));

  iconv_close(cd);

  return converted_fname;
}
#else
static char* convert_fname(char* fname) {
  return fname;
}
#endif

static void append_dir_structure(const struct url* u, struct growable* dest) {
  char *pathel, *next;
  int cut = opt.cut_dirs;

  pathel = u->path;
  for (; (next = strchr(pathel, '/')) != NULL; pathel = next + 1) {
    if (cut-- > 0)
      continue;
    if (pathel == next)
      continue;

    if (dest->tail)
      append_char('/', dest);

    append_uri_pathel(pathel, next, true, dest);
  }
}

char* url_file_name(const struct url* u, char* replaced_filename) {
  struct growable fnres;
  struct growable temp_fnres;

  const char* u_file;
  char *fname, *unique, *fname_len_check;
  const char* index_filename = "index.html";

  fnres.base = NULL;
  fnres.size = 0;
  fnres.tail = 0;

  temp_fnres.base = NULL;
  temp_fnres.size = 0;
  temp_fnres.tail = 0;

  if (opt.default_page)
    index_filename = opt.default_page;

  if (opt.dir_prefix)
    append_string(opt.dir_prefix, &fnres);

  if (opt.dirstruct) {
    if (opt.protocol_directories) {
      if (temp_fnres.tail)
        append_char('/', &temp_fnres);
      append_string(supported_schemes[u->scheme].name, &temp_fnres);
    }
    if (opt.add_hostdir) {
      if (temp_fnres.tail)
        append_char('/', &temp_fnres);
      if (0 != strcmp(u->host, ".."))
        append_string(u->host, &temp_fnres);
      else
        append_string("%2E%2E", &temp_fnres);
      if (u->port != scheme_default_port(u->scheme)) {
        char portstr[24];
        number_to_string(portstr, u->port);
        append_char(FN_PORT_SEP, &temp_fnres);
        append_string(portstr, &temp_fnres);
      }
    }

    append_dir_structure(u, &temp_fnres);
  }

  if (!replaced_filename) {
    u_file = *u->file ? u->file : index_filename;

    if (u->query)
      fname_len_check = concat_strings(u_file, FN_QUERY_SEP_STR, u->query, NULL);
    else
      fname_len_check = strdupdelim(u_file, u_file + strlen(u_file));
  }
  else {
    u_file = replaced_filename;
    fname_len_check = strdupdelim(u_file, u_file + strlen(u_file));
  }

  if (temp_fnres.tail)
    append_char('/', &temp_fnres);

  append_uri_pathel(fname_len_check, fname_len_check + strlen(fname_len_check), true, &temp_fnres);

  append_char('\0', &temp_fnres);

  fname = convert_fname(temp_fnres.base);
  temp_fnres.base = NULL;
  temp_fnres.size = 0;
  temp_fnres.tail = 0;
  append_string(fname, &temp_fnres);

  xfree(fname);
  xfree(fname_len_check);

  if (fnres.tail)
    append_char('/', &fnres);
  append_string(temp_fnres.base, &fnres);

  fname = fnres.base;

  xfree(temp_fnres.base);

  if (ALLOW_CLOBBER && !(file_exists_p(fname, NULL) && !file_non_directory_p(fname))) {
    unique = fname;
  }
  else {
    unique = unique_name_passthrough(fname);
    if (unique != fname)
      xfree(fname);
  }

  return unique;
}

static bool path_simplify(enum url_scheme scheme, char* path) {
  char* h = path;
  char* t = path;
  char* beg = path;
  char* end = strchr(path, '\0');
  bool modified = false;

  while (h < end) {
    if (h[0] == '.' && (h[1] == '/' || h[1] == '\0')) {
      h += 2;
      modified = true;
    }
    else if (h[0] == '.' && h[1] == '.' && (h[2] == '/' || h[2] == '\0')) {
      if (t > beg) {
        for (--t; t > beg && t[-1] != '/'; t--)
          ;
      }
      else if (scheme == SCHEME_FTP
#ifdef HAVE_SSL
               || scheme == SCHEME_FTPS
#endif
      ) {
        beg = t + 3;
        goto regular;
      }
      h += 3;
      modified = true;
    }
    else {
    regular:
      if (t == h) {
        while (h < end && *h != '/')
          t++, h++;
        if (h < end)
          t++, h++;
      }
      else {
        while (h < end && *h != '/')
          *t++ = *h++;
        if (h < end)
          *t++ = *h++;
        modified = true;
      }
    }
  }

  if (t != h) {
    *t = '\0';
    modified = true;
  }

  return modified;
}

static const char* path_end(const char* url) {
  enum url_scheme scheme = url_scheme(url);
  const char* seps;
  if (scheme == SCHEME_INVALID)
    scheme = SCHEME_HTTP;
  seps = init_seps(scheme) + 2;
  return strpbrk_or_eos(url, seps);
}

#define find_last_char(b, e, c) memrchr((b), (c), (size_t)((e) - (b)))

char* uri_merge(const char* base, const char* link) {
  int linklength;
  const char* end;
  char* merge;

  if (url_has_scheme(link))
    return xstrdup(link);

  end = path_end(base);
  linklength = (int)strlen(link);

  if (!*link) {
    return xstrdup(base);
  }
  else if (*link == '?') {
    int baselength = (int)(end - base);
    merge = xmalloc((size_t)baselength + (size_t)linklength + 1);
    memcpy(merge, base, (size_t)baselength);
    memcpy(merge + baselength, link, (size_t)linklength);
    merge[baselength + linklength] = '\0';
  }
  else if (*link == '#') {
    int baselength;
    const char* end1 = strchr(base, '#');
    if (!end1)
      end1 = base + strlen(base);
    baselength = (int)(end1 - base);
    merge = xmalloc((size_t)baselength + (size_t)linklength + 1);
    memcpy(merge, base, (size_t)baselength);
    memcpy(merge + baselength, link, (size_t)linklength);
    merge[baselength + linklength] = '\0';
  }
  else if (*link == '/' && *(link + 1) == '/') {
    int span;
    const char* slash;
    const char* start_insert;

    slash = memchr(base, '/', (size_t)(end - base));
    if (slash && *(slash + 1) == '/')
      start_insert = slash;
    else
      start_insert = base;

    span = (int)(start_insert - base);
    merge = xmalloc((size_t)span + (size_t)linklength + 1);
    if (span)
      memcpy(merge, base, (size_t)span);
    memcpy(merge + span, link, (size_t)linklength);
    merge[span + linklength] = '\0';
  }
  else if (*link == '/') {
    int span;
    const char* slash;
    const char* start_insert = NULL;
    const char* pos = base;
    bool seen_slash_slash = false;
  again:
    slash = memchr(pos, '/', (size_t)(end - pos));
    if (slash && !seen_slash_slash)
      if (*(slash + 1) == '/') {
        pos = slash + 2;
        seen_slash_slash = true;
        goto again;
      }

    if (!slash && !seen_slash_slash)
      start_insert = base;
    else if (!slash && seen_slash_slash)
      start_insert = end;
    else if (slash && !seen_slash_slash)
      start_insert = base;
    else if (slash && seen_slash_slash)
      start_insert = slash;

    span = (int)(start_insert - base);
    merge = xmalloc((size_t)span + (size_t)linklength + 1);
    if (span)
      memcpy(merge, base, (size_t)span);
    memcpy(merge + span, link, (size_t)linklength);
    merge[span + linklength] = '\0';
  }
  else {
    bool need_explicit_slash = false;
    int span;
    const char* start_insert;
    const char* last_slash = find_last_char(base, end, '/');
    if (!last_slash) {
      start_insert = base;
    }
    else if (last_slash && last_slash >= base + 2 && last_slash[-2] == ':' && last_slash[-1] == '/') {
      start_insert = end + 1;
      need_explicit_slash = true;
    }
    else {
      start_insert = last_slash + 1;
    }

    span = (int)(start_insert - base);
    merge = xmalloc((size_t)span + (size_t)linklength + 1);
    if (span)
      memcpy(merge, base, (size_t)span);
    if (need_explicit_slash)
      merge[span - 1] = '/';
    memcpy(merge + span, link, (size_t)linklength);
    merge[span + linklength] = '\0';
  }

  return merge;
}

#define APPEND(p, s)               \
  do {                             \
    int len = (int)strlen(s);      \
    memcpy((p), (s), (size_t)len); \
    (p) += len;                    \
  } while (0)

#define HIDDEN_PASSWORD "*password*"

char* url_string(const struct url* url, enum url_auth_mode auth_mode) {
  int size;
  char *result, *p;
  char *quoted_host, *quoted_user = NULL, *quoted_passwd = NULL;

  int scheme_port = supported_schemes[url->scheme].default_port;
  const char* scheme_str = supported_schemes[url->scheme].leading_string;
  int fplen = full_path_length(url);

  bool brackets_around_host;

  assert(scheme_str != NULL);

  if (url->user) {
    if (auth_mode != URL_AUTH_HIDE) {
      quoted_user = url_escape_allow_passthrough(url->user);
      if (url->passwd) {
        if (auth_mode == URL_AUTH_HIDE_PASSWD)
          quoted_passwd = (char*)HIDDEN_PASSWORD;
        else
          quoted_passwd = url_escape_allow_passthrough(url->passwd);
      }
    }
  }

  quoted_host = url_escape_allow_passthrough(url->host);

  if (quoted_host != url->host)
    unescape_single_char(quoted_host, ':');
  brackets_around_host = strchr(quoted_host, ':') != NULL;

  size = (int)(strlen(scheme_str) + strlen(quoted_host) + (brackets_around_host ? 2 : 0) + fplen + 1);
  if (url->port != scheme_port)
    size += 1 + numdigit(url->port);
  if (quoted_user) {
    size += 1 + (int)strlen(quoted_user);
    if (quoted_passwd)
      size += 1 + (int)strlen(quoted_passwd);
  }

  p = result = xmalloc((size_t)size);

  APPEND(p, scheme_str);
  if (quoted_user) {
    APPEND(p, quoted_user);
    if (quoted_passwd) {
      *p++ = ':';
      APPEND(p, quoted_passwd);
    }
    *p++ = '@';
  }

  if (brackets_around_host)
    *p++ = '[';
  APPEND(p, quoted_host);
  if (brackets_around_host)
    *p++ = ']';
  if (url->port != scheme_port) {
    *p++ = ':';
    p = number_to_string(p, url->port);
  }

  full_path_write(url, p);
  p += fplen;
  *p++ = '\0';

  assert(p - result == size);

  if (quoted_user && quoted_user != url->user)
    xfree(quoted_user);
  if (quoted_passwd && auth_mode == URL_AUTH_SHOW && quoted_passwd != url->passwd)
    xfree(quoted_passwd);
  if (quoted_host != url->host)
    xfree(quoted_host);

  return result;
}

bool schemes_are_similar_p(enum url_scheme a, enum url_scheme b) {
  if (a == b)
    return true;
#ifdef HAVE_SSL
  if ((a == SCHEME_HTTP && b == SCHEME_HTTPS) || (a == SCHEME_HTTPS && b == SCHEME_HTTP))
    return true;
#endif
  return false;
}

static int getchar_from_escaped_string(const char* str, char* c) {
  const char* p = str;

  assert(str && *str);
  assert(c);

  if (p[0] == '%') {
    if (!c_isxdigit(p[1]) || !c_isxdigit(p[2])) {
      *c = '%';
      return 1;
    }
    else {
      if (p[2] == 0)
        return 0;

      *c = X2DIGITS_TO_NUM(p[1], p[2]);
      if (URL_RESERVED_CHAR(*c)) {
        *c = '%';
        return 1;
      }
      return 3;
    }
  }
  else {
    *c = p[0];
  }

  return 1;
}

bool are_urls_equal(const char* u1, const char* u2) {
  const char *p, *q;
  int pp, qq;
  char ch1, ch2;
  assert(u1 && u2);

  p = u1;
  q = u2;

  while (*p && *q && (pp = getchar_from_escaped_string(p, &ch1)) && (qq = getchar_from_escaped_string(q, &ch2)) && (c_tolower(ch1) == c_tolower(ch2))) {
    p += pp;
    q += qq;
  }

  return (*p == 0 && *q == 0);
}

#ifdef TESTING

static const char* run_test(const char* test, const char* expected_result, enum url_scheme scheme, bool expected_change) {
  char* test_copy = xstrdup(test);
  bool modified = path_simplify(scheme, test_copy);

  if (strcmp(test_copy, expected_result) != 0) {
    printf("Failed path_simplify(\"%s\"): expected \"%s\", got \"%s\".\n", test, expected_result, test_copy);
    mu_assert("", 0);
  }
  if (modified != expected_change) {
    if (expected_change)
      printf("Expected modification with path_simplify(\"%s\").\n", test);
    else
      printf("Expected no modification with path_simplify(\"%s\").\n", test);
  }
  xfree(test_copy);
  mu_assert("", modified == expected_change);
  return NULL;
}

const char* test_path_simplify(void) {
  static const struct {
    const char *test, *result;
    enum url_scheme scheme;
    bool should_modify;
  } tests[] = {{"", "", SCHEME_HTTP, false},
               {".", "", SCHEME_HTTP, true},
               {"./", "", SCHEME_HTTP, true},
               {"..", "", SCHEME_HTTP, true},
               {"../", "", SCHEME_HTTP, true},
               {"..", "..", SCHEME_FTP, false},
               {"../", "../", SCHEME_FTP, false},
               {"foo", "foo", SCHEME_HTTP, false},
               {"foo/bar", "foo/bar", SCHEME_HTTP, false},
               {"foo///bar", "foo///bar", SCHEME_HTTP, false},
               {"foo/.", "foo/", SCHEME_HTTP, true},
               {"foo/./", "foo/", SCHEME_HTTP, true},
               {"foo./", "foo./", SCHEME_HTTP, false},
               {"foo/../bar", "bar", SCHEME_HTTP, true},
               {"foo/../bar/", "bar/", SCHEME_HTTP, true},
               {"foo/bar/..", "foo/", SCHEME_HTTP, true},
               {"foo/bar/../x", "foo/x", SCHEME_HTTP, true},
               {"foo/bar/../x/", "foo/x/", SCHEME_HTTP, true},
               {"foo/..", "", SCHEME_HTTP, true},
               {"foo/../..", "", SCHEME_HTTP, true},
               {"foo/../../..", "", SCHEME_HTTP, true},
               {"foo/../../bar/../../baz", "baz", SCHEME_HTTP, true},
               {"foo/../..", "..", SCHEME_FTP, true},
               {"foo/../../..", "../..", SCHEME_FTP, true},
               {"foo/../../bar/../../baz", "../../baz", SCHEME_FTP, true},
               {"a/b/../../c", "c", SCHEME_HTTP, true},
               {"./a/../b", "b", SCHEME_HTTP, true}};
  unsigned i;

  for (i = 0; i < countof(tests); i++) {
    const char* message;
    const char* test = tests[i].test;
    const char* expected_result = tests[i].result;
    enum url_scheme scheme = tests[i].scheme;
    bool expected_change = tests[i].should_modify;

    message = run_test(test, expected_result, scheme, expected_change);
    if (message)
      return message;
  }
  return NULL;
}

const char* test_append_uri_pathel(void) {
  unsigned i;
  static const struct {
    const char* original_url;
    const char* input;
    bool escaped;
    const char* expected_result;
  } test_array[] = {
      {"http://www.yoyodyne.com/path/", "somepage.html", false, "http://www.yoyodyne.com/path/somepage.html"},
  };

  for (i = 0; i < countof(test_array); ++i) {
    struct growable dest;
    const char* p = test_array[i].input;

    memset(&dest, 0, sizeof(dest));

    append_string(test_array[i].original_url, &dest);
    append_uri_pathel(p, p + strlen(p), test_array[i].escaped, &dest);

    mu_assert("test_append_uri_pathel: wrong result", strcmp(dest.base, test_array[i].expected_result) == 0);
    xfree(dest.base);
  }

  return NULL;
}

const char* test_are_urls_equal(void) {
  unsigned i;
  static const struct {
    const char* url1;
    const char* url2;
    bool expected_result;
  } test_array[] = {
      {"http://www.adomain.com/apath/", "http://www.adomain.com/apath/", true},       {"http://www.adomain.com/apath/", "http://www.adomain.com/anotherpath/", false},
      {"http://www.adomain.com/apath/", "http://www.anotherdomain.com/path/", false}, {"http://www.adomain.com/~path/", "http://www.adomain.com/%7epath/", true},
      {"http://www.adomain.com/longer-path/", "http://www.adomain.com/path/", false}, {"http://www.adomain.com/path%2f", "http://www.adomain.com/path/", false},
  };

  for (i = 0; i < countof(test_array); ++i) {
    mu_assert("test_are_urls_equal: wrong result", are_urls_equal(test_array[i].url1, test_array[i].url2) == test_array[i].expected_result);
  }

  return NULL;
}

const char* test_uri_merge(void) {
  static const struct test_data {
    const char* url;
    const char* link;
    const char* expected;
  } test_data[] = {
      {"http://www.yoyodyne.com/path/", "somepage.html", "http://www.yoyodyne.com/path/somepage.html"},
      {"http://example.com/path/", "//other.com/somepage.html", "http://other.com/somepage.html"},
      {"https://example.com/path/", "//other.com/somepage.html", "https://other.com/somepage.html"},
  };

  for (unsigned i = 0; i < countof(test_data); ++i) {
    const struct test_data* t = &test_data[i];
    char* result = uri_merge(t->url, t->link);
    bool ok = strcmp(result, t->expected) == 0;
    if (!ok)
      return aprintf("test_uri_merge [%u]: expected '%s', got '%s'", i, t->expected, result);

    xfree(result);
  }

  return NULL;
}

#endif

/*
 * vim: et ts=2 sw=2
 */
