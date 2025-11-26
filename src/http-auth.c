/* HTTP authentication management
 * src/http-auth.c
 *
 * Handles Basic and Digest authentication, with optional NTLM support
 */

#include "wget.h"
#include "http-auth.h"
#include "http.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "c-ctype.h"
#include "c-strcase.h"
#include "gettext.h"
#include "hash.h"
#include "log.h"
#include "md5.h"
#include "quotearg.h"
#include "utils.h"
#include "xalloc.h"
#include "xstrndup.h"

#ifdef ENABLE_NTLM
#include "http-ntlm.h"
#endif

static struct hash_table* basic_authed_hosts;

/* If this host is known to have issued a Basic challenge, or
 * auth_without_challenge is set, attach an Authorization header
 *
 * Returns true if credentials were added
 */
bool maybe_send_basic_creds(const char* hostname, const char* user, const char* passwd, struct request* req) {
  bool do_challenge = false;

  if (opt.auth_without_challenge) {
    DEBUGP(("Auth-without-challenge set, sending Basic credentials\n"));
    do_challenge = true;
  }
  else if (basic_authed_hosts && hash_table_contains(basic_authed_hosts, hostname)) {
    DEBUGP(("Found %s in basic_authed_hosts\n", quote(hostname)));
    do_challenge = true;
  }
  else {
    DEBUGP(("Host %s has not issued a general basic challenge\n", quote(hostname)));
  }

  if (do_challenge) {
    request_set_header(req, "Authorization", basic_authentication_encode(user, passwd), rel_value);
  }

  return do_challenge;
}

void register_basic_auth_host(const char* hostname) {
  if (!basic_authed_hosts)
    basic_authed_hosts = make_nocase_string_hash_table(1);

  if (!hash_table_contains(basic_authed_hosts, hostname)) {
    hash_table_put(basic_authed_hosts, xstrdup(hostname), NULL);
    DEBUGP(("Inserted %s into basic_authed_hosts\n", quote(hostname)));
  }
}

void http_auth_cleanup(void) {
  if (basic_authed_hosts) {
    hash_table_iterator iter;

    for (hash_table_iterate(basic_authed_hosts, &iter); hash_table_iter_next(&iter);)
      xfree(iter.key);

    hash_table_destroy(basic_authed_hosts);
    basic_authed_hosts = NULL;
  }
}

/* Basic authentication
 *
 * Encodes "user:pass" as base64 and prefixes "Basic "
 */
char* basic_authentication_encode(const char* user, const char* passwd) {
  char buf_t1[256];
  char buf_t2[256];
  char *t1, *t2, *ret;
  size_t len1 = strlen(user) + 1 + strlen(passwd);

  if (len1 < sizeof(buf_t1))
    t1 = buf_t1;
  else
    t1 = xmalloc(len1 + 1);

  if (BASE64_LENGTH(len1) < sizeof(buf_t2))
    t2 = buf_t2;
  else
    t2 = xmalloc(BASE64_LENGTH(len1) + 1);

  sprintf(t1, "%s:%s", user, passwd);
  wget_base64_encode(t1, len1, t2);

  ret = concat_strings("Basic ", t2, (char*)0);

  if (t2 != buf_t2)
    xfree(t2);

  if (t1 != buf_t1)
    xfree(t1);

  return ret;
}

#ifdef ENABLE_DIGEST
/* Render MD5 hash as a hex string into buf
 * buf must hold 2 * MD5_DIGEST_SIZE + 1 bytes
 */
static void dump_hash(char* buf, const unsigned char* hash) {
  int i;

  for (i = 0; i < MD5_DIGEST_SIZE; i++, hash++) {
    *buf++ = XNUM_TO_digit(*hash >> 4);
    *buf++ = XNUM_TO_digit(*hash & 0xf);
  }
  *buf = '\0';
}

/* Build a Digest Authorization header from a WWW-Authenticate challenge
 *
 * Parses challenge params (realm, nonce, qop, algorithm, opaque) and
 * computes the appropriate response for RFC 2069 / 2617
 *
 * On missing required fields, sets *auth_err and returns NULL
 */
static char* digest_authentication_encode(const char* au, const char* user, const char* passwd, const char* method, const char* path, uerr_t* auth_err) {
  static char *realm, *opaque, *nonce, *qop, *algorithm;
  static struct {
    const char* name;
    char** variable;
  } options[] = {
      {"realm", &realm}, {"opaque", &opaque}, {"nonce", &nonce}, {"qop", &qop}, {"algorithm", &algorithm},
  };

  char cnonce[16] = "";
  char* res = NULL;
  int res_len;
  size_t res_size;
  param_token name, value;

  realm = opaque = nonce = algorithm = qop = NULL;

  /* skip "Digest" prefix */
  au += 6;
  while (extract_param(&au, &name, &value, ',', NULL)) {
    size_t i;
    size_t namelen = (size_t)(name.e - name.b);

    for (i = 0; i < countof(options); i++) {
      if (namelen == strlen(options[i].name) && strncmp(name.b, options[i].name, namelen) == 0) {
        *options[i].variable = strdupdelim(value.b, value.e);
        break;
      }
    }
  }

  if (qop && strcmp(qop, "auth")) {
    logprintf(LOG_NOTQUIET, _("Unsupported quality of protection '%s'\n"), qop);
    xfree(qop);
    qop = NULL;
  }
  else if (algorithm && strcmp(algorithm, "MD5") && strcmp(algorithm, "MD5-sess")) {
    logprintf(LOG_NOTQUIET, _("Unsupported algorithm '%s'\n"), algorithm);
    xfree(algorithm);
    algorithm = NULL;
  }

  if (!realm || !nonce || !user || !passwd || !path || !method) {
    *auth_err = ATTRMISSING;
    goto cleanup;
  }

  /* compute response digest */
  {
    struct md5_ctx ctx;
    unsigned char hash[MD5_DIGEST_SIZE];
    char a1buf[MD5_DIGEST_SIZE * 2 + 1];
    char a2buf[MD5_DIGEST_SIZE * 2 + 1];
    char response_digest[MD5_DIGEST_SIZE * 2 + 1];

    /* A1BUF = H(user ":" realm ":" password) */
    md5_init_ctx(&ctx);
    md5_process_bytes((unsigned char*)user, strlen(user), &ctx);
    md5_process_bytes((unsigned char*)":", 1, &ctx);
    md5_process_bytes((unsigned char*)realm, strlen(realm), &ctx);
    md5_process_bytes((unsigned char*)":", 1, &ctx);
    md5_process_bytes((unsigned char*)passwd, strlen(passwd), &ctx);
    md5_finish_ctx(&ctx, hash);

    dump_hash(a1buf, hash);

    if (algorithm && strcmp(algorithm, "MD5-sess") == 0) {
      /* A1BUF = H( H(user ":" realm ":" password) ":" nonce ":" cnonce ) */
      snprintf(cnonce, sizeof(cnonce), "%08x", (unsigned)random_number(INT_MAX));

      md5_init_ctx(&ctx);
      md5_process_bytes(a1buf, MD5_DIGEST_SIZE * 2, &ctx);
      md5_process_bytes((unsigned char*)":", 1, &ctx);
      md5_process_bytes((unsigned char*)nonce, strlen(nonce), &ctx);
      md5_process_bytes((unsigned char*)":", 1, &ctx);
      md5_process_bytes((unsigned char*)cnonce, strlen(cnonce), &ctx);
      md5_finish_ctx(&ctx, hash);

      dump_hash(a1buf, hash);
    }

    /* A2BUF = H(method ":" path) */
    md5_init_ctx(&ctx);
    md5_process_bytes((unsigned char*)method, strlen(method), &ctx);
    md5_process_bytes((unsigned char*)":", 1, &ctx);
    md5_process_bytes((unsigned char*)path, strlen(path), &ctx);
    md5_finish_ctx(&ctx, hash);
    dump_hash(a2buf, hash);

    if (qop && strcmp(qop, "auth") == 0) {
      /* RFC 2617 Digest Access Authentication */
      if (!*cnonce)
        snprintf(cnonce, sizeof(cnonce), "%08x", (unsigned)random_number(INT_MAX));

      /* RESPONSE = H(A1BUF ":" nonce ":" nc ":" cnonce ":" qop ":" A2BUF) */
      md5_init_ctx(&ctx);
      md5_process_bytes((unsigned char*)a1buf, MD5_DIGEST_SIZE * 2, &ctx);
      md5_process_bytes((unsigned char*)":", 1, &ctx);
      md5_process_bytes((unsigned char*)nonce, strlen(nonce), &ctx);
      md5_process_bytes((unsigned char*)":", 1, &ctx);
      md5_process_bytes((unsigned char*)"00000001", 8, &ctx); /* TODO: track per-nonce counters */
      md5_process_bytes((unsigned char*)":", 1, &ctx);
      md5_process_bytes((unsigned char*)cnonce, strlen(cnonce), &ctx);
      md5_process_bytes((unsigned char*)":", 1, &ctx);
      md5_process_bytes((unsigned char*)qop, strlen(qop), &ctx);
      md5_process_bytes((unsigned char*)":", 1, &ctx);
      md5_process_bytes((unsigned char*)a2buf, MD5_DIGEST_SIZE * 2, &ctx);
      md5_finish_ctx(&ctx, hash);
    }
    else {
      /* RFC 2069 Digest Access Authentication */
      /* RESPONSE = H(A1BUF ":" nonce ":" A2BUF) */
      md5_init_ctx(&ctx);
      md5_process_bytes((unsigned char*)a1buf, MD5_DIGEST_SIZE * 2, &ctx);
      md5_process_bytes((unsigned char*)":", 1, &ctx);
      md5_process_bytes((unsigned char*)nonce, strlen(nonce), &ctx);
      md5_process_bytes((unsigned char*)":", 1, &ctx);
      md5_process_bytes((unsigned char*)a2buf, MD5_DIGEST_SIZE * 2, &ctx);
      md5_finish_ctx(&ctx, hash);
    }

    dump_hash(response_digest, hash);

    res_size = strlen(user) + strlen(realm) + strlen(nonce) + strlen(path) + 2 * MD5_DIGEST_SIZE + (opaque ? strlen(opaque) : 0) + (algorithm ? strlen(algorithm) : 0) + (qop ? 128 : 0) +
               strlen(cnonce) + 128;

    res = xmalloc(res_size);

    if (qop && strcmp(qop, "auth") == 0) {
      res_len = snprintf(res, res_size,
                         "Digest "
                         "username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\""
                         ", qop=auth, nc=00000001, cnonce=\"%s\"",
                         user, realm, nonce, path, response_digest, cnonce);
    }
    else {
      res_len = snprintf(res, res_size,
                         "Digest "
                         "username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\"",
                         user, realm, nonce, path, response_digest);
    }

    if (opaque)
      res_len += snprintf(res + res_len, res_size - (size_t)res_len, ", opaque=\"%s\"", opaque);

    if (algorithm)
      snprintf(res + res_len, res_size - (size_t)res_len, ", algorithm=\"%s\"", algorithm);
  }

cleanup:
  xfree(realm);
  xfree(opaque);
  xfree(nonce);
  xfree(qop);
  xfree(algorithm);

  return res;
}
#endif /* ENABLE_DIGEST */

/* STRSIZE accounts for the trailing NUL in sizeof */
#define STRSIZE(literal) (sizeof(literal) - 1)

/* True if [b,e) starts with literal and is followed by whitespace or NUL
 * comparison is case-insensitive
 */
#define STARTS(literal, b, e) \
  ((e > (b)) && ((size_t)((e) - (b))) >= STRSIZE(literal) && c_strncasecmp((b), (literal), STRSIZE(literal)) == 0 && (((size_t)((e) - (b))) == STRSIZE(literal) || c_isspace((b)[STRSIZE(literal)])))

bool known_authentication_scheme_p(const char* hdrbeg, const char* hdrend) {
  return STARTS("Basic", hdrbeg, hdrend)
#ifdef ENABLE_DIGEST
         || STARTS("Digest", hdrbeg, hdrend)
#endif
#ifdef ENABLE_NTLM
         || STARTS("NTLM", hdrbeg, hdrend)
#endif
      ;
}

#undef STARTS

/* Build an Authorization header for a supported scheme
 *
 * au       challenge header value (e.g. \"Basic ...\", \"Digest ...\")
 * user     username
 * passwd   password
 * method   HTTP method used for the request
 * path     request path
 * finished set to true once the auth handshake is complete
 * auth_err set on Digest errors
 *
 * Returns a newly allocated header value or NULL on error
 */
char* create_authorization_line(const char* au,
                                const char* user,
                                const char* passwd,
                                const char* method,
                                const char* path,
                                bool* finished,
                                uerr_t* auth_err
#ifdef ENABLE_NTLM
                                ,
                                struct ntlmdata* ntlm
#endif
) {
  /* We are called only with known schemes, so dispatch on the first letter */
  switch (c_toupper(*au)) {
    case 'B': /* Basic */
      *finished = true;
      return basic_authentication_encode(user, passwd);
#ifdef ENABLE_DIGEST
    case 'D': /* Digest */
      *finished = true;
      return digest_authentication_encode(au, user, passwd, method, path, auth_err);
#endif
#ifdef ENABLE_NTLM
    case 'N': /* NTLM */
      if (!ntlm_input(ntlm, au)) {
        *finished = true;
        return NULL;
      }
      return ntlm_output(ntlm, user, passwd, finished);
#endif
    default:
      /* only called for schemes accepted by known_authentication_scheme_p */
      abort();
  }
}
