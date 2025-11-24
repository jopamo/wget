/* HTTP authentication helpers.
 * src/http_auth.c
 */

#include "wget.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "c-ctype.h"
#include "c-strcase.h"
#include "hash.h"
#include "http_auth.h"
#include "http-header.h"
#include "http_request.h"
#include "utils.h"

#ifdef ENABLE_DIGEST
#include "md5.h"
#endif
#ifdef ENABLE_NTLM
#include "http-ntlm.h"
#endif

static struct hash_table* basic_authed_hosts;

bool http_auth_maybe_send_basic_creds(const char* hostname, const char* user, const char* passwd, struct request* req) {
  bool do_challenge = false;

  if (opt.auth_without_challenge) {
    DEBUGP(("Auth-without-challenge set, sending Basic credentials.\n"));
    do_challenge = true;
  }
  else if (basic_authed_hosts && hash_table_contains(basic_authed_hosts, hostname)) {
    DEBUGP(("Found %s in basic_authed_hosts.\n", quote(hostname)));
    do_challenge = true;
  }
  else {
    DEBUGP(("Host %s has not issued a general basic challenge.\n", quote(hostname)));
  }

  if (do_challenge)
    request_set_header(req, "Authorization", http_auth_basic_encode(user, passwd), rel_value);

  return do_challenge;
}

void http_auth_register_basic_challenge(const char* hostname) {
  if (!basic_authed_hosts)
    basic_authed_hosts = make_nocase_string_hash_table(1);

  if (!hash_table_contains(basic_authed_hosts, hostname)) {
    hash_table_put(basic_authed_hosts, xstrdup(hostname), NULL);
    DEBUGP(("Inserted %s into basic_authed_hosts\n", quote(hostname)));
  }
}

char* http_auth_basic_encode(const char* user, const char* passwd) {
  char buf_t1[256], buf_t2[256];
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

#define SKIP_WS(x)          \
  do {                      \
    while (c_isspace(*(x))) \
      ++(x);                \
  } while (0)

#ifdef ENABLE_DIGEST
static void dump_hash(char* buf, const unsigned char* hash) {
  int i;

  for (i = 0; i < MD5_DIGEST_SIZE; i++, hash++) {
    *buf++ = XNUM_TO_digit(*hash >> 4);
    *buf++ = XNUM_TO_digit(*hash & 0xf);
  }
  *buf = '\0';
}

static char* digest_authentication_encode(const char* au, const char* user, const char* passwd, const char* method, const char* path, uerr_t* auth_err) {
  static char *realm, *opaque, *nonce, *qop, *algorithm;
  static struct {
    const char* name;
    char** variable;
  } options[] = {{"realm", &realm}, {"opaque", &opaque}, {"nonce", &nonce}, {"qop", &qop}, {"algorithm", &algorithm}};
  char cnonce[16] = "";
  char* res = NULL;
  int res_len;
  size_t res_size;
  param_token name, value;

  realm = opaque = nonce = algorithm = qop = NULL;

  au += 6;
  while (extract_param(&au, &name, &value, ',', NULL)) {
    size_t i;
    size_t namelen = name.e - name.b;
    for (i = 0; i < countof(options); i++)
      if (namelen == strlen(options[i].name) && 0 == strncmp(name.b, options[i].name, namelen)) {
        *options[i].variable = strdupdelim(value.b, value.e);
        break;
      }
  }

  if (qop && strcmp(qop, "auth")) {
    logprintf(LOG_NOTQUIET, _("Unsupported quality of protection '%s'.\n"), qop);
    xfree(qop);
  }
  else if (algorithm && strcmp(algorithm, "MD5") && strcmp(algorithm, "MD5-sess")) {
    logprintf(LOG_NOTQUIET, _("Unsupported algorithm '%s'.\n"), algorithm);
    xfree(algorithm);
  }

  if (!realm || !nonce || !user || !passwd || !path || !method) {
    *auth_err = ATTRMISSING;
    goto cleanup;
  }

  {
    struct md5_ctx ctx;
    unsigned char hash[MD5_DIGEST_SIZE];
    char a1buf[MD5_DIGEST_SIZE * 2 + 1], a2buf[MD5_DIGEST_SIZE * 2 + 1];
    char response_digest[MD5_DIGEST_SIZE * 2 + 1];

    md5_init_ctx(&ctx);
    md5_process_bytes((unsigned char*)user, strlen(user), &ctx);
    md5_process_bytes((unsigned char*)":", 1, &ctx);
    md5_process_bytes((unsigned char*)realm, strlen(realm), &ctx);
    md5_process_bytes((unsigned char*)":", 1, &ctx);
    md5_process_bytes((unsigned char*)passwd, strlen(passwd), &ctx);
    md5_finish_ctx(&ctx, hash);

    dump_hash(a1buf, hash);

    if (algorithm && !strcmp(algorithm, "MD5-sess")) {
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

    md5_init_ctx(&ctx);
    md5_process_bytes((unsigned char*)method, strlen(method), &ctx);
    md5_process_bytes((unsigned char*)":", 1, &ctx);
    md5_process_bytes((unsigned char*)path, strlen(path), &ctx);
    md5_finish_ctx(&ctx, hash);

    dump_hash(a2buf, hash);

    if (qop && !strcmp(qop, "auth")) {
      if (!*cnonce)
        snprintf(cnonce, sizeof(cnonce), "%08x", (unsigned)random_number(INT_MAX));

      md5_init_ctx(&ctx);
      md5_process_bytes((unsigned char*)a1buf, MD5_DIGEST_SIZE * 2, &ctx);
      md5_process_bytes((unsigned char*)":", 1, &ctx);
      md5_process_bytes((unsigned char*)nonce, strlen(nonce), &ctx);
      md5_process_bytes((unsigned char*)":", 1, &ctx);
      md5_process_bytes((unsigned char*)"00000001", 8, &ctx);
      md5_process_bytes((unsigned char*)":", 1, &ctx);
      md5_process_bytes((unsigned char*)cnonce, strlen(cnonce), &ctx);
      md5_process_bytes((unsigned char*)":", 1, &ctx);
      md5_process_bytes((unsigned char*)qop, strlen(qop), &ctx);
      md5_process_bytes((unsigned char*)":", 1, &ctx);
      md5_process_bytes((unsigned char*)a2buf, MD5_DIGEST_SIZE * 2, &ctx);
      md5_finish_ctx(&ctx, hash);
    }
    else {
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

    if (qop && !strcmp(qop, "auth")) {
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
      res_len += snprintf(res + res_len, res_size - res_len, ", opaque=\"%s\"", opaque);

    if (algorithm)
      snprintf(res + res_len, res_size - res_len, ", algorithm=\"%s\"", algorithm);
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

#define STRSIZE(literal) (sizeof(literal) - 1)
#define STARTS(literal, b, e) \
  ((e > b) && ((size_t)((e) - (b))) >= STRSIZE(literal) && 0 == c_strncasecmp(b, literal, STRSIZE(literal)) && ((size_t)((e) - (b)) == STRSIZE(literal) || c_isspace(b[STRSIZE(literal)])))

bool http_auth_known_scheme(const char* hdrbeg, const char* hdrend) {
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

char* http_auth_create_authorization_line(const char* au, const char* user, const char* passwd, const char* method, const char* path, struct ntlmdata* ntlm_state, bool* finished, uerr_t* auth_err) {
#ifndef ENABLE_NTLM
  (void)ntlm_state;
#endif

  switch (c_toupper(*au)) {
    case 'B':
      *finished = true;
      return http_auth_basic_encode(user, passwd);
#ifdef ENABLE_DIGEST
    case 'D':
      *finished = true;
      return digest_authentication_encode(au, user, passwd, method, path, auth_err);
#endif
#ifdef ENABLE_NTLM
    case 'N':
      if (!ntlm_state || !ntlm_input(ntlm_state, au)) {
        *finished = true;
        return NULL;
      }
      return ntlm_output(ntlm_state, user, passwd, finished);
#endif
    default:
      abort();
  }
}

void http_auth_cleanup(void) {
  if (!basic_authed_hosts)
    return;

  hash_table_iterator iter;
  for (hash_table_iterate(basic_authed_hosts, &iter); hash_table_iter_next(&iter);)
    xfree(iter.key);

  hash_table_destroy(basic_authed_hosts);
  basic_authed_hosts = NULL;
}
