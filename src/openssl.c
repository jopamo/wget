/* SSL support via OpenSSL library
 * src/openssl.c
 */

#include "wget.h"

#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <xalloc.h>

#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#if OPENSSL_VERSION_NUMBER >= 0x00907000
#include <openssl/conf.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#endif

#include "utils.h"
#include "connect.h"
#include "ptimer.h"
#include "url.h"
#include "ssl.h"
#include "exits.h"
#include "threading.h"

#include <fcntl.h>

/* Application-wide SSL context shared by all connections */
static SSL_CTX* ssl_ctx;
static wget_mutex_t ssl_context_lock;

/* Initialize the SSL PRNG using configured sources and OpenSSL defaults */

static void init_prng(void) {
  char namebuf[256];
  const char* random_file = NULL;

  /* Seed from user supplied random file or RAND_file_name default */
  if (opt.random_file)
    random_file = opt.random_file;
  else {
    namebuf[0] = '\0';
    random_file = RAND_file_name(namebuf, sizeof(namebuf));
    if (!random_file || !file_exists_p(random_file, NULL))
      random_file = NULL;
  }

  if (random_file && *random_file) {
    /* Seed at most 16k (arbitrary but common limit) from random file */
    int err = RAND_load_file(random_file, 16384);
    if (err == -1) {
      /* later the thread error queue will be cleared */
      if ((err = ERR_peek_last_error()) != 0)
        logprintf(LOG_VERBOSE, "WARNING: Could not load random file: %s, %s\n", random_file, ERR_reason_error_string(err));
    }
  }

#ifdef HAVE_RAND_EGD
  /* Optionally pull entropy from EGD when configured */
  if (opt.egd_file && *opt.egd_file)
    RAND_egd(opt.egd_file);
#endif
}

/* Print errors in the OpenSSL error stack */

static void print_errors(void) {
  unsigned long err;
  while ((err = ERR_get_error()) != 0)
    logprintf(LOG_NOTQUIET, "OpenSSL: %s\n", ERR_error_string(err, NULL));
}

/* Convert keyfile type as used by options.h to a type understood by OpenSSL */

static int key_type_to_ssl_type(enum keyfile_type type) {
  switch (type) {
    case keyfile_pem:
      return SSL_FILETYPE_PEM;
    case keyfile_asn1:
      return SSL_FILETYPE_ASN1;
    default:
      abort();
  }
}

/* SSL has been initialized at least once */
static int ssl_true_initialized = 0;

/* Create an SSL context and configure protocol and trust defaults
   Returns true on success, false otherwise */

bool ssl_init(void) {
  const SSL_METHOD* meth = NULL;
  long ssl_options = 0;
  char* ciphers_string = NULL;
#if !defined(LIBRESSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER >= 0x10100000L)
  int ssl_proto_version = 0;
#endif
  bool success = false;

  /* Initialize the SSL context lock */
  wget_mutex_init(&ssl_context_lock);

#if OPENSSL_VERSION_NUMBER >= 0x00907000
  if (ssl_true_initialized == 0) {
#if !defined(LIBRESSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG | OPENSSL_INIT_ENGINE_ALL_BUILTIN, NULL);
#else
    OPENSSL_config(NULL);
#endif
    ssl_true_initialized = 1;
  }
#endif

  wget_mutex_lock(&ssl_context_lock);

  if (ssl_ctx) {
    success = true;
    goto out;
  }

  /* Init the PRNG and bail out on failure */
  init_prng();
  if (RAND_status() != 1) {
    logprintf(LOG_NOTQUIET, _("Could not seed PRNG; consider using --random-file.\n"));
    goto error;
  }

#if defined(LIBRESSL_VERSION_NUMBER) || (OPENSSL_VERSION_NUMBER < 0x10100000L)
  SSL_library_init();
  SSL_load_error_strings();
  SSLeay_add_all_algorithms();
  SSLeay_add_ssl_algorithms();
#endif

  switch (opt.secure_protocol) {
    case secure_protocol_sslv2:
#if !defined OPENSSL_NO_SSL2 && OPENSSL_VERSION_NUMBER < 0x10100000L
      meth = SSLv2_client_method();
#endif
      break;

    case secure_protocol_sslv3:
#ifndef OPENSSL_NO_SSL3_METHOD
      meth = SSLv3_client_method();
#endif
      break;

    case secure_protocol_auto:
    case secure_protocol_pfs:
      meth = SSLv23_client_method();
      ssl_options |= SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
      break;

    case secure_protocol_tlsv1:
#if !defined(LIBRESSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER >= 0x10100000L)
      meth = TLS_client_method();
      ssl_proto_version = TLS1_VERSION;
#else
      meth = TLSv1_client_method();
#endif
      break;

#if OPENSSL_VERSION_NUMBER >= 0x10001000
    case secure_protocol_tlsv1_1:
#if !defined(LIBRESSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER >= 0x10100000L)
      meth = TLS_client_method();
      ssl_proto_version = TLS1_1_VERSION;
#else
      meth = TLSv1_1_client_method();
#endif
      break;

    case secure_protocol_tlsv1_2:
#if !defined(LIBRESSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER >= 0x10100000L)
      meth = TLS_client_method();
      ssl_proto_version = TLS1_2_VERSION;
#else
      meth = TLSv1_2_client_method();
#endif
      break;

    case secure_protocol_tlsv1_3:
#if !defined(LIBRESSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER >= 0x10100000L) && defined TLS1_3_VERSION
      meth = TLS_client_method();
      ssl_proto_version = TLS1_3_VERSION;
#else
      logprintf(LOG_NOTQUIET, _("Your OpenSSL version is too old to support TLS 1.3\n"));
      goto error;
#endif
      break;
#else
    case secure_protocol_tlsv1_1:
      logprintf(LOG_NOTQUIET, _("Your OpenSSL version is too old to support TLSv1.1\n"));
      goto error;

    case secure_protocol_tlsv1_2:
      logprintf(LOG_NOTQUIET, _("Your OpenSSL version is too old to support TLSv1.2\n"));
      goto error;
#endif

    default:
      logprintf(LOG_NOTQUIET, _("OpenSSL: unimplemented 'secure-protocol' option value %d\n"), opt.secure_protocol);
      logprintf(LOG_NOTQUIET, _("Please report this issue to bug-wget@gnu.org\n"));
      abort();
  }

  if (!meth) {
    logprintf(LOG_NOTQUIET, _("Your OpenSSL version does not support option '%s'.\n"), opt.secure_protocol_name);
    logprintf(LOG_NOTQUIET, _("Rebuilding Wget and/or OpenSSL may help in this situation.\n"));
    exit(WGET_EXIT_GENERIC_ERROR);
  }

  ssl_ctx = SSL_CTX_new((SSL_METHOD*)meth);
  if (!ssl_ctx)
    goto error;

  if (ssl_options)
    SSL_CTX_set_options(ssl_ctx, ssl_options);

#if ((OPENSSL_VERSION_NUMBER >= 0x10101000L) && !defined(LIBRESSL_VERSION_NUMBER) && !defined(OPENSSL_IS_BORINGSSL))
  SSL_CTX_set_post_handshake_auth(ssl_ctx, 1);
#endif

#if !defined(LIBRESSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER >= 0x10100000L)
  if (ssl_proto_version)
    SSL_CTX_set_min_proto_version(ssl_ctx, ssl_proto_version);
#endif

  /* OpenSSL cipher string:
   *  1. --ciphers overrides everything
   *  2. Allow RSA key exchange by default (secure_protocol_auto)
   *  3. For PFS mode, drop RSA key exchange ciphers
   */
  if (!opt.tls_ciphers_string) {
    if (opt.secure_protocol == secure_protocol_auto)
      ciphers_string = "HIGH:!aNULL:!RC4:!MD5:!SRP:!PSK";
    else if (opt.secure_protocol == secure_protocol_pfs)
      ciphers_string = "HIGH:!aNULL:!RC4:!MD5:!SRP:!PSK:!kRSA";
  }
  else {
    ciphers_string = opt.tls_ciphers_string;
  }

  if (ciphers_string && !SSL_CTX_set_cipher_list(ssl_ctx, ciphers_string)) {
    logprintf(LOG_NOTQUIET, _("OpenSSL: Invalid cipher list: %s\n"), ciphers_string);
    goto error;
  }

  SSL_CTX_set_default_verify_paths(ssl_ctx);
  SSL_CTX_load_verify_locations(ssl_ctx, opt.ca_cert, opt.ca_directory);

#ifdef X509_V_FLAG_PARTIAL_CHAIN
  /* Allow trust to be anchored at an intermediate when explicitly configured */
  X509_VERIFY_PARAM* param = X509_VERIFY_PARAM_new();
  if (param) {
    (void)X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_TRUSTED_FIRST | X509_V_FLAG_PARTIAL_CHAIN);
    if (SSL_CTX_set1_param(ssl_ctx, param) == 0)
      logprintf(LOG_NOTQUIET, _("OpenSSL: Failed set trust to partial chain\n"));
    X509_VERIFY_PARAM_free(param);
  }
  else {
    logprintf(LOG_NOTQUIET, _("OpenSSL: Failed to allocate verification param\n"));
  }
#endif

  if (opt.crl_file) {
    X509_STORE* store = SSL_CTX_get_cert_store(ssl_ctx);
    X509_LOOKUP* lookup;

    lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    if (!lookup || !X509_load_crl_file(lookup, opt.crl_file, X509_FILETYPE_PEM))
      goto error;

    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
  }

  /* Let SSL_connect continue on certificate problems
     Actual verification is done in ssl_check_certificate */
  SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

  /* Use the private key from the cert file unless otherwise specified */
  if (opt.cert_file && !opt.private_key) {
    opt.private_key = xstrdup(opt.cert_file);
    opt.private_key_type = opt.cert_type;
  }

  /* Use cert from private key file unless otherwise specified */
  if (opt.private_key && !opt.cert_file) {
    opt.cert_file = xstrdup(opt.private_key);
    opt.cert_type = opt.private_key_type;
  }

  if (opt.cert_file)
    if (SSL_CTX_use_certificate_file(ssl_ctx, opt.cert_file, key_type_to_ssl_type(opt.cert_type)) != 1)
      goto error;
  if (opt.private_key)
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, opt.private_key, key_type_to_ssl_type(opt.private_key_type)) != 1)
      goto error;

  /* Allow partial writes because fd_write handles them correctly */
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

  /* Let OpenSSL handle renegotiation automatically */
  SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);

  success = true;
  goto out;

error:
  if (ssl_ctx) {
    SSL_CTX_free(ssl_ctx);
    ssl_ctx = NULL;
  }
  print_errors();
  success = false;

out:
  wget_mutex_unlock(&ssl_context_lock);
  return success;
}

void ssl_cleanup(void) {
  wget_mutex_lock(&ssl_context_lock);
  if (ssl_ctx) {
    SSL_CTX_free(ssl_ctx);
    ssl_ctx = NULL;
  }
  wget_mutex_unlock(&ssl_context_lock);
}

struct openssl_transport_context {
  SSL* conn;         /* SSL connection handle */
  SSL_SESSION* sess; /* SSL session info */
  char* last_error;  /* last error printed with openssl_errstr */
};

typedef int (*ssl_fn_t)(SSL*, void*, int);

#ifdef OPENSSL_RUN_WITHTIMEOUT

struct scwt_context {
  SSL* ssl;
  int result;
};

static void ssl_connect_with_timeout_callback(void* arg) {
  struct scwt_context* ctx = (struct scwt_context*)arg;
  ctx->result = SSL_connect(ctx->ssl);
}

static int ssl_connect_with_timeout(int fd WGET_ATTR_UNUSED, SSL* conn, double timeout) {
  struct scwt_context scwt_ctx;
  scwt_ctx.ssl = conn;
  errno = 0;
  if (run_with_timeout(timeout, ssl_connect_with_timeout_callback, &scwt_ctx)) {
    errno = ETIMEDOUT;
    return -1;
  }
  return scwt_ctx.result;
}

struct openssl_read_args {
  int fd;
  struct openssl_transport_context* ctx;
  ssl_fn_t fn;
  char* buf;
  int bufsize;
  int retval;
};

static void openssl_read_peek_callback(void* arg) {
  struct openssl_read_args* args = (struct openssl_read_args*)arg;
  struct openssl_transport_context* ctx = args->ctx;
  ssl_fn_t fn = args->fn;
  SSL* conn = ctx->conn;
  char* buf = args->buf;
  int bufsize = args->bufsize;
  int ret;

  do {
    ret = fn(conn, buf, bufsize);
  } while (ret == -1 && SSL_get_error(conn, ret) == SSL_ERROR_SYSCALL && errno == EINTR);
  args->retval = ret;
}

static int openssl_read_peek(int fd, char* buf, int bufsize, void* arg, double timeout, ssl_fn_t fn) {
  struct openssl_transport_context* ctx = arg;
  int ret = SSL_pending(ctx->conn);

  if (ret)
    ret = fn(ctx->conn, buf, MIN(bufsize, ret));
  else {
    struct openssl_read_args args;
    args.fd = fd;
    args.buf = buf;
    args.bufsize = bufsize;
    args.fn = fn;
    args.ctx = ctx;

    if (timeout == -1)
      timeout = opt.read_timeout;

    if (run_with_timeout(timeout, openssl_read_peek_callback, &args)) {
      errno = ETIMEDOUT;
      ret = -1;
    }
    else
      ret = args.retval;
  }
  return ret;
}

#else /* OPENSSL_RUN_WITHTIMEOUT */

/* Nonblocking helpers using fcntl on POSIX sockets */

#define NONBLOCK_DECL int flags = 0;
#define FD_SET_NONBLOCKED(_fd)                 \
  flags = fcntl(_fd, F_GETFL, 0);              \
  if (flags < 0)                               \
    return flags;                              \
  if (fcntl(_fd, F_SETFL, flags | O_NONBLOCK)) \
    return -1;
#define FD_SET_BLOCKED(_fd)           \
  if (fcntl(_fd, F_SETFL, flags) < 0) \
    return -1;

#define TIMER_INIT(_fd, _ret, _timeout)  \
  {                                      \
    NONBLOCK_DECL                        \
    int timed_out = 0;                   \
    FD_SET_NONBLOCKED(_fd)               \
    struct ptimer* timer = ptimer_new(); \
    if (timer == NULL)                   \
      _ret = -1;                         \
    else {                               \
      double next_timeout = _timeout;

#define TIMER_FREE(_fd)  \
  ptimer_destroy(timer); \
  }                      \
  FD_SET_BLOCKED(_fd)    \
  if (timed_out) {       \
    errno = ETIMEDOUT;   \
  }                      \
  }

#define TIMER_WAIT(_fd, _conn, _ret, _timeout)       \
  {                                                  \
    int wait_for;                                    \
    int err = SSL_get_error(_conn, _ret);            \
    if (err == SSL_ERROR_WANT_READ)                  \
      wait_for = WAIT_FOR_READ;                      \
    else if (err == SSL_ERROR_WANT_WRITE)            \
      wait_for = WAIT_FOR_WRITE;                     \
    else                                             \
      break;                                         \
    err = select_fd_nb(_fd, next_timeout, wait_for); \
    if (err <= 0) {                                  \
      if (err == 0)                                  \
      timedout:                                      \
        timed_out = 1;                               \
      _ret = -1;                                     \
      break;                                         \
    }                                                \
    next_timeout = _timeout - ptimer_measure(timer); \
    if (next_timeout <= 0)                           \
      goto timedout;                                 \
  }

static int ssl_connect_with_timeout(int fd, SSL* conn, double timeout) {
  int ret;

  errno = 0;
  if (timeout == 0)
    ret = SSL_connect(conn);
  else {
    TIMER_INIT(fd, ret, timeout)
    ERR_clear_error();
    while ((ret = SSL_connect(conn)) < 0)
      TIMER_WAIT(fd, conn, ret, timeout)
    TIMER_FREE(fd)
  }

  return ret;
}

static int openssl_read_peek(int fd, char* buf, int bufsize, void* arg, double timeout, ssl_fn_t fn) {
  struct openssl_transport_context* ctx = arg;
  int ret = SSL_pending(ctx->conn);

  if (timeout == -1)
    timeout = opt.read_timeout;

  /* If we have data queued in SSL, read it immediately
     or do a blocking read when timeout == 0 */
  if (ret || timeout == 0) {
    do {
      ret = fn(ctx->conn, buf, (ret ? MIN(bufsize, ret) : bufsize));
    } while (ret == -1 && SSL_get_error(ctx->conn, ret) == SSL_ERROR_SYSCALL && errno == EINTR);
  }
  else {
    TIMER_INIT(fd, ret, timeout)
    while ((ret = fn(ctx->conn, buf, bufsize)) <= 0)
      TIMER_WAIT(fd, ctx->conn, ret, timeout)
    TIMER_FREE(fd)
  }

  return ret;
}

#endif /* OPENSSL_RUN_WITHTIMEOUT */

static int openssl_read(int fd, char* buf, int bufsize, void* arg, double timeout) {
  return openssl_read_peek(fd, buf, bufsize, arg, timeout, SSL_read);
}

static int openssl_write(int fd WGET_ATTR_UNUSED, char* buf, int bufsize, void* arg) {
  int ret = 0;
  struct openssl_transport_context* ctx = arg;
  SSL* conn = ctx->conn;
  do
    ret = SSL_write(conn, buf, bufsize);
  while (ret == -1 && SSL_get_error(conn, ret) == SSL_ERROR_SYSCALL && errno == EINTR);
  return ret;
}

static int openssl_poll(int fd, double timeout, int wait_for, void* arg) {
  struct openssl_transport_context* ctx = arg;
  SSL* conn = ctx->conn;
  if ((wait_for & WAIT_FOR_READ) && SSL_pending(conn))
    return 1;
  if (timeout == -1)
    timeout = opt.read_timeout;
  return select_fd(fd, timeout, wait_for);
}

static int openssl_peek(int fd, char* buf, int bufsize, void* arg, double timeout) {
  return openssl_read_peek(fd, buf, bufsize, arg, timeout, SSL_peek);
}

static const char* openssl_errstr(int fd WGET_ATTR_UNUSED, void* arg) {
  struct openssl_transport_context* ctx = arg;
  unsigned long errcode;
  char* errmsg = NULL;
  int msglen = 0;

  /* No SSL specific error pending */
  if ((errcode = ERR_get_error()) == 0)
    return NULL;

  xfree(ctx->last_error);

  /* Accumulate error strings from the OpenSSL error stack */
  for (;;) {
    const char* str = ERR_error_string(errcode, NULL);
    int len = strlen(str);

    errmsg = xrealloc(errmsg, msglen + len + 2 + 1);
    memcpy(errmsg + msglen, str, len);
    msglen += len;

    errcode = ERR_get_error();
    if (errcode == 0)
      break;

    errmsg[msglen++] = ';';
    errmsg[msglen++] = ' ';
  }
  errmsg[msglen] = '\0';

  ctx->last_error = errmsg;

  return errmsg;
}

static void openssl_close(int fd, void* arg) {
  struct openssl_transport_context* ctx = arg;
  SSL* conn = ctx->conn;

  SSL_shutdown(conn);
  SSL_free(conn);
  xfree(ctx->last_error);
  xfree(ctx);

  close(fd);

  DEBUGP(("Closed %d/SSL 0x%0*lx\n", fd, PTR_FORMAT(conn)));
}

/* Transport descriptor used by the generic fd layer */

static struct transport_implementation openssl_transport = {openssl_read, openssl_write, openssl_poll, openssl_peek, openssl_errstr, openssl_close};

/* Normalize SNI hostname by stripping trailing dots */

static const char* _sni_hostname(const char* hostname) {
  size_t len = strlen(hostname);
  char* sni_hostname = xmemdup(hostname, len + 1);

  /* RFC 6066 SNI: ASCII hostname without trailing dot */
  while (len && sni_hostname[--len] == '.')
    sni_hostname[len] = 0;

  return sni_hostname;
}

/* Perform the SSL handshake and bind SSL to fd
   Returns true on success, false on failure */

bool ssl_connect_wget(int fd, const char* hostname, int* continue_session) {
  SSL* conn = NULL;
  struct openssl_transport_context* ctx;

  DEBUGP(("Initiating SSL handshake\n"));

  wget_mutex_lock(&ssl_context_lock);
  if (!ssl_ctx) {
    wget_mutex_unlock(&ssl_context_lock);
    goto error;
  }
  conn = SSL_new(ssl_ctx);
  wget_mutex_unlock(&ssl_context_lock);
  if (!conn)
    goto error;

#if OPENSSL_VERSION_NUMBER >= 0x0090806fL && !defined(OPENSSL_NO_TLSEXT)
  /* Use SNI whenever we have a hostname and library supports it */
  if (!is_valid_ip_address(hostname)) {
    const char* sni_hostname = _sni_hostname(hostname);

    long rc = SSL_set_tlsext_host_name(conn, sni_hostname);
    xfree(sni_hostname);

    if (rc == 0) {
      DEBUGP(("Failed to set TLS server-name indication\n"));
      goto error;
    }
  }
#endif

  if (continue_session) {
    /* attempt to resume a previous SSL session */
    ctx = fd_transport_context(*continue_session);
    if (!ctx || !ctx->sess || !SSL_set_session(conn, ctx->sess))
      goto error;
  }

  if (!SSL_set_fd(conn, fd))
    goto error;
  SSL_set_connect_state(conn);

  /* Re-seed PRNG just before handshake */
  init_prng();
  if (RAND_status() != 1) {
    logprintf(LOG_NOTQUIET, _("WARNING: Could not seed PRNG. Consider using --random-file.\n"));
    goto error;
  }

  if (ssl_connect_with_timeout(fd, conn, opt.read_timeout) <= 0 || !SSL_is_init_finished(conn))
    goto timedout;

  ctx = xnew0(struct openssl_transport_context);
  ctx->conn = conn;
  ctx->sess = SSL_get0_session(conn);
  if (!ctx->sess)
    logprintf(LOG_NOTQUIET, "WARNING: Could not save SSL session data for socket %d\n", fd);

  /* Register SSL transport on this fd */
  fd_register_transport(fd, &openssl_transport, ctx);
  DEBUGP(("Handshake successful; connected socket %d to SSL handle 0x%0*lx\n", fd, PTR_FORMAT(conn)));

  ERR_clear_error();
  return true;

timedout:
  if (errno == ETIMEDOUT)
    DEBUGP(("SSL handshake timed out\n"));
  else
  error:
    DEBUGP(("SSL handshake failed\n"));
  print_errors();
  if (conn)
    SSL_free(conn);
  return false;
}

#define ASTERISK_EXCLUDES_DOT /* mandated by rfc2818 */

/* Simple wildcard matching for certificate hostnames */

static bool pattern_match(const char* pattern, const char* string) {
  const char *p = pattern, *n = string;
  char c;

  for (; (c = c_tolower(*p++)) != '\0'; n++)
    if (c == '*') {
      for (c = c_tolower(*p); c == '*'; c = c_tolower(*++p))
        ;
      for (; *n != '\0'; n++) {
        if (c_tolower(*n) == c && pattern_match(p, n))
          return true;
#ifdef ASTERISK_EXCLUDES_DOT
        else if (*n == '.')
          return false;
#endif
      }
      return c == '\0';
    }
    else {
      if (c != c_tolower(*n))
        return false;
    }
  return *n == '\0';
}

static char* _get_rfc2253_formatted(X509_NAME* name) {
  int len;
  char* out = NULL;
  BIO* b;

  b = BIO_new(BIO_s_mem());
  if (b) {
    if (X509_NAME_print_ex(b, name, 0, XN_FLAG_RFC2253) >= 0 && (len = BIO_number_written(b)) > 0) {
      out = xmalloc(len + 1);
      BIO_read(b, out, len);
      out[len] = 0;
    }
    BIO_free(b);
  }

  return out ? out : xstrdup("");
}

/*
 * Heavily modified from:
 * https://www.owasp.org/index.php/Certificate_and_Public_Key_Pinning#OpenSSL
 */
static bool pkp_pin_peer_pubkey(X509* cert, const char* pinnedpubkey) {
  int len1 = 0, len2 = 0;
  char* buff1 = NULL;
  char* temp = NULL;
  bool result = false;

  if (!pinnedpubkey)
    return true;

  if (!cert)
    return result;

  len1 = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), NULL);
  if (len1 < 1)
    goto cleanup;

  buff1 = temp = OPENSSL_malloc(len1);
  if (!buff1)
    goto cleanup;

  len2 = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), (unsigned char**)&temp);

  if ((len1 != len2) || !temp || (temp - buff1) != len1)
    goto cleanup;

  result = wg_pin_peer_pubkey(pinnedpubkey, buff1, len1);

cleanup:
  if (buff1)
    OPENSSL_free(buff1);

  return result;
}

/* Verify server certificate validity and hostname, and apply pinning if enabled
   Returns true when the certificate is accepted under current policy */

bool ssl_check_certificate(int fd, const char* host) {
  X509* cert;
  GENERAL_NAMES* subjectAltNames;
  char common_name[256];
  long vresult;
  bool success = true;
  bool alt_name_checked = false;
  bool pinsuccess = opt.pinnedpubkey == NULL;

  const char* severity = opt.check_cert ? _("ERROR") : _("WARNING");

  struct openssl_transport_context* ctx = fd_transport_context(fd);
  SSL* conn = ctx->conn;
  assert(conn != NULL);

  if (opt.check_cert == CHECK_CERT_QUIET && pinsuccess)
    return success;

  cert = SSL_get_peer_certificate(conn);
  if (!cert) {
    logprintf(LOG_NOTQUIET, _("%s: No certificate presented by %s.\n"), severity, quotearg_style(escape_quoting_style, host));
    success = false;
    goto no_cert;
  }

  IF_DEBUG {
    char* subject = _get_rfc2253_formatted(X509_get_subject_name(cert));
    char* issuer = _get_rfc2253_formatted(X509_get_issuer_name(cert));
    DEBUGP(("certificate:\n  subject: %s\n  issuer:  %s\n", quotearg_n_style(0, escape_quoting_style, subject), quotearg_n_style(1, escape_quoting_style, issuer)));
    xfree(subject);
    xfree(issuer);
  }

  vresult = SSL_get_verify_result(conn);
  if (vresult != X509_V_OK) {
    char* issuer = _get_rfc2253_formatted(X509_get_issuer_name(cert));
    logprintf(LOG_NOTQUIET, _("%s: cannot verify %s's certificate, issued by %s:\n"), severity, quotearg_n_style(0, escape_quoting_style, host), quote_n(1, issuer));
    xfree(issuer);

    switch (vresult) {
      case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        logprintf(LOG_NOTQUIET, _("  Unable to locally verify the issuer's authority.\n"));
        break;
      case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
      case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        logprintf(LOG_NOTQUIET, _("  Self-signed certificate encountered.\n"));
        break;
      case X509_V_ERR_CERT_NOT_YET_VALID:
        logprintf(LOG_NOTQUIET, _("  Issued certificate not yet valid.\n"));
        break;
      case X509_V_ERR_CERT_HAS_EXPIRED:
        logprintf(LOG_NOTQUIET, _("  Issued certificate has expired.\n"));
        break;
      default:
        logprintf(LOG_NOTQUIET, "  %s\n", X509_verify_cert_error_string(vresult));
    }
    success = false;
  }

  subjectAltNames = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);

  if (subjectAltNames) {
    const char* sni_hostname = _sni_hostname(host);

    ASN1_OCTET_STRING* host_in_octet_string = a2i_IPADDRESS(sni_hostname);

    int numaltnames = sk_GENERAL_NAME_num(subjectAltNames);
    int i;

    for (i = 0; i < numaltnames; i++) {
      const GENERAL_NAME* name = sk_GENERAL_NAME_value(subjectAltNames, i);
      if (!name)
        continue;

      if (host_in_octet_string) {
        if (name->type == GEN_IPADD) {
          alt_name_checked = true;
          if (!ASN1_STRING_cmp(host_in_octet_string, name->d.iPAddress))
            break;
        }
      }
      else if (name->type == GEN_DNS) {
        unsigned char* name_in_utf8 = NULL;

        alt_name_checked = true;

        if (ASN1_STRING_to_UTF8(&name_in_utf8, name->d.dNSName) >= 0) {
          if (pattern_match((char*)name_in_utf8, sni_hostname) && strlen((char*)name_in_utf8) == (size_t)ASN1_STRING_length(name->d.dNSName)) {
            OPENSSL_free(name_in_utf8);
            break;
          }
          OPENSSL_free(name_in_utf8);
        }
      }
    }

    sk_GENERAL_NAME_pop_free(subjectAltNames, GENERAL_NAME_free);
    if (host_in_octet_string)
      ASN1_OCTET_STRING_free(host_in_octet_string);

    if (alt_name_checked && i >= numaltnames) {
      logprintf(LOG_NOTQUIET,
                _("%s: no certificate subject alternative name matches\n"
                  "\trequested host name %s.\n"),
                severity, quote_n(1, sni_hostname));
      success = false;
    }

    xfree(sni_hostname);
  }

  if (!alt_name_checked) {
    X509_NAME* xname = X509_get_subject_name(cert);
    common_name[0] = '\0';
    X509_NAME_get_text_by_NID(xname, NID_commonName, common_name, sizeof(common_name));

    if (!pattern_match(common_name, host)) {
      logprintf(LOG_NOTQUIET, _("%s: certificate common name %s doesn't match requested host name %s.\n"), severity, quote_n(0, common_name), quote_n(1, host));
      success = false;
    }
    else {
      int i = -1, j;
      X509_NAME_ENTRY* xentry;
      ASN1_STRING* sdata;

      if (xname) {
        for (;;) {
          j = X509_NAME_get_index_by_NID(xname, NID_commonName, i);
          if (j == -1)
            break;
          i = j;
        }
      }

      xentry = X509_NAME_get_entry(xname, i);
      sdata = X509_NAME_ENTRY_get_data(xentry);
      if (strlen(common_name) != (size_t)ASN1_STRING_length(sdata)) {
        logprintf(LOG_NOTQUIET,
                  _("%s: certificate common name is invalid (contains a NUL character).\n"
                    "This may be an indication that the host is not who it claims to be\n"
                    "(that is, it is not the real %s).\n"),
                  severity, quote(host));
        success = false;
      }
    }
  }

  pinsuccess = pkp_pin_peer_pubkey(cert, opt.pinnedpubkey);
  if (!pinsuccess) {
    logprintf(LOG_ALWAYS, _("The public key does not match pinned public key!\n"));
    success = false;
  }

  if (success)
    DEBUGP(("X509 certificate successfully verified and matches host %s\n", quotearg_style(escape_quoting_style, host)));
  X509_free(cert);

no_cert:
  if (opt.check_cert == CHECK_CERT_ON && !success)
    logprintf(LOG_NOTQUIET, _("To connect to %s insecurely, use `--no-check-certificate'.\n"), quotearg_style(escape_quoting_style, host));

  return !pinsuccess ? false : (opt.check_cert == CHECK_CERT_ON ? success : true);
}
