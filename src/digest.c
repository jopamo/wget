/* Digest wrappers built on top of nettle or OpenSSL
 * src/digest.c
 */

#include "wget.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"

#include <stdio.h>

#ifdef HAVE_NETTLE
#include <nettle/md5.h>
#include <nettle/sha1.h>
#include <nettle/sha2.h>
#endif

void md5_init_ctx(struct md5_ctx* ctx) {
#ifdef HAVE_NETTLE
  nettle_md5_init(ctx);
#else
  MD5_Init(&ctx->impl);
#endif
}

void md5_process_bytes(const void* buffer, size_t len, struct md5_ctx* ctx) {
#ifdef HAVE_NETTLE
  nettle_md5_update(ctx, len, buffer);
#else
  MD5_Update(&ctx->impl, buffer, len);
#endif
}

void md5_finish_ctx(struct md5_ctx* ctx, void* resbuf) {
#ifdef HAVE_NETTLE
  nettle_md5_digest(ctx, MD5_DIGEST_SIZE, resbuf);
#else
  MD5_Final(resbuf, &ctx->impl);
#endif
}

void sha1_init_ctx(struct sha1_ctx* ctx) {
#ifdef HAVE_NETTLE
  nettle_sha1_init(ctx);
#else
  SHA1_Init(&ctx->impl);
#endif
}

void sha1_process_bytes(const void* buffer, size_t len, struct sha1_ctx* ctx) {
#ifdef HAVE_NETTLE
  nettle_sha1_update(ctx, len, buffer);
#else
  SHA1_Update(&ctx->impl, buffer, len);
#endif
}

void sha1_finish_ctx(struct sha1_ctx* ctx, void* resbuf) {
#ifdef HAVE_NETTLE
  nettle_sha1_digest(ctx, SHA1_DIGEST_SIZE, resbuf);
#else
  SHA1_Final(resbuf, &ctx->impl);
#endif
}

void sha256_init_ctx(struct sha256_ctx* ctx) {
#ifdef HAVE_NETTLE
  nettle_sha256_init(ctx);
#else
  SHA256_Init(&ctx->impl);
#endif
}

void sha256_process_bytes(const void* buffer, size_t len, struct sha256_ctx* ctx) {
#ifdef HAVE_NETTLE
  nettle_sha256_update(ctx, len, buffer);
#else
  SHA256_Update(&ctx->impl, buffer, len);
#endif
}

void sha256_finish_ctx(struct sha256_ctx* ctx, void* resbuf) {
#ifdef HAVE_NETTLE
  nettle_sha256_digest(ctx, SHA256_DIGEST_SIZE, resbuf);
#else
  SHA256_Final(resbuf, &ctx->impl);
#endif
}

/* Generic streaming helper used by all digest_stream functions
 * INIT   initializes the context pointed to by CTX
 * UPDATE feeds data into the digest
 * FINISH writes the final digest into RESBLOCK
 */
typedef void (*digest_init_fn)(void* ctx);
typedef void (*digest_update_fn)(void* ctx, const void* buffer, size_t len);
typedef void (*digest_finish_fn)(void* ctx, void* resblock);

static int digest_stream_common(FILE* stream, void* ctx, digest_init_fn init, digest_update_fn update, digest_finish_fn finish, void* resblock) {
  unsigned char buffer[BUFSIZ];
  size_t n;

  if (!stream || !resblock)
    return -1;

  init(ctx);

  while ((n = fread(buffer, 1, sizeof(buffer), stream)) > 0)
    update(ctx, buffer, n);

  if (ferror(stream))
    return -1;

  finish(ctx, resblock);
  return 0;
}

/* Thin adapters so we can use the generic helper above */

static void md5_init_any(void* ctx) {
  md5_init_ctx((struct md5_ctx*)ctx);
}

static void md5_update_any(void* ctx, const void* buffer, size_t len) {
  md5_process_bytes(buffer, len, (struct md5_ctx*)ctx);
}

static void md5_finish_any(void* ctx, void* resblock) {
  md5_finish_ctx((struct md5_ctx*)ctx, resblock);
}

static void sha1_init_any(void* ctx) {
  sha1_init_ctx((struct sha1_ctx*)ctx);
}

static void sha1_update_any(void* ctx, const void* buffer, size_t len) {
  sha1_process_bytes(buffer, len, (struct sha1_ctx*)ctx);
}

static void sha1_finish_any(void* ctx, void* resblock) {
  sha1_finish_ctx((struct sha1_ctx*)ctx, resblock);
}

static void sha256_init_any(void* ctx) {
  sha256_init_ctx((struct sha256_ctx*)ctx);
}

static void sha256_update_any(void* ctx, const void* buffer, size_t len) {
  sha256_process_bytes(buffer, len, (struct sha256_ctx*)ctx);
}

static void sha256_finish_any(void* ctx, void* resblock) {
  sha256_finish_ctx((struct sha256_ctx*)ctx, resblock);
}

int md5_stream(FILE* stream, void* resblock) {
  struct md5_ctx ctx;
  return digest_stream_common(stream, &ctx, md5_init_any, md5_update_any, md5_finish_any, resblock);
}

int sha1_stream(FILE* stream, void* resblock) {
  struct sha1_ctx ctx;
  return digest_stream_common(stream, &ctx, sha1_init_any, sha1_update_any, sha1_finish_any, resblock);
}

int sha256_stream(FILE* stream, void* resblock) {
  struct sha256_ctx ctx;
  return digest_stream_common(stream, &ctx, sha256_init_any, sha256_update_any, sha256_finish_any, resblock);
}

void sha256_buffer(const void* buffer, size_t len, void* resblock) {
  struct sha256_ctx ctx;

  sha256_init_ctx(&ctx);
  sha256_process_bytes(buffer, len, &ctx);
  sha256_finish_ctx(&ctx, resblock);
}
