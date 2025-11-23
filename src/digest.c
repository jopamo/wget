/* Digest wrappers built on top of nettle or OpenSSL.  */

#include "wget.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"

#include <errno.h>
#include <string.h>

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

int md5_stream(FILE* stream, void* resblock) {
  struct md5_ctx ctx;
  md5_init_ctx(&ctx);
  unsigned char buffer[BUFSIZ];
  size_t n;
  while ((n = fread(buffer, 1, sizeof(buffer), stream)) > 0)
    md5_process_bytes(buffer, n, &ctx);
  if (ferror(stream))
    return -1;
  md5_finish_ctx(&ctx, resblock);
  return 0;
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

int sha1_stream(FILE* stream, void* resblock) {
  struct sha1_ctx ctx;
  sha1_init_ctx(&ctx);
  unsigned char buffer[BUFSIZ];
  size_t n;
  while ((n = fread(buffer, 1, sizeof(buffer), stream)) > 0)
    sha1_process_bytes(buffer, n, &ctx);
  if (ferror(stream))
    return -1;
  sha1_finish_ctx(&ctx, resblock);
  return 0;
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

int sha256_stream(FILE* stream, void* resblock) {
  struct sha256_ctx ctx;
  sha256_init_ctx(&ctx);
  unsigned char buffer[BUFSIZ];
  size_t n;
  while ((n = fread(buffer, 1, sizeof(buffer), stream)) > 0)
    sha256_process_bytes(buffer, n, &ctx);
  if (ferror(stream))
    return -1;
  sha256_finish_ctx(&ctx, resblock);
  return 0;
}

void sha256_buffer(const void* buffer, size_t len, void* resblock) {
  struct sha256_ctx ctx;
  sha256_init_ctx(&ctx);
  sha256_process_bytes(buffer, len, &ctx);
  sha256_finish_ctx(&ctx, resblock);
}
