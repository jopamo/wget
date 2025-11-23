/* Minimal SHA256 interface.  */
#ifndef WGET_SHA256_H
#define WGET_SHA256_H

#include <stddef.h>
#include <stdio.h>

#define SHA256_DIGEST_SIZE 32

#ifdef HAVE_NETTLE
#include <nettle/sha2.h>
#else
#include <openssl/sha.h>
typedef struct sha256_ctx {
  SHA256_CTX impl;
} sha256_ctx;
#endif

void sha256_init_ctx(struct sha256_ctx* ctx);
void sha256_process_bytes(const void* buffer, size_t len, struct sha256_ctx* ctx);
void sha256_finish_ctx(struct sha256_ctx* ctx, void* resbuf);
int sha256_stream(FILE* stream, void* resblock);
void sha256_buffer(const void* buffer, size_t len, void* resblock);

#endif /* WGET_SHA256_H */
